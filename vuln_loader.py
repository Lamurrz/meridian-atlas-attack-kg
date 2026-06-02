"""
Vulnerability Loader
Pulls CVE data from NVD (NIST National Vulnerability Database) and
links it into the knowledge graph as:

  (Vulnerability) nodes
  (Vulnerability)-[:AFFECTS]->(AssetNode)
  (Technique)-[:EXPLOITS]->(Vulnerability)   [where CPE matches known ML libs]

NVD API v2 is used (api.nvd.nist.gov).
Rate limit: 5 req/30s without API key, 50 req/30s with key.

ML-relevant CPE prefixes are matched to identify vulnerabilities
that affect AI/ML libraries and frameworks.
"""

import argparse
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests
from neo4j import GraphDatabase
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ── ML-relevant CPE vendor/product prefixes ───────────────────────────────────
# Expanding this list is the primary customization point for new ML libraries.

ML_CPE_PATTERNS = {
    "tensorflow":     {"framework": "tensorflow",  "asset_types": ["AIModel", "MLPipeline"]},
    "pytorch":        {"framework": "pytorch",     "asset_types": ["AIModel", "MLPipeline"]},
    "scikit-learn":   {"framework": "sklearn",     "asset_types": ["AIModel"]},
    "transformers":   {"framework": "huggingface", "asset_types": ["AIModel", "InferenceAPI"]},
    "onnxruntime":    {"framework": "onnx",        "asset_types": ["AIModel", "InferenceAPI"]},
    "mlflow":         {"framework": "other",       "asset_types": ["MLPipeline", "ModelRegistry"]},
    "ray":            {"framework": "other",       "asset_types": ["MLPipeline"]},
    "triton":         {"framework": "other",       "asset_types": ["InferenceAPI"]},
    "torchserve":     {"framework": "other",       "asset_types": ["InferenceAPI"]},
    "jupyter":        {"framework": "other",       "asset_types": ["MLPipeline"]},
    "numpy":          {"framework": "other",       "asset_types": ["AIModel", "MLPipeline"]},
    "pillow":         {"framework": "other",       "asset_types": ["AIModel"]},
    "langchain":      {"framework": "other",       "asset_types": ["InferenceAPI"]},
}

# ATLAS/ATT&CK technique IDs known to exploit ML library vulnerabilities
# Maps CPE pattern → list of relevant technique external_ids
CPE_TO_TECHNIQUE = {
    "tensorflow":   ["AML.T0010", "T1195.001"],   # supply chain + dependency
    "pytorch":      ["AML.T0010", "T1195.001"],
    "transformers": ["AML.T0010", "AML.T0051"],   # includes prompt injection surface
    "mlflow":       ["AML.T0010", "T1213"],        # data from info repositories
    "triton":       ["T1190"],                     # exploit public-facing app
    "torchserve":   ["T1190"],
    "jupyter":      ["T1059", "T1190"],
}


# ── Cypher queries ─────────────────────────────────────────────────────────────

UPSERT_VULN = """
UNWIND $batch AS v
MERGE (n:Vulnerability {cve_id: v.cve_id})
ON CREATE SET n += v, n.first_seen = v.published
ON MATCH  SET n.cvss_v3        = v.cvss_v3,
              n.severity       = v.severity,
              n.exploit_maturity = v.exploit_maturity,
              n.description    = v.description,
              n.modified       = v.modified,
              n.patch_available = v.patch_available
RETURN count(n) AS n
"""

CREATE_AFFECTS = """
UNWIND $batch AS e
MATCH (v:Vulnerability {cve_id: e.cve_id})
MATCH (a {asset_id: e.asset_id})
MERGE (v)-[r:AFFECTS]->(a)
ON CREATE SET r.matched_cpe    = e.matched_cpe,
              r.requires_auth  = e.requires_auth,
              r.cvss_v3        = e.cvss_v3
RETURN count(r) AS n
"""

CREATE_EXPLOITS = """
UNWIND $batch AS e
MATCH (t {external_id: e.technique_id})
MATCH (v:Vulnerability {cve_id: e.cve_id})
MERGE (t)-[r:EXPLOITS]->(v)
ON CREATE SET r.exploit_maturity = e.exploit_maturity,
              r.cvss_v3          = e.cvss_v3,
              r.requires_auth    = e.requires_auth
RETURN count(r) AS n
"""

FIND_ASSETS_BY_FRAMEWORK = """
MATCH (a)
WHERE a.ml_framework = $framework
   OR a.asset_type IN $asset_types
RETURN a.asset_id AS asset_id, a.ml_framework AS framework
"""


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class VulnRecord:
    cve_id:           str
    description:      str
    published:        str
    modified:         str
    cvss_v3:          float = 0.0
    severity:         str  = "UNKNOWN"      # CRITICAL HIGH MEDIUM LOW
    exploit_maturity: str  = "theoretical"  # theoretical | poc | weaponized
    patch_available:  bool = False
    cpe_matches:      list = field(default_factory=list)
    ml_patterns:      list = field(default_factory=list)  # matched ML CPE patterns

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()
                if k not in ("cpe_matches", "ml_patterns")}


# ── NVD API client ────────────────────────────────────────────────────────────

class NvdClient:
    BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = "", rpm_limit: int = 5):
        self.api_key  = api_key
        self.interval = 60.0 / (50 if api_key else rpm_limit)
        self._last    = 0.0

    def _throttle(self):
        wait = self.interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    @retry(
        retry=retry_if_exception_type(requests.HTTPError),
        wait=wait_exponential(multiplier=2, min=10, max=120),
        stop=stop_after_attempt(4),
    )
    def _get(self, params: dict) -> dict:
        self._throttle()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        r = requests.get(self.BASE, params=params, headers=headers, timeout=30)
        r.raise_for_status()
        return r.json()

    def fetch_by_keyword(self, keyword: str, days_back: int = 365) -> list[dict]:
        """Fetch CVEs containing keyword in description, published in last N days."""
        from datetime import timedelta
        end   = datetime.now(timezone.utc)
        start = end - timedelta(days=days_back)
        params = {
            "keywordSearch": keyword,
            "pubStartDate":  start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate":    end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 100,
        }
        data = self._get(params)
        return data.get("vulnerabilities", [])

    def fetch_by_cpe(self, cpe_prefix: str, days_back: int = 365) -> list[dict]:
        """Fetch CVEs matching a CPE vendor/product prefix."""
        from datetime import timedelta
        end   = datetime.now(timezone.utc)
        start = end - timedelta(days=days_back)
        params = {
            "cpeName":      f"cpe:2.3:*:{cpe_prefix}:*:*:*:*:*:*:*:*",
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate":   end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 100,
        }
        try:
            data = self._get(params)
            return data.get("vulnerabilities", [])
        except Exception as e:
            log.warning(f"CPE fetch failed for {cpe_prefix}: {e}")
            return []


# ── Parser ─────────────────────────────────────────────────────────────────────

def parse_nvd_entry(entry: dict) -> VulnRecord | None:
    cve = entry.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions", [])
    desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), ""
    )[:1000]

    # CVSS v3 score
    metrics  = cve.get("metrics", {})
    cvss_v3  = 0.0
    severity = "UNKNOWN"
    for key in ("cvssMetricV31", "cvssMetricV30"):
        m_list = metrics.get(key, [])
        if m_list:
            data   = m_list[0].get("cvssData", {})
            cvss_v3  = float(data.get("baseScore", 0.0))
            severity = data.get("baseSeverity", "UNKNOWN")
            break

    # Exploit maturity — use EPSS or CISA KEV heuristic if available
    # Here we use a simple CVSS-based heuristic as a baseline
    if cvss_v3 >= 9.0:
        exploit_maturity = "weaponized"
    elif cvss_v3 >= 7.0:
        exploit_maturity = "poc"
    else:
        exploit_maturity = "theoretical"

    # Check for patch (any reference to a fix or advisory)
    refs = cve.get("references", [])
    patch_available = any(
        "patch" in r.get("url", "").lower() or
        "advisory" in r.get("url", "").lower() or
        "fix" in " ".join(r.get("tags", [])).lower()
        for r in refs
    )

    # Collect CPE matches and identify ML patterns
    configs    = cve.get("configurations", [])
    cpe_values = []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe_values.append(match.get("criteria", "").lower())

    ml_patterns = [
        pattern for pattern in ML_CPE_PATTERNS
        if any(pattern in cpe for cpe in cpe_values)
    ]

    return VulnRecord(
        cve_id           = cve_id,
        description      = desc,
        published        = cve.get("published", ""),
        modified         = cve.get("lastModified", ""),
        cvss_v3          = cvss_v3,
        severity         = severity,
        exploit_maturity = exploit_maturity,
        patch_available  = patch_available,
        cpe_matches      = cpe_values,
        ml_patterns      = ml_patterns,
    )


# ── Loader ─────────────────────────────────────────────────────────────────────

class VulnLoader:

    def __init__(self, neo4j_uri: str, user: str, password: str,
                 nvd_api_key: str = "", batch_size: int = 200):
        self.driver     = GraphDatabase.driver(neo4j_uri, auth=(user, password))
        self.nvd        = NvdClient(api_key=nvd_api_key)
        self.batch_size = batch_size

    def close(self):
        self.driver.close()

    def _batch_run(self, query: str, items: list, param: str = "batch") -> int:
        if not items:
            return 0
        total = 0
        with self.driver.session() as s:
            for i in range(0, len(items), self.batch_size):
                chunk = items[i: i + self.batch_size]
                r = s.run(query, {param: chunk})
                total += r.single()["n"]
        return total

    def _assets_for_framework(self, framework: str, asset_types: list) -> list[str]:
        with self.driver.session() as s:
            result = s.run(FIND_ASSETS_BY_FRAMEWORK,
                           {"framework": framework, "asset_types": asset_types})
            return [r["asset_id"] for r in result]

    def ingest_vulns(self, vulns: list[VulnRecord]) -> dict:
        if not vulns:
            return {"vulns": 0, "affects": 0, "exploits": 0}

        # 1. Upsert Vulnerability nodes
        vuln_count = self._batch_run(UPSERT_VULN,
                                     [v.to_dict() for v in vulns])
        log.info(f"Upserted {vuln_count} vulnerability nodes")

        # 2. Create AFFECTS edges to matching assets
        affects_edges = []
        for v in vulns:
            for pattern in v.ml_patterns:
                meta = ML_CPE_PATTERNS[pattern]
                asset_ids = self._assets_for_framework(
                    meta["framework"], meta["asset_types"]
                )
                for asset_id in asset_ids:
                    affects_edges.append({
                        "cve_id":       v.cve_id,
                        "asset_id":     asset_id,
                        "matched_cpe":  pattern,
                        "requires_auth": False,   # conservative default
                        "cvss_v3":      v.cvss_v3,
                    })

        affects_count = self._batch_run(CREATE_AFFECTS, affects_edges)
        log.info(f"Created {affects_count} AFFECTS edges")

        # 3. Create EXPLOITS edges (Technique → Vulnerability)
        exploits_edges = []
        for v in vulns:
            for pattern in v.ml_patterns:
                tech_ids = CPE_TO_TECHNIQUE.get(pattern, [])
                for tid in tech_ids:
                    exploits_edges.append({
                        "technique_id":   tid,
                        "cve_id":         v.cve_id,
                        "exploit_maturity": v.exploit_maturity,
                        "cvss_v3":        v.cvss_v3,
                        "requires_auth":  False,
                    })

        exploits_count = self._batch_run(CREATE_EXPLOITS, exploits_edges)
        log.info(f"Created {exploits_count} EXPLOITS edges")

        return {"vulns": vuln_count, "affects": affects_count, "exploits": exploits_count}

    def fetch_and_ingest_ml_vulns(self, days_back: int = 365) -> dict:
        """
        Main entry point: fetches CVEs for all ML_CPE_PATTERNS from NVD
        and ingests them. Deduplicates by CVE ID across pattern queries.
        """
        log.info(f"Fetching ML-relevant CVEs from NVD (last {days_back} days) …")
        seen: set[str] = set()
        all_vulns: list[VulnRecord] = []

        for pattern in ML_CPE_PATTERNS:
            log.info(f"  Querying NVD for pattern: {pattern}")
            entries = self.nvd.fetch_by_keyword(pattern, days_back)
            for entry in entries:
                v = parse_nvd_entry(entry)
                if v and v.cve_id not in seen:
                    seen.add(v.cve_id)
                    v.ml_patterns = v.ml_patterns or [pattern]
                    all_vulns.append(v)

        log.info(f"Fetched {len(all_vulns)} unique ML-relevant CVEs")
        return self.ingest_vulns(all_vulns)

    def load_from_json(self, path: str) -> dict:
        """Load pre-fetched CVE data from a local JSON file (NVD export format)."""
        data = json.loads(open(path).read())
        vulns_raw = data if isinstance(data, list) else data.get("vulnerabilities", [])
        vulns = [v for entry in vulns_raw
                 if (v := parse_nvd_entry(entry if "cve" in entry else {"cve": entry}))]
        log.info(f"Parsed {len(vulns)} vulnerabilities from {path}")
        return self.ingest_vulns(vulns)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Load vulnerability intel into Neo4j")
    parser.add_argument("--input",    default=None, help="Local NVD JSON export path")
    parser.add_argument("--days",     type=int, default=365, help="Days back for NVD query")
    parser.add_argument("--api-key",  default="", help="NVD API key (optional)")
    parser.add_argument("--uri",      default="bolt://localhost:7687")
    parser.add_argument("--user",     default="neo4j")
    parser.add_argument("--password", default="password")
    args = parser.parse_args()

    loader = VulnLoader(args.uri, args.user, args.password, nvd_api_key=args.api_key)
    try:
        if args.input:
            result = loader.load_from_json(args.input)
        else:
            result = loader.fetch_and_ingest_ml_vulns(days_back=args.days)
        log.info(f"Vulnerability load complete: {result}")
    finally:
        loader.close()


if __name__ == "__main__":
    main()
