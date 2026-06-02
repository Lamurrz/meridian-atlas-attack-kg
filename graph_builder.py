"""
Graph Builder + Scoring Engine
Third and final layer of the knowledge graph construction pipeline.

Runs after:
  1. stix_taxii_ingestion.py  (threat framework domain)
  2. asset_loader.py          (asset inventory domain)
  3. vuln_loader.py           (vulnerability intel domain)

Responsibilities:
  A. Cross-domain edge creation
       (Technique)-[:TARGETS]->(AssetNode)
       (MitigationControl)-[:MITIGATES]->(Technique)
       (AssetNode)-[:SCORED_BY]->(RiskScore)

  B. Risk scoring engine
       Implements: R = 1 - ∏(1 - Pᵢ) × criticality_multiplier × 10
       Where each path score Pᵢ = actor_weight × exploit_avail
                                   × reachability × (1 - max_control_eff)

  C. Staleness management
       Rescores only assets flagged rescore_needed = true
       Updates scoring_timestamp and clears the flag
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from neo4j import GraphDatabase

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ── Constants matching the scoring model we defined ───────────────────────────

FREQ_WEIGHT   = {"rare": 0.3, "occasional": 0.6, "frequent": 1.0}
EXPLOIT_WEIGHT = {"theoretical": 0.2, "poc": 0.6, "weaponized": 1.0}
SCORING_MODEL_VERSION = "1.0.0"


# ── Cross-domain edge rules ───────────────────────────────────────────────────
# Each rule defines which asset types a technique class targets,
# what attack vector applies, and which asset properties make the edge valid.

TARGETS_RULES = [
    # (technique_external_id_prefix, asset_type, attack_vector, precondition_field, precondition_value)
    # ATLAS ML model evasion techniques → InferenceAPI assets
    ("AML.T0015", "InferenceAPI",  "query",         "auth_required",     False),
    ("AML.T0005", "InferenceAPI",  "query",         None,                None),
    ("AML.T0005", "AIModel",       "artifact",      None,                None),
    ("AML.T0043", "InferenceAPI",  "query",         None,                None),
    ("AML.T0043", "AIModel",       "artifact",      None,                None),
    # Data poisoning → TrainingData
    ("AML.T0020", "TrainingData",  "data_pipeline", None,                None),
    ("AML.T0020", "MLPipeline",    "pipeline",      None,                None),
    # Supply chain → MLPipeline / ModelRegistry
    ("AML.T0010", "MLPipeline",    "supply_chain",  None,                None),
    ("AML.T0010", "ModelRegistry", "supply_chain",  None,                None),
    # ATT&CK exfiltration → InferenceAPI with probability output
    ("T1530",     "TrainingData",  "cloud_storage", "is_public",         False),
    ("T1190",     "InferenceAPI",  "network",       None,                None),
    # LLM-specific
    ("AML.T0051", "InferenceAPI",  "query",         "output_type",       "text"),
]

# Control mappings: which controls (by name pattern) mitigate which techniques
MITIGATES_RULES = [
    # (control_name_contains, technique_prefix, effectiveness, asset_type_scope)
    ("rate limit",        "AML.T0005.003", 0.70, ["InferenceAPI"]),
    ("rate limit",        "AML.T0015",     0.55, ["InferenceAPI"]),
    ("authentication",    "T1190",         0.80, ["InferenceAPI"]),
    ("authentication",    "AML.T0005",     0.60, ["InferenceAPI"]),
    ("input validation",  "AML.T0051",     0.75, ["InferenceAPI"]),
    ("output filtering",  "AML.T0051",     0.65, ["InferenceAPI"]),
    ("access control",    "T1530",         0.85, ["TrainingData"]),
    ("signing",           "AML.T0010",     0.80, ["MLPipeline", "ModelRegistry"]),
    ("monitoring",        "AML.T0015",     0.45, ["InferenceAPI", "AIModel"]),
    ("differential privacy", "AML.T0024",  0.70, ["InferenceAPI", "TrainingData"]),
]


# ── Cypher queries ─────────────────────────────────────────────────────────────

ENSURE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS FOR (n:Vulnerability) ON (n.cve_id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:RiskScore)     ON (n.asset_id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:Technique)     ON (n.external_id)",
    "CREATE INDEX IF NOT EXISTS FOR (n:ThreatActor)   ON (n.stix_id)",
]

CREATE_TARGETS = """
UNWIND $batch AS e
MATCH (t {external_id: e.technique_id})
MATCH (a {asset_id: e.asset_id})
MERGE (t)-[r:TARGETS]->(a)
ON CREATE SET r.attack_vector     = e.attack_vector,
              r.precondition_met  = e.precondition_met,
              r.impact_category   = e.impact_category,
              r.asset_type_scope  = e.asset_type_scope,
              r.exploit_maturity  = e.exploit_maturity
ON MATCH  SET r.precondition_met  = e.precondition_met,
              r.exploit_maturity  = e.exploit_maturity
RETURN count(r) AS n
"""

CREATE_MITIGATES = """
UNWIND $batch AS e
MATCH (c:MitigationControl)
WHERE toLower(c.name) CONTAINS e.control_pattern
MATCH (t {external_id: e.technique_id})
MERGE (c)-[r:MITIGATES]->(t)
ON CREATE SET r.effectiveness     = e.effectiveness,
              r.asset_type_scope  = e.asset_type_scope,
              r.control_layer     = 'technical'
RETURN count(r) AS n
"""

# Fetch all assets that need rescoring with their threat path data
FETCH_THREAT_PATHS = """
MATCH (asset)
WHERE asset.rescore_needed = true
  AND asset.asset_id IS NOT NULL
MATCH (actor:ThreatActor)-[u:USES_TECHNIQUE]->(t:Technique)-[tgt:TARGETS]->(asset)
WHERE u.attribution_confidence IS NOT NULL
OPTIONAL MATCH (ctrl:MitigationControl)-[m:MITIGATES]->(t)
  WHERE asset.asset_type IN m.asset_type_scope
WITH asset,
     actor,
     t,
     u,
     tgt,
     asset.criticality_multiplier AS crit_mult,
     u.attribution_confidence * CASE u.frequency
       WHEN 'frequent'   THEN 1.0
       WHEN 'occasional' THEN 0.6
       ELSE 0.3 END AS actor_weight,
     CASE coalesce(tgt.exploit_maturity, 'theoretical')
       WHEN 'weaponized'  THEN 1.0
       WHEN 'poc'         THEN 0.6
       ELSE 0.2 END AS exploit_avail,
     coalesce(tgt.technique_reachability, 0.7) AS reachability,
     1.0 - coalesce(max(m.effectiveness), 0.0) AS residual
WITH asset.asset_id AS asset_id,
     crit_mult,
     collect({
       actor_id:    actor.stix_id,
       technique:   t.external_id,
       path_score:  actor_weight * exploit_avail * reachability * residual
     }) AS paths
RETURN asset_id, crit_mult, paths
"""

UPSERT_RISK_SCORE = """
UNWIND $batch AS s
MATCH (asset {asset_id: s.asset_id})
MERGE (rs:RiskScore {asset_id: s.asset_id})
SET rs.score              = s.score,
    rs.confidence         = s.confidence,
    rs.contributing_paths = s.contributing_paths,
    rs.top_threat_actor   = s.top_threat_actor,
    rs.scored_at          = s.scored_at,
    rs.model_version      = s.model_version
MERGE (asset)-[r:SCORED_BY]->(rs)
SET r.scoring_timestamp   = s.scored_at,
    r.score_version       = s.model_version,
    r.contributing_paths  = s.contributing_paths,
    r.top_threat_actor    = s.top_threat_actor
SET asset.rescore_needed  = false,
    asset.last_scored     = s.scored_at
RETURN count(rs) AS n
"""

FETCH_ALL_ASSETS = """
MATCH (a)
WHERE a.asset_id IS NOT NULL
SET a.rescore_needed = true
RETURN count(a) AS n
"""


# ── Scoring engine ─────────────────────────────────────────────────────────────

@dataclass
class ScoredAsset:
    asset_id:          str
    score:             float
    confidence:        float
    contributing_paths: int
    top_threat_actor:  str
    scored_at:         str = ""
    model_version:     str = SCORING_MODEL_VERSION

    def __post_init__(self):
        if not self.scored_at:
            self.scored_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return self.__dict__


def compute_asset_score(asset_id: str, paths: list[dict], crit_mult: float) -> ScoredAsset:
    """
    Applies the parallel failure mode formula:
      R = 1 - ∏(1 - Pᵢ)  ×  criticality_multiplier  ×  10

    Confidence is derived from the number of paths and actor attribution
    quality — more paths with high-confidence actors = higher confidence.
    """
    if not paths:
        return ScoredAsset(
            asset_id=asset_id, score=0.0, confidence=0.0,
            contributing_paths=0, top_threat_actor=""
        )

    path_scores = [min(1.0, max(0.0, p["path_score"])) for p in paths]
    combined_r  = 1.0 - 1.0
    product = 1.0
    for ps in path_scores:
        product *= (1.0 - ps)
    combined_r = 1.0 - product

    crit_mult  = max(1.0, min(2.0, crit_mult or 1.0))
    raw_score  = min(10.0, combined_r * 10.0 * crit_mult)
    score      = round(raw_score, 2)

    # Confidence: mean of path scores weighted by path count
    confidence = round(min(1.0, sum(path_scores) / max(1, len(path_scores))), 3)

    # Top threat actor by highest individual path score
    top_path = max(paths, key=lambda p: p["path_score"])
    top_actor = top_path.get("actor_id", "")

    return ScoredAsset(
        asset_id=asset_id,
        score=score,
        confidence=confidence,
        contributing_paths=len(paths),
        top_threat_actor=top_actor,
    )


# ── Graph builder ──────────────────────────────────────────────────────────────

class GraphBuilder:

    def __init__(self, neo4j_uri: str, user: str, password: str, batch_size: int = 300):
        self.driver     = GraphDatabase.driver(neo4j_uri, auth=(user, password))
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

    def ensure_indexes(self):
        with self.driver.session() as s:
            for q in ENSURE_INDEXES:
                s.run(q)
        log.info("Indexes verified")

    # ── A: Cross-domain edges ─────────────────────────────────────────────────

    def build_targets_edges(self) -> int:
        """
        Creates TARGETS edges between Technique nodes and AssetNodes based on
        TARGETS_RULES. Evaluates preconditions against live asset properties.
        """
        log.info("Building TARGETS edges …")
        targets_batch = []

        with self.driver.session() as s:
            for (tech_prefix, asset_type, attack_vector,
                 precond_field, precond_value) in TARGETS_RULES:

                # Find techniques matching the prefix
                tech_q = """
                MATCH (t:Technique)
                WHERE t.external_id STARTS WITH $prefix
                  AND NOT t.is_revoked
                RETURN t.external_id AS tid
                """
                tech_rows = s.run(tech_q, {"prefix": tech_prefix}).data()

                # Find assets of the matching type, evaluating preconditions
                if precond_field:
                    asset_q = f"""
                    MATCH (a:{asset_type})
                    WHERE a.{precond_field} = $pval
                    RETURN a.asset_id AS aid
                    """
                    asset_rows = s.run(asset_q, {"pval": precond_value}).data()
                else:
                    asset_q = f"""
                    MATCH (a:{asset_type})
                    RETURN a.asset_id AS aid
                    """
                    asset_rows = s.run(asset_q).data()

                for t in tech_rows:
                    for a in asset_rows:
                        targets_batch.append({
                            "technique_id":    t["tid"],
                            "asset_id":        a["aid"],
                            "attack_vector":   attack_vector,
                            "precondition_met": True,
                            "impact_category": "integrity",
                            "asset_type_scope": [asset_type],
                            "exploit_maturity": "theoretical",  # updated by vuln_loader
                            "technique_reachability": 0.7,
                        })

        count = self._batch_run(CREATE_TARGETS, targets_batch)
        log.info(f"Created {count} TARGETS edges")
        return count

    def build_mitigates_edges(self) -> int:
        """
        Creates MITIGATES edges from MitigationControl nodes to Technique nodes.
        Effectiveness and asset_type_scope come from MITIGATES_RULES.
        """
        log.info("Building MITIGATES edges …")
        mit_batch = []
        for (pattern, tech_prefix, eff, scope) in MITIGATES_RULES:
            mit_batch.append({
                "control_pattern": pattern,
                "technique_id":    tech_prefix,
                "effectiveness":   eff,
                "asset_type_scope": scope,
            })
        count = self._batch_run(CREATE_MITIGATES, mit_batch)
        log.info(f"Created {count} MITIGATES edges")
        return count

    # ── B: Scoring engine ─────────────────────────────────────────────────────

    def score_assets(self, force_all: bool = False) -> dict:
        """
        Scores all assets flagged rescore_needed = true.
        Set force_all=True to rescore every asset regardless of flag.
        """
        if force_all:
            with self.driver.session() as s:
                result = s.run(FETCH_ALL_ASSETS)
                flagged = result.single()["n"]
            log.info(f"Force-flagged {flagged} assets for rescore")

        log.info("Fetching threat paths for flagged assets …")
        with self.driver.session() as s:
            rows = s.run(FETCH_THREAT_PATHS).data()

        log.info(f"Computing scores for {len(rows)} assets …")
        scored = []
        for row in rows:
            sa = compute_asset_score(
                asset_id  = row["asset_id"],
                paths     = row["paths"],
                crit_mult = row.get("crit_mult") or 1.0,
            )
            scored.append(sa.to_dict())

        upserted = self._batch_run(UPSERT_RISK_SCORE, scored)
        log.info(f"Upserted {upserted} RiskScore nodes")

        # Summary stats
        if scored:
            scores = [s["score"] for s in scored]
            critical = sum(1 for s in scores if s >= 9.0)
            high     = sum(1 for s in scores if 7.0 <= s < 9.0)
            medium   = sum(1 for s in scores if 5.0 <= s < 7.0)
            low      = sum(1 for s in scores if s < 5.0)
            log.info(
                f"Score distribution — critical:{critical} high:{high} "
                f"medium:{medium} low:{low} "
                f"(mean={sum(scores)/len(scores):.2f})"
            )

        return {"scored": upserted, "paths_evaluated": sum(len(r["paths"]) for r in rows)}

    # ── C: Full build ─────────────────────────────────────────────────────────

    def build(self, force_rescore: bool = False) -> dict:
        """
        Runs the complete graph builder sequence:
          1. Ensure indexes
          2. TARGETS edges
          3. MITIGATES edges
          4. Risk scoring
        """
        log.info("=== Graph builder starting ===")
        self.ensure_indexes()

        targets  = self.build_targets_edges()
        mitigates = self.build_mitigates_edges()
        scoring  = self.score_assets(force_all=force_rescore)

        summary = {
            "targets_edges":   targets,
            "mitigates_edges": mitigates,
            **scoring,
        }
        log.info(f"Graph builder complete: {summary}")
        return summary


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Build cross-domain edges and score assets")
    parser.add_argument("--force-rescore", action="store_true",
                        help="Rescore all assets, not just flagged ones")
    parser.add_argument("--uri",      default="bolt://localhost:7687")
    parser.add_argument("--user",     default="neo4j")
    parser.add_argument("--password", default="password")
    args = parser.parse_args()

    builder = GraphBuilder(args.uri, args.user, args.password)
    try:
        builder.build(force_rescore=args.force_rescore)
    finally:
        builder.close()


if __name__ == "__main__":
    main()
