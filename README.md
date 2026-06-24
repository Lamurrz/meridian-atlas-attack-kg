# Meridian MITRE Atlas to MITRE Att@ck Knowledge Graph

A knowledge graph system for evaluating AI system exposure to adversarial threats by cross-referencing **MITRE ATLAS** and **MITRE ATT&CK** framework data with an asset inventory and live vulnerability intelligence.

Built to support dynamic risk prioritization of AI assets — answering the question: *given your deployed AI systems and the current threat landscape, which assets are most exposed, to whom, and through what attack paths?*

---

## Architecture overview

The graph is structured as three layered domains that merge into a unified Neo4j property graph:

```
┌─────────────────────────────────────────────────────┐
│  Threat framework domain  (read-only, MITRE-sourced) │
│  Tactic · Technique · SubTechnique                   │
│  ThreatActor · Campaign · MitigationControl          │
└────────────────────┬────────────────────────────────┘
                     │  TARGETS · USES_TECHNIQUE
                     │  MITIGATES · MAPS_TO
┌────────────────────▼────────────────────────────────┐
│  Asset inventory domain   (org-specific)             │
│  AIModel · InferenceAPI · TrainingData               │
│  MLPipeline · ModelRegistry                          │
└────────────────────┬────────────────────────────────┘
                     │  AFFECTS · EXPLOITS
                     │  SCORED_BY
┌────────────────────▼────────────────────────────────┐
│  Intelligence & scoring domain  (computed)           │
│  Vulnerability · RiskScore                           │
└─────────────────────────────────────────────────────┘
```

### Key design decisions

**Neo4j over RDF** — query patterns are graph traversals (path-finding, risk aggregation), not ontological inference. Cypher handles these more intuitively than SPARQL at this scale.

**ATLAS + ATT&CK cross-framework mapping** — ATLAS techniques that have no ATT&CK peer (proxy model creation, ML model evasion, model access) are modeled as ATLAS-only nodes with outbound `ENABLES` edges to the ATT&CK techniques they make operationally viable. Mapping edges carry `confidence_score`, `mapping_type`, and `validity_scope` properties to prevent over-broad risk scoring.

**Validity-scoped edges** — `TARGETS` and `MITIGATES` edges carry `asset_type_scope` arrays. A rate-limiting control applied to an `InferenceAPI` is not credited against a `TrainingData` node. This scoping prevents the scoring engine from double-counting controls that don't apply.

**Parallel failure mode scoring** — asset risk is computed as `R = 1 − ∏(1 − Pᵢ)` across all active threat paths, scaled 0–10 and multiplied by an asset criticality factor. This correctly models an asset with many weak paths as riskier than one with a single weak path, while preventing unrealistically high scores from many low-probability paths.

---

## Confirmed graph statistics (full build)

| Component | Count |
|-----------|-------|
| Technique nodes | 1,886 |
| ThreatActor nodes | 378 |
| MitigationControl nodes | 571 |
| Tactic nodes | 46 |
| Campaign nodes | 112 |
| Total edges | 40,920 |
| TARGETS edges (cross-domain) | 130 |
| MITIGATES edges (cross-domain) | 15 |
| RiskScore nodes populated | 9 |
| Threat paths evaluated | 181 |
| Mean asset risk score | 6.02 |

---

## Repository structure

```
.
├── bootstrap.py              # Orchestrator — single entry point for all modes
├── stix_taxii_ingestion.py   # Threat framework domain: STIX/TAXII → Neo4j
├── asset_loader.py           # Asset inventory domain: JSON/CSV → Neo4j
├── vuln_loader.py            # Intelligence domain: NVD CVEs → Neo4j
├── graph_builder.py          # Cross-domain edges + risk scoring engine
└── requirements.txt
```

---

## Prerequisites

- Python 3.11+
- Neo4j 5.x (Community or Enterprise) running locally or remotely
- Optional: NVD API key from [nvd.nist.gov/developers](https://nvd.nist.gov/developers/request-an-api-key) (increases rate limit from 5 to 50 req/30s)

```bash
pip install -r requirements.txt
```

---

## Quick start

### First-time full build (with sample assets)

```bash
python bootstrap.py --mode full --seed-assets --password <your_neo4j_password>
```

This runs the complete pipeline:

1. Pulls ATT&CK and ATLAS STIX bundles from GitHub
2. Loads built-in sample AI asset inventory
3. Fetches ML-relevant CVEs from NVD
4. Creates cross-domain edges and computes risk scores

Expected duration: 3–8 minutes depending on NVD response times.

### First-time build with your own asset inventory

```bash
python bootstrap.py --mode full --asset-input my_assets.json --password <your_neo4j_password>
```

See [Asset inventory format](#asset-inventory-format) below for the expected schema.

### Scheduled updates

```bash
# Daily incremental update (recommended: cron at 04:00 UTC)
python bootstrap.py --mode daily --password <your_neo4j_password>

# Weekly full refresh (recommended: cron Sunday 02:00 UTC)
python bootstrap.py --mode full --password <your_neo4j_password>
```

### Targeted operations

```bash
# Reload asset inventory and rescore affected assets
python bootstrap.py --mode assets --asset-input updated_assets.json --password <pw>

# Refresh vulnerability intel only
python bootstrap.py --mode vulns --vuln-days 90 --password <pw>

# Rescore all assets without fetching new data
python bootstrap.py --mode score --force-rescore --password <pw>
```

---

## Configuration

All settings can be provided via CLI flags or environment variables:

| Environment variable | CLI flag | Default | Description |
|---|---|---|---|
| `NEO4J_URI` | `--uri` | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_USER` | `--user` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `--password` | `password` | Neo4j password |
| `NVD_API_KEY` | `--nvd-key` | *(empty)* | NVD API key |

---

## Module reference

### `stix_taxii_ingestion.py`

Populates the threat framework domain from two sources:

**Track 1 — Weekly GitHub bulk pull**

- `mitre-attack/attack-stix-data` — ATT&CK Enterprise STIX 2.1 bundle
- `mitre-atlas/atlas-navigator-data` — Combined ATLAS + ATT&CK STIX bundle

**Track 2 — Daily TAXII 2.1 delta**

- `attack-taxii.mitre.org` — incremental fetch using `added_after` cursor
- Rate-limited to 10 requests per 10 minutes with exponential backoff

STIX object types mapped to Neo4j labels:

| STIX type | Neo4j label |
|---|---|
| `attack-pattern` | `Technique` |
| `intrusion-set` | `ThreatActor` |
| `course-of-action` | `MitigationControl` |
| `x-mitre-tactic` | `Tactic` |
| `campaign` | `Campaign` |
| `malware` / `tool` | `Software` |

---

### `asset_loader.py`

Ingests an AI asset inventory as the asset domain layer. Accepts JSON or CSV.

**Node types created:** `AIModel`, `InferenceAPI`, `TrainingData`, `MLPipeline`, `ModelRegistry`

#### Asset inventory format

```json
[
  {
    "asset_id": "api-fraud-inference",
    "asset_type": "InferenceAPI",
    "name": "Fraud scoring API",
    "output_type": "probability",
    "rate_limit_rpm": 0,
    "auth_required": true,
    "criticality_multiplier": 1.8
  }
]
```

---

### `vuln_loader.py`

Pulls CVE data from the NVD API v2 and links it into the graph.

ML framework CPE patterns tracked: `tensorflow` · `pytorch` · `scikit-learn` · `transformers` · `onnxruntime` · `mlflow` · `ray` · `triton` · `torchserve` · `jupyter` · `numpy` · `pillow` · `langchain`

---

### `graph_builder.py`

The integration layer. Runs after all three domain loaders.

**Cross-domain edges created:**

- `TARGETS` — links Technique nodes to asset nodes based on technique prefix and asset type rules
- `MITIGATES` — links MitigationControl nodes to Technique nodes with asset-type-scoped effectiveness

**Risk scoring formula:**

```
Per threat path:
  Pᵢ = actor_weight × exploit_availability × technique_reachability × (1 − control_effectiveness)

  actor_weight = coalesce(attribution_confidence, 0.5) × frequency_weight
  frequency_weight = {rare: 0.3, occasional: 0.6, frequent: 1.0}

Asset-level aggregation (parallel failure mode):
  R = (1 − ∏(1 − Pᵢ)) × criticality_multiplier × 10
```

**Note:** `attribution_confidence` and `frequency` are not present on all `USES_TECHNIQUE`
edges in the STIX data. The scoring query uses `coalesce()` to default to `0.5` confidence
and `occasional` frequency when these properties are absent, ensuring all threat paths
contribute to asset risk scores.

---

## Example Cypher queries

**Top 10 highest-risk assets:**

```cypher
MATCH (a)-[:SCORED_BY]->(r:RiskScore)
RETURN a.name, a.asset_type, r.score, r.contributing_paths
ORDER BY r.score DESC LIMIT 10
```

**Assets with empirical anomaly evidence (from CyberGraph-AD):**

```cypher
MATCH (a)-[:SCORED_BY]->(r:RiskScore)
WHERE r.adjusted_score IS NOT NULL
RETURN a.name, a.asset_type, r.score AS theoretical,
       r.adjusted_score AS empirical, r.anomaly_types
ORDER BY r.adjusted_score DESC
```

**All active threat paths to a specific asset:**

```cypher
MATCH (actor:ThreatActor)-[:USES_TECHNIQUE]->(t:Technique)
      -[:TARGETS]->(a {asset_id: 'api-fraud-inference'})
RETURN actor.name, t.external_id, t.name
ORDER BY actor.name
```

**Control gap analysis — techniques with no mitigating control:**

```cypher
MATCH (t:Technique)-[:TARGETS]->(a)
WHERE NOT (:MitigationControl)-[:MITIGATES]->(t)
  AND NOT t.is_revoked
RETURN t.external_id, t.name, count(a) AS assets_exposed
ORDER BY assets_exposed DESC
```

---

## Scheduling

```
# Weekly full refresh — Sunday 02:00 UTC
0 2 * * 0  cd /path/to/repo && python bootstrap.py --mode full --password <pw> >> logs/weekly.log 2>&1

# Daily delta — 04:00 UTC
0 4 * * *  cd /path/to/repo && python bootstrap.py --mode daily --password <pw> >> logs/daily.log 2>&1
```

---

## Background

This system grew out of research into the structural relationship between MITRE ATLAS (adversarial ML threats) and MITRE ATT&CK (enterprise threat framework). Three ATLAS tactics have no direct ATT&CK peer: ML attack staging, ML model access, and ML model evasion. These are modeled as ATLAS-only nodes with outbound edges to the ATT&CK techniques they make operationally viable.

The proxy model subgraph (`AML.T0005.x`) is treated as the highest-value staging risk surface: an adversary who can build a proxy model reduces their attack cost for every subsequent evasion or extraction technique.

---

## License

MIT
