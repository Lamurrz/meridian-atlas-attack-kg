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
python bootstrap.py --mode full --seed-assets
```

This runs the complete pipeline:
1. Pulls ATT&CK and ATLAS STIX bundles from GitHub
2. Loads built-in sample AI asset inventory
3. Fetches ML-relevant CVEs from NVD
4. Creates cross-domain edges and computes risk scores

Expected duration: 3–8 minutes depending on NVD response times.

### First-time build with your own asset inventory

```bash
python bootstrap.py --mode full --asset-input my_assets.json
```

See [Asset inventory format](#asset-inventory-format) below for the expected schema.

### Scheduled updates

```bash
# Daily incremental update (recommended: cron at 04:00 UTC)
python bootstrap.py --mode daily

# Weekly full refresh (recommended: cron Sunday 02:00 UTC)
python bootstrap.py --mode full
```

### Targeted operations

```bash
# Reload asset inventory and rescore affected assets
python bootstrap.py --mode assets --asset-input updated_assets.json

# Refresh vulnerability intel only
python bootstrap.py --mode vulns --vuln-days 90

# Rescore all assets without fetching new data
python bootstrap.py --mode score --force-rescore
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
- `mitre-atlas/atlas-navigator-data` — Combined ATLAS + ATT&CK STIX bundle (includes MITRE-curated cross-framework relationships)

**Track 2 — Daily TAXII 2.1 delta**
- `attack-taxii.mitre.org` — incremental fetch using `added_after` cursor
- Rate-limited to 10 requests per 10 minutes; implements token-bucket throttling and exponential backoff on 429 responses

STIX object types mapped to Neo4j labels:

| STIX type | Neo4j label |
|---|---|
| `attack-pattern` | `Technique` |
| `intrusion-set` | `ThreatActor` |
| `course-of-action` | `MitigationControl` |
| `x-mitre-tactic` | `Tactic` |
| `campaign` | `Campaign` |
| `malware` / `tool` | `Software` |

STIX relationship types mapped to Neo4j edge labels:

| STIX `relationship_type` | Neo4j relationship |
|---|---|
| `uses` | `USES_TECHNIQUE` |
| `mitigates` | `MITIGATES` |
| `subtechnique-of` | `SUBTECHNIQUE_OF` |
| `revoked-by` | `REVOKED_BY` |

---

### `asset_loader.py`

Ingests an AI asset inventory as the asset domain layer. Accepts JSON or CSV; includes a field-name normalizer that handles common CMDB export variants.

**Node types created:** `AIModel`, `InferenceAPI`, `TrainingData`, `MLPipeline`, `ModelRegistry`

**Edges created:** `(AssetNode)-[:PART_OF]->(MLPipeline)`

#### Asset inventory format

Assets are defined as a JSON array (or a dict with an `assets` key):

```json
[
  {
    "asset_id": "pipeline-fraud-001",
    "asset_type": "MLPipeline",
    "name": "Fraud detection pipeline",
    "exposure_level": "restricted",
    "criticality_multiplier": 1.8,
    "owner_team": "risk-ml"
  },
  {
    "asset_id": "model-fraud-xgb-v3",
    "asset_type": "AIModel",
    "name": "Fraud XGBoost v3",
    "ml_framework": "sklearn",
    "model_family": "gbm",
    "architecture_public": false,
    "pipeline_id": "pipeline-fraud-001",
    "pipeline_stage": "serve",
    "criticality_multiplier": 1.8
  },
  {
    "asset_id": "api-fraud-inference",
    "asset_type": "InferenceAPI",
    "name": "Fraud scoring API",
    "endpoint_url": "https://api.internal/fraud/v3/score",
    "output_type": "probability",
    "rate_limit_rpm": 0,
    "auth_required": true,
    "pipeline_id": "pipeline-fraud-001",
    "pipeline_stage": "serve"
  },
  {
    "asset_id": "data-fraud-training",
    "asset_type": "TrainingData",
    "name": "Fraud training dataset",
    "is_public": false,
    "contains_pii": true,
    "domain": "financial-transactions",
    "exposure_level": "confidential",
    "pipeline_id": "pipeline-fraud-001",
    "pipeline_stage": "train"
  }
]
```

**Key properties by asset type:**

| Property | Applies to | Effect on scoring |
|---|---|---|
| `output_type` | `InferenceAPI` | `probability`/`logit` output enables higher-fidelity proxy model attacks |
| `rate_limit_rpm` | `InferenceAPI` | `0` (unlimited) increases reachability for query-based techniques |
| `auth_required` | `InferenceAPI` | `false` raises exploit availability for unauthenticated attack vectors |
| `architecture_public` | `AIModel` | `true` enables exact proxy model replication (higher transfer rate) |
| `contains_pii` | `TrainingData` | `true` elevates impact category for exfiltration techniques |
| `is_public` | `TrainingData` | `true` enables adversary dataset acquisition for staging attacks |
| `criticality_multiplier` | all | Float 1.0–2.0; pipeline position risk weight applied to final score |
| `exposure_level` | all | `public` > `internal` > `restricted` > `confidential` |

---

### `vuln_loader.py`

Pulls CVE data from the NVD API v2 and links it into the graph.

**Nodes created:** `Vulnerability`

**Edges created:**
- `(Vulnerability)-[:AFFECTS]->(AssetNode)` — matched by asset `ml_framework` against CVE CPE strings
- `(Technique)-[:EXPLOITS]->(Vulnerability)` — mapped via `CPE_TO_TECHNIQUE` lookup table

**ML framework CPE patterns tracked** (extend `ML_CPE_PATTERNS` in `vuln_loader.py`):

`tensorflow` · `pytorch` · `scikit-learn` · `transformers` · `onnxruntime` · `mlflow` · `ray` · `triton` · `torchserve` · `jupyter` · `numpy` · `pillow` · `langchain`

**Exploit maturity mapping from CVSS:**

| CVSS v3 base score | `exploit_maturity` | Weight in scoring |
|---|---|---|
| ≥ 9.0 | `weaponized` | 1.0 |
| 7.0 – 8.9 | `poc` | 0.6 |
| < 7.0 | `theoretical` | 0.2 |

---

### `graph_builder.py`

The integration layer. Runs after all three domain loaders.

**Cross-domain edges created:**

`TARGETS` — links `Technique` nodes to `AssetNode` targets based on rules in `TARGETS_RULES`. Each rule specifies the technique prefix, asset type, attack vector, and an optional precondition evaluated against live asset properties. Example: `AML.T0051` (prompt injection) only targets `InferenceAPI` assets where `output_type = 'text'`.

`MITIGATES` — links `MitigationControl` nodes to `Technique` nodes based on `MITIGATES_RULES`. Each rule specifies a control name pattern, technique prefix, effectiveness score (0–1), and asset type scope. Effectiveness is asset-type-scoped — a rate limiter on an `InferenceAPI` does not reduce risk for `TrainingData` attacks.

**Risk scoring formula:**

Per threat path:
```
Pᵢ = actor_weight × exploit_availability × technique_reachability × (1 − max_control_effectiveness)

where:
  actor_weight        = attribution_confidence × frequency_weight
  frequency_weight    = {rare: 0.3, occasional: 0.6, frequent: 1.0}
  exploit_availability = {theoretical: 0.2, poc: 0.6, weaponized: 1.0}
```

Asset-level aggregation (parallel failure mode):
```
R = (1 − ∏(1 − Pᵢ)) × criticality_multiplier × 10
```

Scores are written as `RiskScore` nodes linked to assets via `SCORED_BY` edges. Only assets flagged `rescore_needed = true` are rescored on incremental runs.

---

## Example Cypher queries

**Top 10 highest-risk assets:**
```cypher
MATCH (a)-[:SCORED_BY]->(r:RiskScore)
RETURN a.name, a.asset_type, r.score, r.contributing_paths
ORDER BY r.score DESC LIMIT 10
```

**All active threat paths to a specific asset:**
```cypher
MATCH (actor:ThreatActor)-[:USES_TECHNIQUE]->(t:Technique)
      -[:TARGETS]->(a {asset_id: 'api-fraud-inference'})
RETURN actor.name, t.external_id, t.name
ORDER BY actor.name
```

**Assets exposed to a specific threat actor:**
```cypher
MATCH (actor:ThreatActor {name: 'APT41'})-[:USES_TECHNIQUE]->(t:Technique)
      -[:TARGETS]->(a)
MATCH (a)-[:SCORED_BY]->(r:RiskScore)
RETURN a.name, a.asset_type, t.external_id, r.score
ORDER BY r.score DESC
```

**Control gap analysis — techniques with no mitigating control:**
```cypher
MATCH (t:Technique)-[:TARGETS]->(a)
WHERE NOT (:MitigationControl)-[:MITIGATES]->(t)
  AND NOT t.is_revoked
RETURN t.external_id, t.name, count(a) AS assets_exposed
ORDER BY assets_exposed DESC
```

**Pipeline-level risk propagation — find inference APIs backed by PII training data:**
```cypher
MATCH (api:InferenceAPI)-[:PART_OF]->(pipe:MLPipeline)
      <-[:PART_OF]-(td:TrainingData)
WHERE td.contains_pii = true
MATCH (api)-[:SCORED_BY]->(r:RiskScore)
RETURN api.name, pipe.name, td.name, r.score
ORDER BY r.score DESC
```

**Assets where proxy model staging is viable (exposed architecture + unlimited API):**
```cypher
MATCH (api:InferenceAPI)-[:PART_OF]->(pipe:MLPipeline)
      <-[:PART_OF]-(model:AIModel)
WHERE model.architecture_public = true
  AND api.rate_limit_rpm = 0
RETURN api.asset_id, model.name, api.output_type
```

---

## Scheduling

Recommended cron schedule:

```cron
# Weekly full refresh — Sunday 02:00 UTC
0 2 * * 0  cd /path/to/repo && python bootstrap.py --mode full >> logs/weekly.log 2>&1

# Daily delta — 04:00 UTC
0 4 * * *  cd /path/to/repo && python bootstrap.py --mode daily >> logs/daily.log 2>&1
```

---

## Extending the system

**Adding new asset types** — add the label to `VALID_ASSET_TYPES` in `asset_loader.py` and create the corresponding Neo4j constraint. Add targeting rules to `TARGETS_RULES` in `graph_builder.py`.

**Adding new ML framework CVE coverage** — add an entry to `ML_CPE_PATTERNS` in `vuln_loader.py` with the CPE string pattern, framework name, and relevant asset types. Add technique mappings to `CPE_TO_TECHNIQUE`.

**Adding custom TARGETS rules** — extend `TARGETS_RULES` in `graph_builder.py`. Each rule is a tuple of `(technique_prefix, asset_type, attack_vector, precondition_field, precondition_value)`.

**Tuning control effectiveness** — edit `MITIGATES_RULES` in `graph_builder.py`. Effectiveness values (0–1) are per-rule and asset-type-scoped.

**Adjusting the scoring model** — `FREQ_WEIGHT` and `EXPLOIT_WEIGHT` dicts in `graph_builder.py` control the step-function mappings. The `criticality_multiplier` bounds (1.0–2.0) are enforced in `compute_asset_score()`.

---

## Background

This system grew out of research into the structural relationship between MITRE ATLAS (adversarial ML threats) and MITRE ATT&CK (enterprise threat framework). Three ATLAS tactics have no direct ATT&CK peer: ML attack staging, ML model access, and ML model evasion. These are modeled as ATLAS-only nodes with outbound edges to the ATT&CK techniques they make operationally viable.

The proxy model subgraph (`AML.T0005.x`) is treated as the highest-value staging risk surface: an adversary who can build a proxy model reduces their attack cost for every subsequent evasion or extraction technique. Assets that expose sufficient information to enable proxy construction — public inference APIs with probability output, disclosed model architectures, publicly accessible training datasets — carry elevated staging risk independent of direct attack surface.

---

## License

MIT
