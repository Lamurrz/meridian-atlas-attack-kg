"""
Asset Loader
Ingests an AI asset inventory into Neo4j as the asset domain layer.

Input formats supported:
  - JSON  (list of asset dicts, or CMDB export)
  - CSV   (one asset per row)
  - dict  (programmatic use)

Node types created:
  AIModel, InferenceAPI, TrainingData, MLPipeline, ModelRegistry

Edges created:
  (AIModel)-[:PART_OF]->(MLPipeline)
  (InferenceAPI)-[:PART_OF]->(MLPipeline)
  (TrainingData)-[:PART_OF]->(MLPipeline)

Usage:
  python asset_loader.py --input assets.json
  python asset_loader.py --input assets.csv --format csv
"""

import argparse
import csv
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ── Asset type definitions ────────────────────────────────────────────────────

VALID_ASSET_TYPES = {
    "AIModel", "InferenceAPI", "TrainingData",
    "MLPipeline", "ModelRegistry",
}

VALID_OUTPUT_TYPES = {"probability", "logit", "top1", "embedding", "text", "binary"}
VALID_EXPOSURE_LEVELS = {"public", "internal", "restricted", "confidential"}
VALID_PIPELINE_STAGES = {"ingest", "train", "eval", "serve", "monitor"}
VALID_FRAMEWORKS = {"pytorch", "tensorflow", "sklearn", "jax", "onnx", "huggingface", "other"}


# ── Cypher queries ─────────────────────────────────────────────────────────────

UPSERT_ASSET = """
UNWIND $batch AS a
CALL apoc.merge.node(
    [a.asset_type],
    {asset_id: a.asset_id},
    a,
    {name: a.name, description: a.description,
     exposure_level: a.exposure_level, updated_at: a.updated_at,
     rescore_needed: true}
) YIELD node RETURN count(node) AS n
"""

# Fallback without APOC
UPSERT_ASSET_PLAIN = """
UNWIND $batch AS a
MERGE (n {asset_id: a.asset_id})
ON CREATE SET n += a, n.created_at = a.updated_at
ON MATCH  SET n.name           = a.name,
              n.description    = a.description,
              n.exposure_level = a.exposure_level,
              n.updated_at     = a.updated_at,
              n.rescore_needed = true
RETURN count(n) AS n
"""

CREATE_PART_OF = """
UNWIND $batch AS e
MATCH (child {asset_id: e.child_id})
MATCH (pipe:MLPipeline {asset_id: e.pipeline_id})
MERGE (child)-[r:PART_OF]->(pipe)
ON CREATE SET r.pipeline_stage       = e.pipeline_stage,
              r.data_flow_direction  = e.data_flow_direction,
              r.criticality_multiplier = e.criticality_multiplier
RETURN count(r) AS n
"""

ENSURE_CONSTRAINTS = """
CREATE CONSTRAINT IF NOT EXISTS
FOR (n:{label}) REQUIRE n.asset_id IS UNIQUE
"""


# ── Asset model ───────────────────────────────────────────────────────────────

@dataclass
class AssetRecord:
    asset_id:     str
    asset_type:   str
    name:         str
    description:  str       = ""
    pipeline_id:  str       = ""          # which MLPipeline this belongs to
    pipeline_stage: str     = "serve"     # ingest | train | eval | serve | monitor
    data_flow_direction: str = "downstream"
    criticality_multiplier: float = 1.0  # 1.0–2.0; used in risk formula

    # AIModel-specific
    ml_framework:   str   = ""
    model_family:   str   = ""           # transformer | cnn | gbm | llm | other
    architecture_public: bool = False

    # InferenceAPI-specific
    endpoint_url:   str   = ""
    output_type:    str   = "probability"  # probability | logit | top1 | embedding
    rate_limit_rpm: int   = 0             # 0 = unlimited
    auth_required:  bool  = True

    # TrainingData-specific
    is_public:      bool  = False
    contains_pii:   bool  = False
    domain:         str   = ""

    # Common
    exposure_level: str   = "internal"   # public | internal | restricted | confidential
    owner_team:     str   = ""
    tags:           list  = field(default_factory=list)
    updated_at:     str   = ""

    def __post_init__(self):
        if not self.asset_id:
            self.asset_id = str(uuid.uuid4())
        if self.asset_type not in VALID_ASSET_TYPES:
            raise ValueError(f"Invalid asset_type: {self.asset_type}")
        if self.exposure_level not in VALID_EXPOSURE_LEVELS:
            self.exposure_level = "internal"
        if not self.updated_at:
            self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if v != "" and v is not None}
        d["asset_type"] = self.asset_type
        return d


# ── Normalizer ────────────────────────────────────────────────────────────────

def normalize_asset(raw: dict) -> AssetRecord:
    """
    Accepts a loosely-typed dict from JSON/CSV and returns a validated AssetRecord.
    Handles common field name variants from CMDB exports.
    """
    def get(*keys, default=""):
        for k in keys:
            if k in raw and raw[k] not in (None, ""):
                return raw[k]
        return default

    asset_type = get("asset_type", "type", "asset_class", default="AIModel")
    if asset_type not in VALID_ASSET_TYPES:
        # Attempt heuristic mapping
        t = asset_type.lower()
        if "api" in t or "endpoint" in t:
            asset_type = "InferenceAPI"
        elif "train" in t or "dataset" in t or "data" in t:
            asset_type = "TrainingData"
        elif "pipeline" in t:
            asset_type = "MLPipeline"
        elif "registry" in t or "artifact" in t:
            asset_type = "ModelRegistry"
        else:
            asset_type = "AIModel"

    crit = float(get("criticality_multiplier", "criticality", "crit_mult", default=1.0))
    crit = max(1.0, min(2.0, crit))

    return AssetRecord(
        asset_id    = str(get("asset_id", "id", "uuid", default=str(uuid.uuid4()))),
        asset_type  = asset_type,
        name        = get("name", "asset_name", "display_name", default="unnamed"),
        description = get("description", "desc", "notes", default=""),
        pipeline_id = get("pipeline_id", "pipeline", "ml_pipeline", default=""),
        pipeline_stage = get("pipeline_stage", "stage", default="serve"),
        data_flow_direction = get("data_flow_direction", "flow", default="downstream"),
        criticality_multiplier = crit,
        ml_framework   = get("ml_framework", "framework", default=""),
        model_family   = get("model_family", "family", "model_type", default=""),
        architecture_public = bool(get("architecture_public", "arch_public", default=False)),
        endpoint_url   = get("endpoint_url", "url", "endpoint", default=""),
        output_type    = get("output_type", "api_output_type", default="probability"),
        rate_limit_rpm = int(get("rate_limit_rpm", "rate_limit", default=0)),
        auth_required  = bool(get("auth_required", "requires_auth", default=True)),
        is_public      = bool(get("is_public", "public", default=False)),
        contains_pii   = bool(get("contains_pii", "pii", default=False)),
        domain         = get("domain", "data_domain", default=""),
        exposure_level = get("exposure_level", "exposure", default="internal"),
        owner_team     = get("owner_team", "team", "owner", default=""),
        tags           = raw.get("tags", []),
    )


# ── Loader ────────────────────────────────────────────────────────────────────

class AssetLoader:

    def __init__(self, neo4j_uri: str, user: str, password: str, batch_size: int = 200):
        self.driver     = GraphDatabase.driver(neo4j_uri, auth=(user, password))
        self.batch_size = batch_size

    def close(self):
        self.driver.close()

    def ensure_constraints(self):
        with self.driver.session() as s:
            for label in VALID_ASSET_TYPES:
                s.run(ENSURE_CONSTRAINTS.format(label=label))
        log.info("Asset constraints verified")

    def _batch_run(self, query: str, items: list, param: str = "batch") -> int:
        total = 0
        with self.driver.session() as s:
            for i in range(0, len(items), self.batch_size):
                chunk = items[i: i + self.batch_size]
                r = s.run(query, {param: chunk})
                total += r.single()["n"]
        return total

    def load_records(self, records: list[AssetRecord]) -> dict:
        if not records:
            log.warning("No asset records to load")
            return {"nodes": 0, "edges": 0}

        asset_dicts = [r.to_dict() for r in records]
        nodes = self._batch_run(UPSERT_ASSET_PLAIN, asset_dicts)
        log.info(f"Upserted {nodes} asset nodes")

        # Build PART_OF edges for assets that declare a pipeline_id
        edges = [
            {
                "child_id":    r.asset_id,
                "pipeline_id": r.pipeline_id,
                "pipeline_stage": r.pipeline_stage,
                "data_flow_direction": r.data_flow_direction,
                "criticality_multiplier": r.criticality_multiplier,
            }
            for r in records
            if r.pipeline_id and r.asset_type != "MLPipeline"
        ]
        edge_count = self._batch_run(CREATE_PART_OF, edges) if edges else 0
        log.info(f"Created {edge_count} PART_OF edges")
        return {"nodes": nodes, "edges": edge_count}

    # ── Input format readers ──────────────────────────────────────────────────

    def load_from_json(self, path: str) -> dict:
        data = json.loads(Path(path).read_text())
        if isinstance(data, dict):
            data = data.get("assets", data.get("items", [data]))
        records = [normalize_asset(d) for d in data]
        log.info(f"Loaded {len(records)} assets from {path}")
        return self.load_records(records)

    def load_from_csv(self, path: str) -> dict:
        records = []
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                records.append(normalize_asset(dict(row)))
        log.info(f"Loaded {len(records)} assets from {path}")
        return self.load_records(records)

    def load_from_dicts(self, items: list[dict]) -> dict:
        records = [normalize_asset(d) for d in items]
        return self.load_records(records)


# ── Sample seed data ───────────────────────────────────────────────────────────

SAMPLE_ASSETS = [
    {
        "asset_id": "pipeline-fraud-001",
        "asset_type": "MLPipeline",
        "name": "Fraud detection pipeline",
        "description": "Real-time transaction fraud scoring pipeline",
        "exposure_level": "restricted",
        "criticality_multiplier": 1.8,
        "owner_team": "risk-ml",
    },
    {
        "asset_id": "model-fraud-xgb-v3",
        "asset_type": "AIModel",
        "name": "Fraud XGBoost v3",
        "ml_framework": "sklearn",
        "model_family": "gbm",
        "architecture_public": False,
        "exposure_level": "restricted",
        "pipeline_id": "pipeline-fraud-001",
        "pipeline_stage": "serve",
        "criticality_multiplier": 1.8,
    },
    {
        "asset_id": "api-fraud-inference",
        "asset_type": "InferenceAPI",
        "name": "Fraud scoring API",
        "endpoint_url": "https://api.internal/fraud/v3/score",
        "output_type": "probability",
        "rate_limit_rpm": 0,
        "auth_required": True,
        "exposure_level": "internal",
        "pipeline_id": "pipeline-fraud-001",
        "pipeline_stage": "serve",
        "criticality_multiplier": 1.8,
    },
    {
        "asset_id": "data-fraud-training-2024",
        "asset_type": "TrainingData",
        "name": "Fraud training dataset 2024",
        "is_public": False,
        "contains_pii": True,
        "domain": "financial-transactions",
        "exposure_level": "confidential",
        "pipeline_id": "pipeline-fraud-001",
        "pipeline_stage": "train",
        "criticality_multiplier": 1.5,
    },
    {
        "asset_id": "pipeline-nlp-001",
        "asset_type": "MLPipeline",
        "name": "Customer support LLM pipeline",
        "exposure_level": "internal",
        "criticality_multiplier": 1.3,
        "owner_team": "nlp-team",
    },
    {
        "asset_id": "model-support-llm",
        "asset_type": "AIModel",
        "name": "Support LLM (fine-tuned Mistral)",
        "ml_framework": "huggingface",
        "model_family": "llm",
        "architecture_public": True,
        "exposure_level": "internal",
        "pipeline_id": "pipeline-nlp-001",
        "pipeline_stage": "serve",
        "criticality_multiplier": 1.3,
    },
    {
        "asset_id": "api-support-chat",
        "asset_type": "InferenceAPI",
        "name": "Customer support chat API",
        "endpoint_url": "https://api.internal/support/chat",
        "output_type": "text",
        "rate_limit_rpm": 600,
        "auth_required": True,
        "exposure_level": "public",
        "pipeline_id": "pipeline-nlp-001",
        "pipeline_stage": "serve",
        "criticality_multiplier": 1.5,
    },
]


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Load AI asset inventory into Neo4j")
    parser.add_argument("--input",    default=None, help="Path to JSON or CSV asset file")
    parser.add_argument("--format",   default="json", choices=["json", "csv"])
    parser.add_argument("--seed",     action="store_true", help="Load built-in sample assets")
    parser.add_argument("--uri",      default="bolt://localhost:7687")
    parser.add_argument("--user",     default="neo4j")
    parser.add_argument("--password", default="password")
    args = parser.parse_args()

    loader = AssetLoader(args.uri, args.user, args.password)
    try:
        loader.ensure_constraints()
        if args.seed or not args.input:
            log.info("Loading sample asset data")
            result = loader.load_from_dicts(SAMPLE_ASSETS)
        elif args.format == "csv":
            result = loader.load_from_csv(args.input)
        else:
            result = loader.load_from_json(args.input)
        log.info(f"Asset load complete: {result}")
    finally:
        loader.close()


if __name__ == "__main__":
    main()
