"""
Bootstrap Orchestrator
Single entry point that builds the complete layered knowledge graph
from scratch or performs incremental updates.

Modes:
  full      — constraints → threat ingest → assets → vulns → graph build
  assets    — reload asset inventory only, then rescore
  vulns     — refresh vulnerability intel only, then rescore
  score     — rescore flagged assets only (fastest, no data fetch)
  daily     — TAXII delta + vuln refresh + rescore

Usage:
  python bootstrap.py --mode full                     # first run
  python bootstrap.py --mode full --seed-assets       # with sample data
  python bootstrap.py --mode daily                    # scheduled daily
  python bootstrap.py --mode assets --input my.json   # reload assets
  python bootstrap.py --mode score                    # rescore only

Environment variables (override CLI defaults):
  NEO4J_URI       bolt://localhost:7687
  NEO4J_USER      neo4j
  NEO4J_PASSWORD  password
  NVD_API_KEY     (optional, increases NVD rate limit)
"""

import argparse
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from dataclasses import dataclass, field

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(module)s] %(message)s",
)


@dataclass
class BootstrapConfig:
    neo4j_uri:  str = ""
    neo4j_user: str = ""
    neo4j_password: str = ""
    nvd_api_key: str = ""

    def __post_init__(self):
        self.neo4j_uri      = self.neo4j_uri  or os.environ.get("NEO4J_URI",      "bolt://localhost:7687")
        self.neo4j_user     = self.neo4j_user or os.environ.get("NEO4J_USER",     "neo4j")
        self.neo4j_password = self.neo4j_password or os.environ.get("NEO4J_PASSWORD", "password")
        self.nvd_api_key    = self.nvd_api_key or os.environ.get("NVD_API_KEY",   "")

    @property
    def neo4j_kwargs(self) -> dict:
        return {
            "neo4j_uri": self.neo4j_uri,
            "user":      self.neo4j_user,
            "password":  self.neo4j_password,
        }


@dataclass
class RunSummary:
    mode:     str
    started:  str = ""
    finished: str = ""
    duration: float = 0.0
    steps:    dict  = field(default_factory=dict)
    errors:   list  = field(default_factory=list)

    def __post_init__(self):
        self.started = datetime.now(timezone.utc).isoformat()

    def complete(self):
        self.finished = datetime.now(timezone.utc).isoformat()

    def print_summary(self):
        status = "SUCCESS" if not self.errors else f"PARTIAL ({len(self.errors)} errors)"
        log.info("=" * 60)
        log.info(f"Bootstrap [{self.mode}] — {status}")
        log.info(f"  Started:  {self.started}")
        log.info(f"  Finished: {self.finished}")
        log.info(f"  Duration: {self.duration:.1f}s")
        for step, result in self.steps.items():
            log.info(f"  {step}: {result}")
        if self.errors:
            for e in self.errors:
                log.error(f"  ERROR: {e}")
        log.info("=" * 60)


# ── Step runners ───────────────────────────────────────────────────────────────

def run_threat_ingest_weekly(cfg: BootstrapConfig) -> dict:
    from stix_taxii_ingestion import IngestionPipeline, PipelineConfig
    pc = PipelineConfig(
        neo4j_uri=cfg.neo4j_uri,
        neo4j_user=cfg.neo4j_user,
        neo4j_password=cfg.neo4j_password,
    )
    pipeline = IngestionPipeline(pc)
    try:
        audit = pipeline.run_weekly_bulk()
        return {"nodes": audit.nodes_upserted, "edges": audit.edges_upserted,
                "errors": audit.errors}
    finally:
        pipeline.close()


def run_threat_ingest_daily(cfg: BootstrapConfig) -> dict:
    from stix_taxii_ingestion import IngestionPipeline, PipelineConfig
    pc = PipelineConfig(
        neo4j_uri=cfg.neo4j_uri,
        neo4j_user=cfg.neo4j_user,
        neo4j_password=cfg.neo4j_password,
    )
    pipeline = IngestionPipeline(pc)
    try:
        audit = pipeline.run_daily_delta()
        return {"nodes": audit.nodes_upserted, "edges": audit.edges_upserted,
                "errors": audit.errors}
    finally:
        pipeline.close()


def run_asset_load(cfg: BootstrapConfig, input_path: str = None,
                   fmt: str = "json", seed: bool = False) -> dict:
    from asset_loader import AssetLoader, SAMPLE_ASSETS
    loader = AssetLoader(**cfg.neo4j_kwargs)
    try:
        loader.ensure_constraints()
        if seed or not input_path:
            return loader.load_from_dicts(SAMPLE_ASSETS)
        elif fmt == "csv":
            return loader.load_from_csv(input_path)
        else:
            return loader.load_from_json(input_path)
    finally:
        loader.close()


def run_vuln_load(cfg: BootstrapConfig, input_path: str = None,
                  days_back: int = 365) -> dict:
    from vuln_loader import VulnLoader
    loader = VulnLoader(
        neo4j_uri=cfg.neo4j_uri,
        user=cfg.neo4j_user,
        password=cfg.neo4j_password,
        nvd_api_key=cfg.nvd_api_key,
    )
    try:
        if input_path:
            return loader.load_from_json(input_path)
        else:
            return loader.fetch_and_ingest_ml_vulns(days_back=days_back)
    finally:
        loader.close()


def run_graph_build(cfg: BootstrapConfig, force_rescore: bool = False) -> dict:
    from graph_builder import GraphBuilder
    builder = GraphBuilder(**cfg.neo4j_kwargs)
    try:
        return builder.build(force_rescore=force_rescore)
    finally:
        builder.close()


# ── Mode orchestrators ─────────────────────────────────────────────────────────

def mode_full(cfg: BootstrapConfig, args) -> RunSummary:
    """
    Complete build from scratch. Runs threat ingest and asset/vuln load
    concurrently (they write to independent node types), then graph builder.
    """
    summary = RunSummary(mode="full")
    t0 = time.monotonic()

    log.info("Mode: full — building layered knowledge graph from scratch")

    # Phase 1: threat framework + asset domain run concurrently
    log.info("Phase 1: concurrent threat ingest + asset load")
    with ThreadPoolExecutor(max_workers=2) as pool:
        future_threat = pool.submit(run_threat_ingest_weekly, cfg)
        future_asset  = pool.submit(
            run_asset_load, cfg,
            getattr(args, "asset_input", None),
            getattr(args, "asset_format", "json"),
            getattr(args, "seed_assets", False),
        )
        for fut, name in [(future_threat, "threat_ingest"), (future_asset, "asset_load")]:
            try:
                summary.steps[name] = fut.result()
            except Exception as e:
                summary.errors.append(f"{name}: {e}")
                log.exception(f"Phase 1 step {name} failed")

    # Phase 2: vulnerability load (needs asset nodes to exist)
    log.info("Phase 2: vulnerability load")
    try:
        summary.steps["vuln_load"] = run_vuln_load(
            cfg,
            input_path = getattr(args, "vuln_input", None),
            days_back  = getattr(args, "vuln_days", 365),
        )
    except Exception as e:
        summary.errors.append(f"vuln_load: {e}")
        log.exception("Phase 2 vuln_load failed")

    # Phase 3: graph builder — cross-domain edges + scoring
    log.info("Phase 3: graph build + scoring")
    try:
        summary.steps["graph_build"] = run_graph_build(cfg, force_rescore=True)
    except Exception as e:
        summary.errors.append(f"graph_build: {e}")
        log.exception("Phase 3 graph_build failed")

    summary.duration = time.monotonic() - t0
    summary.complete()
    return summary


def mode_daily(cfg: BootstrapConfig, args) -> RunSummary:
    """
    Incremental daily update: TAXII delta + vuln refresh + rescore flagged assets.
    """
    summary = RunSummary(mode="daily")
    t0 = time.monotonic()

    log.info("Mode: daily — incremental update")

    with ThreadPoolExecutor(max_workers=2) as pool:
        future_threat = pool.submit(run_threat_ingest_daily, cfg)
        future_vuln   = pool.submit(run_vuln_load, cfg,
                                    getattr(args, "vuln_input", None), 30)
        for fut, name in [(future_threat, "taxii_delta"), (future_vuln, "vuln_refresh")]:
            try:
                summary.steps[name] = fut.result()
            except Exception as e:
                summary.errors.append(f"{name}: {e}")

    try:
        summary.steps["graph_build"] = run_graph_build(cfg, force_rescore=False)
    except Exception as e:
        summary.errors.append(f"graph_build: {e}")

    summary.duration = time.monotonic() - t0
    summary.complete()
    return summary


def mode_assets(cfg: BootstrapConfig, args) -> RunSummary:
    summary = RunSummary(mode="assets")
    t0 = time.monotonic()
    try:
        summary.steps["asset_load"] = run_asset_load(
            cfg,
            getattr(args, "asset_input", None),
            getattr(args, "asset_format", "json"),
            getattr(args, "seed_assets", False),
        )
        summary.steps["graph_build"] = run_graph_build(cfg, force_rescore=False)
    except Exception as e:
        summary.errors.append(str(e))
    summary.duration = time.monotonic() - t0
    summary.complete()
    return summary


def mode_vulns(cfg: BootstrapConfig, args) -> RunSummary:
    summary = RunSummary(mode="vulns")
    t0 = time.monotonic()
    try:
        summary.steps["vuln_load"] = run_vuln_load(
            cfg,
            getattr(args, "vuln_input", None),
            getattr(args, "vuln_days", 365),
        )
        summary.steps["graph_build"] = run_graph_build(cfg, force_rescore=False)
    except Exception as e:
        summary.errors.append(str(e))
    summary.duration = time.monotonic() - t0
    summary.complete()
    return summary


def mode_score(cfg: BootstrapConfig, args) -> RunSummary:
    summary = RunSummary(mode="score")
    t0 = time.monotonic()
    try:
        from graph_builder import GraphBuilder
        builder = GraphBuilder(**cfg.neo4j_kwargs)
        force = getattr(args, "force_rescore", False)
        try:
            summary.steps["scoring"] = builder.score_assets(force_all=force)
        finally:
            builder.close()
    except Exception as e:
        summary.errors.append(str(e))
    summary.duration = time.monotonic() - t0
    summary.complete()
    return summary


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AI Risk Knowledge Graph Bootstrap Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--mode", default="full",
                        choices=["full", "daily", "assets", "vulns", "score"],
                        help="Bootstrap mode (default: full)")

    # Asset options
    parser.add_argument("--asset-input",  default=None, help="Path to asset JSON/CSV")
    parser.add_argument("--asset-format", default="json", choices=["json", "csv"])
    parser.add_argument("--seed-assets",  action="store_true",
                        help="Load built-in sample assets if no input provided")

    # Vuln options
    parser.add_argument("--vuln-input",  default=None, help="Path to local NVD JSON export")
    parser.add_argument("--vuln-days",   type=int, default=365,
                        help="Days back to query NVD (default 365)")

    # Scoring options
    parser.add_argument("--force-rescore", action="store_true",
                        help="Rescore all assets regardless of rescore_needed flag")

    # Neo4j / API
    parser.add_argument("--uri",      default="", help="Neo4j bolt URI")
    parser.add_argument("--user",     default="", help="Neo4j username")
    parser.add_argument("--password", default="", help="Neo4j password")
    parser.add_argument("--nvd-key",  default="", help="NVD API key")

    args = parser.parse_args()

    cfg = BootstrapConfig(
        neo4j_uri      = args.uri,
        neo4j_user     = args.user,
        neo4j_password = args.password,
        nvd_api_key    = args.nvd_key,
    )

    MODE_MAP = {
        "full":   mode_full,
        "daily":  mode_daily,
        "assets": mode_assets,
        "vulns":  mode_vulns,
        "score":  mode_score,
    }

    summary = MODE_MAP[args.mode](cfg, args)
    summary.print_summary()
    sys.exit(1 if summary.errors else 0)


if __name__ == "__main__":
    main()
