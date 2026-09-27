import sys
import json
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.evaluation.metrics import EngineBenchmarkResult, GenerationTrace
from src.visualization.reporter import BenchmarkReporter
from src.config import config

def main():
    parser = argparse.ArgumentParser(description="Re-render the markdown report from stored JSON metrics.")
    parser.add_argument("--in-dir", type=str, default=None, help="Directory holding comparison_benchmark_results.json")
    parser.add_argument("--corpus-size", type=int, default=24000, help="Corpus size to state in the report header")
    parser.add_argument("--bridge-count", type=int, default=None,
                        help="bridge_count used by the run being re-rendered. Read from "
                             "run_manifest.json when present; this flag is the fallback for "
                             "archived runs that predate the manifest.")
    args = parser.parse_args()
    reports_dir = Path(args.in_dir) if args.in_dir else config.REPORTS_DIR
    corpus_size = args.corpus_size

    json_path = reports_dir / "comparison_benchmark_results.json"
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = []
    for d in data:
        traces_data = d.pop("traces", [])
        traces = [GenerationTrace(**t) for t in traces_data]
        res = EngineBenchmarkResult(**d, traces=traces)
        results.append(res)

    # These must describe the run being re-rendered, not a hardcoded guess. The previous
    # version passed query_echo=True for runs that were executed with echo disabled, which
    # would have mislabelled the methodology section of the regenerated report.
    isolated = any(getattr(r, "isolated_targets", False) for r in results)
    query_echo = any("_echo_" in r.attack_type.lower() for r in results)

    # The manifest records what the run actually used. Without it the report cannot state the
    # attack's free parameter or the corpus snapshot, both of which the limitations section
    # has to name.
    manifest_path = reports_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else None
    bridge_count = args.bridge_count
    if bridge_count is None and manifest:
        bridge_count = manifest.get("attack_bridge_count")

    report_path = reports_dir / "rag_poisoning_comparison_report.md"
    BenchmarkReporter.generate_markdown_report(
        results,
        report_path,
        corpus_type="real",
        corpus_size=corpus_size,
        isolated_targets=isolated,
        query_echo=query_echo,
        bridge_count=bridge_count,
        run_manifest=manifest
    )
    print(f"Report regenerated successfully at: {report_path}")

if __name__ == "__main__":
    main()
