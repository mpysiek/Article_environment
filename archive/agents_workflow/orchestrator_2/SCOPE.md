# Scope: Recommendation 3 — Isolated Evaluation Protocol ("1 Target Query per Index Instance")

## Architecture
The isolated evaluation protocol eliminates artificial context contamination and background saturation in CTI RAG poisoning benchmarks. In isolated mode:
- For each test query $Q_i$, the retrieval index contains the clean CTI corpus and EXCLUSIVELY the poison payloads targeted at $Q_i$ ($B \in \{1, 3, 5\}$).
- No foreign payloads targeting $Q_j$ ($j \ne i$) are present during the evaluation of $Q_i$.
- Invariant: $ASR_{\text{untargeted}} \equiv 0.0\%$, and $ASR_{\text{targeted}} \equiv ASR_{\text{any}}$.
- Data flow:
  1. Benchmark CLI (`scripts/run_comparison_benchmark.py` with `--isolated-targets`).
  2. Isolated retrieval execution (`src/evaluation/stages.py::execute_isolated_retrieval`).
  3. Metric collection with `isolated_targets=True` in `EngineBenchmarkResult` (`src/evaluation/metrics.py`).
  4. Reporting and Pareto analysis (`src/visualization/reporter.py`).
  5. Verification through unit, integration, and E2E regression tests (`tests/test_isolated_protocol.py`, `tests/test_isolated_adversarial_stress.py`, `tests/test_challenger_iso_2_adversarial.py`).

## Feature Inventory
| # | Feature | Description | Milestone | Source | Status |
|---|---------|-------------|-----------|--------|--------|
| 1 | F-ISO-01: CLI Flag & Benchmark Integration | Add `--isolated-targets` to `scripts/run_comparison_benchmark.py`, pass to benchmark runner, fix unescaped `% c` bug on line 252 | M1 | Survey Explorer 1 | DONE |
| 2 | F-ISO-02: Retrieval Index Isolation | Ensure per-query indexing with clean corpus + exclusively $Q_i$ payloads ($B \in \{1, 3, 5\}$), leveraging `execute_isolated_retrieval` | M1 | Survey Explorer 1 | DONE |
| 3 | F-ISO-03: Result Metadata & Metrics Tracking | Add `isolated_targets: bool = False` to `EngineBenchmarkResult` in `src/evaluation/metrics.py` | M1 | Survey Explorer 2 | DONE |
| 4 | F-ISO-04: Dynamic Reporter Protocol Awareness | Add dynamic description of isolated protocol, budget dynamics without background saturation, and Pareto status in `src/visualization/reporter.py` | M1 | Survey Explorer 2 | DONE |
| 5 | F-ISO-05: Zero-Hardcoding Reporter Fix | Remove static text literals in Section 5 of `reporter.py` and replace with 100% dynamic synthesis from evaluation results | M1 | Survey Explorer 2 | DONE |
| 6 | F-ISO-06: Dedicated Test Suite (R2) | Implement `tests/test_isolated_protocol.py` (20 tests covering zero foreign poison, budget scaling, clean recall preservation, backward compatibility) | M1 | Survey Explorer 3 | DONE |
| 7 | F-ISO-07: Full Suite Test Integrity (R3) | Verify 100% pass across all 389 tests (`pytest tests/`) without regressions | M1 | Survey Explorer 3 | DONE |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Recommendation 3 Implementation & Full Verification | `scripts/run_comparison_benchmark.py`, `src/evaluation/metrics.py`, `src/visualization/reporter.py`, `tests/test_isolated_protocol.py` | Survey complete | DONE |

## Interface Contracts
### Benchmark CLI ↔ Retrieval Stages
- `scripts/run_comparison_benchmark.py`:
  - Flag `--isolated-targets` (default: False, action: store_true).
  - When `--isolated-targets` is set, calls `execute_isolated_retrieval(engine=engine, clean_docs=clean_docs, poison_payloads=poison_payloads, queries=queries, top_k=config.TOP_K)` from `src/evaluation/stages.py`.
  - When `--isolated-targets` is not set, calls `execute_shared_retrieval`.

### Metrics ↔ Reporter
- `EngineBenchmarkResult`:
  - Attribute `isolated_targets: bool = False`.
  - Serialized to JSON traces and deserialized transparently.
- `BenchmarkReporter.generate_markdown_report`:
  - Parameter `isolated_targets: Optional[bool] = None`.
  - Auto-detects from `results[0].isolated_targets` if `None`.
  - Generates dynamic protocol sections, Pareto table (`VIABLE` vs `NON_VIABLE` with 50% threshold), and dynamic budget dynamics.

## Code Layout
- `scripts/run_comparison_benchmark.py`: CLI parsing, runner execution, result generation.
- `src/evaluation/metrics.py`: `EngineBenchmarkResult` dataclass.
- `src/visualization/reporter.py`: `BenchmarkReporter` markdown generation and Pareto ranking.
- `tests/test_isolated_protocol.py`: 20 unit/integration tests across 5 test classes.
- `tests/test_isolated_adversarial_stress.py`: 29 adversarial stress tests.
- `tests/test_challenger_iso_2_adversarial.py`: 12 backward compatibility and clean recall tests.
