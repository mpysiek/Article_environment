# Tests

433 tests. Each file guards one part of the measurement; a failing test means a published
number could change meaning, not just that the code is untidy.

## Running

```bash
pytest tests -q -p no:cacheprovider
```

`-p no:cacheprovider` keeps `.pytest_cache` out of the working tree. The suite runs on CPU in
about 1–2 minutes and makes no network calls to paid APIs: LLM clients are tested against
mocks.

`test_data_integrity.py` checks the assembled 24,000-document corpus, which is not stored in
the repository (see [`data/README.md`](../data/README.md)). Without it, run the rest:

```bash
pytest tests -q -p no:cacheprovider --ignore=tests/test_data_integrity.py
```

GitHub Actions does exactly that on every push to `main` and every pull request, then runs the
methodological audit gate (`scripts/audit_checks.py`) on run v3.

## What each file covers

| File | Tests | Guards |
| :--- | ---: | :--- |
| `test_e2e_remediation.py` | 225 | contracts of the whole pipeline: targeting metadata, GraphRAG node namespaces and fallback, budget diversity, `query_echo`, `llm_stage_ran`, report synthesis, utility threshold, tie-breaking, latency, McNemar |
| `test_tie_logging_and_query_sets.py` | 32 | full score-tie groups, the hybrid candidate pool, query sets v2 and v3, per-template K4, the bridge threshold formula |
| `test_isolated_adversarial_stress.py` | 29 | zero foreign poison in all four retrievers and the evaluator invariants of isolated mode |
| `test_isolated_protocol.py` | 20 | per-query isolated index: no foreign payloads, budget sensitivity, clean-recall preservation |
| `test_m1_adversarial_stress.py` | 18 | targeted vs. untargeted poison attribution under edge cases (substring collisions, unicode, rank permutations, heavy background contamination) |
| `test_batch_client.py` | 15 | wire format and failure handling of the OpenRouter Batch API client (optional LLM stage) |
| `test_targeting_evaluation.py` | 14 | `poison_target_query` / `poison_type` on results, their propagation and serialisation, targeted metrics |
| `test_challenger_iso_2_adversarial.py` | 12 | clean recall under the isolated protocol, backward compatibility of shared mode, CLI flags |
| `test_stages.py` | 12 | stage A → C round trip: every field the evaluator reads survives serialisation |
| `test_comparison_system.py` | 11 | smoke tests of engines, attackers, evaluator, GraphRAG entity extraction and the report matrix on a small synthetic corpus |
| `test_judge_batch.py` | 11 | the LLM judge's batch mode gives the same prompts and verdicts as the single-call mode |
| `test_data_integrity.py` | 9 | gold documents exist in the corpus; no invented records (needs `data/processed/`) |
| `test_embedding_cache.py` | 9 | the embedding cache key covers the model and every encoding setting, so one model never reads another's vectors |
| `test_optimization_adversarial_edge_cases.py` | 8 | the cached clean index plus per-query payload delta (BM25, GraphRAG) stays consistent under reordering, ID collisions and rebuilds |
| `test_corpus_manifest.py` | 4 | `data/corpus_manifest_v2_24000.csv.xz` matches the runs and `verify()` detects changes |
| `test_defenses.py` | 4 | input sanitisers (not enabled in the reported runs) |

The names `challenger`, `m1` and `e2e_remediation` come from the development rounds in which
the tests were written; they do not mark a separate kind of test.
