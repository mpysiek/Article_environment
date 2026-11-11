# Tests

333 tests. Each file guards one part of the measurement; a failing test means a published
number could change meaning, not just that the code is untidy.

## Running

```bash
pytest tests -q -p no:cacheprovider
```

`-p no:cacheprovider` keeps `.pytest_cache` out of the working tree. The suite runs on CPU in
under a minute and makes no network calls except, on first use, the download of the two
Hugging Face models.

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
| `test_e2e_remediation.py` | 177 | contracts of the whole pipeline: targeting metadata, GraphRAG node namespaces and fallback, budget diversity, `query_echo`, assertion alignment, report synthesis, utility threshold, tie-breaking, latency, McNemar |
| `test_tie_logging_and_query_sets.py` | 32 | full score-tie groups, the hybrid candidate pool, query sets v2 and v3, per-template K4, the bridge threshold formula |
| `test_isolated_adversarial_stress.py` | 29 | zero foreign poison in all four retrievers and the evaluator invariants of isolated mode |
| `test_isolated_protocol.py` | 18 | per-query isolated index: no foreign payloads, budget sensitivity, clean-recall preservation |
| `test_m1_adversarial_stress.py` | 15 | targeted vs. untargeted poison attribution under edge cases (substring collisions, unicode, rank permutations, heavy background contamination) |
| `test_targeting_evaluation.py` | 12 | `poison_target_query` / `poison_type` on results, their propagation through all four retrievers, targeted metrics |
| `test_challenger_iso_2_adversarial.py` | 10 | clean recall under the isolated protocol, backward compatibility of shared mode, CLI flags |
| `test_comparison_system.py` | 10 | smoke tests of engines, attackers, evaluator, GraphRAG entity extraction and the report matrix on a small synthetic corpus |
| `test_data_integrity.py` | 9 | gold documents exist in the corpus; no invented records (needs `data/processed/`) |
| `test_embedding_cache.py` | 9 | the embedding cache key covers the model and every encoding setting, so one model never reads another's vectors |
| `test_optimization_adversarial_edge_cases.py` | 8 | the cached clean index plus per-query payload delta (BM25, GraphRAG) stays consistent under reordering, ID collisions and rebuilds |
| `test_corpus_manifest.py` | 4 | `data/corpus_manifest_v2_24000.csv.xz` matches the runs and `verify()` detects changes |

The names `challenger`, `m1` and `e2e_remediation` come from the development rounds in which
the tests were written; they do not mark a separate kind of test.
