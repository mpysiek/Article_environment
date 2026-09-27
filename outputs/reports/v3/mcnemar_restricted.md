# Restricted McNemar family (manuscript Table 9)

Family size: 43; tests without discordant pairs: 34; significant after Holm: 2.

| Engines | Strata (n) | Outcome | Vector | Budgets | A / B | (b, c) | Statistic | p (raw) | p (Holm) |
|---|---|---|---|---|---|---|---|---|---|
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | payload_at_rank1 | graph | 1, 2, 3 | 50 / 0 | (50, 0) | χ² = 48.02 | 4.22e-12 | 1.81e-10 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | payload_at_rank1 | graph | 1, 2, 3 | 50 / 0 | (50, 0) | χ² = 48.02 | 4.22e-12 | 1.81e-10 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | sparse | 3 | 5 / 13 | (4, 12) | |b-c| = 8 | 7.68e-02 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | sparse | 1 | 4 / 10 | (3, 9) | |b-c| = 6 | 1.46e-01 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | sparse | 2 | 4 / 9 | (4, 9) | |b-c| = 5 | 2.67e-01 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | payload_at_rank1 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | payload_at_rank1 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | payload_at_rank1 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | sparse | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | dense | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | hybrid | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | graph | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | blackbox | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | payload_at_rank1 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | payload_at_rank1 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | payload_at_rank1 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | sparse | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | dense | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | hybrid | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | graph | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | blackbox | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | dense | 1, 2 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | dense | 3 | 2 / 1 | (2, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | hybrid | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | graph | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | blackbox | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | sparse | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | dense | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | hybrid | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | graph | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | blackbox | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |

Excluded rank-1 comparisons (tie crossing): GraphRAG vs Hybrid-Reranker / blackbox; GraphRAG vs Hybrid-Reranker / dense; GraphRAG vs Hybrid-Reranker / hybrid; GraphRAG vs Hybrid-Reranker / sparse; GraphRAG vs Sparse-BM25 / blackbox; GraphRAG vs Sparse-BM25 / dense; GraphRAG vs Sparse-BM25 / hybrid; GraphRAG vs Sparse-BM25 / sparse
