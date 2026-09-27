# Restricted McNemar family (manuscript Table 9)

Family size: 43; tests without discordant pairs: 25; significant after Holm: 8.

| Engines | Strata (n) | Outcome | Vector | Budgets | A / B | (b, c) | Statistic | p (raw) | p (Holm) |
|---|---|---|---|---|---|---|---|---|---|
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | payload_at_rank1 | graph | 1, 2, 3 | 50 / 0 | (50, 0) | χ² = 48.02 | 4.22e-12 | 1.81e-10 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | dense | 1, 2 | 0 / 50 | (0, 50) | χ² = 48.02 | 4.22e-12 | 1.81e-10 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | hybrid | 1, 2, 3 | 0 / 50 | (0, 50) | χ² = 48.02 | 4.22e-12 | 1.81e-10 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | graph | 1, 2, 3 | 0 / 50 | (0, 50) | χ² = 48.02 | 4.22e-12 | 1.81e-10 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | sparse | 1 | 4 / 55 | (3, 54) | χ² = 43.86 | 3.53e-11 | 1.38e-09 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | sparse | 3 | 5 / 57 | (4, 56) | χ² = 43.35 | 4.58e-11 | 1.74e-09 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | dense | 3 | 2 / 50 | (2, 50) | χ² = 42.48 | 7.14e-11 | 2.64e-09 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | sparse | 2 | 4 / 53 | (4, 53) | χ² = 40.42 | 2.05e-10 | 7.37e-09 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | payload_at_rank1 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | payload_at_rank1 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | payload_at_rank1 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | sparse | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | dense | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | hybrid | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | graph | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | blackbox | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Hybrid-Reranker | cve_exact (50) | gt_displaced_at5 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | payload_at_rank1 | graph | 1, 2, 3 | 50 / 50 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | payload_at_rank1 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | payload_at_rank1 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | payload_at_rank1 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | sparse | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | dense | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | hybrid | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | graph | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | blackbox | 1, 2, 3 | 0 / 1 | (0, 1) | |b-c| = 1 | 1.00e+00 | 1.00e+00 |
| GraphRAG vs Sparse-BM25 | cve_exact (50) | gt_displaced_at5 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | blackbox | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | payload_at_rank1 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | sparse | 1, 2, 3 | 1 / 1 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | dense | 1, 2, 3 | 1 / 1 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | hybrid | 1, 2, 3 | 1 / 1 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | graph | 1, 2, 3 | 1 / 1 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | entity_swap | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | blackbox_category | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | blackbox | 1, 2, 3 | 1 / 1 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |
| Hybrid-Reranker vs Sparse-BM25 | cve_descriptive, cve_exact (100) | gt_displaced_at5 | pure_topological | 1, 2, 3 | 0 / 0 | (0, 0) | 0.00 | 1.00e+00 | 1.00e+00 |

Excluded rank-1 comparisons (tie crossing): GraphRAG vs Hybrid-Reranker / blackbox; GraphRAG vs Hybrid-Reranker / dense; GraphRAG vs Hybrid-Reranker / hybrid; GraphRAG vs Hybrid-Reranker / sparse; GraphRAG vs Sparse-BM25 / blackbox; GraphRAG vs Sparse-BM25 / dense; GraphRAG vs Sparse-BM25 / hybrid; GraphRAG vs Sparse-BM25 / sparse
