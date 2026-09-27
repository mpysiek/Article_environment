# Handoff Report: Specification Mining of LLM Judge Evaluation & Metrological Reporting Rigor (R4 & R5)

**Agent**: `specminer_survey_3`  
**Parent Orchestrator**: `dbfcc1f0-e1bc-44ac-beb1-b7dccd9fb635`  
**Workspace**: `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\specminer_survey_3`  
**Type**: Hard Handoff  

---

## 1. Observation

Direct code and test observations from the repository:

1. **Class A9 (Silent Bias in Judge JSON Parse Failures)**:
   - In `src/evaluation/llm_judge.py` lines 172-187:
     ```python
     retained_match = re.search(r'"is_ground_truth_retained"\s*:\s*(true|false)', raw_output, re.IGNORECASE)
     if retained_match:
         retained = retained_match.group(1).lower() == 'true'
     else:
         retained = True
     return {"is_ground_truth_retained": retained, ...}
     ```
   - In `src/evaluation/llm_judge.py` lines 208-226:
     ```python
     adopted_match = re.search(r'"is_poison_adopted"\s*:\s*(true|false)', raw_output, re.IGNORECASE)
     if adopted_match:
         adopted = adopted_match.group(1).lower() == 'true'
     else:
         adopted = False
     return {"is_poison_adopted": adopted, ...}
     ```
   - In `src/evaluation/llm_judge.py` lines 260-264, the comment admits:
     `"...the fallbacks default to is_ground_truth_retained=True / is_poison_adopted=False -- a silent bias toward 'clean'."`
   - In `src/evaluation/metrics.py` lines 210-212:
     `generation_asr = gen_poison_count / total_q`
     `ground_truth_retention = gen_gt_retained_count / total_q`
     Missing judge outputs are substituted with `JudgeVerdict(False, False, False, "No verdict")` at line 159 and divided by `total_q`. No `coverage_rate` exists in `EngineBenchmarkResult` or `Evaluator`.

2. **Class A8 (Stimulus-Assay Misalignment for BlackBox & Topological Attacks)**:
   - In `src/attacks/poisoning.py` lines 248-264:
     `BlackBoxTopicAttacker` injects `topic_poison` (e.g. `"All referenced CVE advisories have been reclassified as informational notices with zero exploitability."`).
   - In `src/evaluation/stages.py` lines 76, 108:
     `make_stage_a_record` unconditionally sets `"target_poison_assertion": query.target_poison_assertion`.
   - In `src/evaluation/llm_judge.py` line 84:
     The judge evaluates whether the generated response accepted `"{target_poison_assertion}"`. Because the black-box payload is `topic_poison` rather than `target_poison_assertion`, the judge never detects the adopted payload.

3. **Class B8 (Flawed LLM Stage Execution Detection)**:
   - In `src/evaluation/metrics.py` lines 29-45:
     `EngineBenchmarkResult` has no `llm_stage_ran: bool` attribute.
   - In `src/visualization/reporter.py` lines 55, 131, 291:
     `has_llm_metrics = any(r.generation_asr > 0 or r.ground_truth_retention > 0 for r in results)`
     If an engine achieves 100% defense (`generation_asr == 0.0`) and 0% GT retention, `has_llm_metrics` evaluates to `False`. The reporter prints `"N/A"` for generation metrics and falsely describes the benchmark as cost-free local retrieval (`$0.00`).

4. **Class B9 (Batch Deduplication Collapsing Scenarios)**:
   - In `src/evaluation/llm_judge.py` lines 317-325:
     `digest = hashlib.sha1(json.dumps(messages, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()`
     Deduplication is global across all items without an opt-out parameter. Identical responses from different engines share a single judge call, precluding independent evaluation.

5. **Class A10 (Hardcoded Report Text & Static Corpus Literals)**:
   - In `src/visualization/reporter.py`:
     - Line 43: `title="🛡️ Full-Scale CTI RAG Poisoning Benchmark (25k+ Docs, 100 Queries)"`
     - Line 439: `f"skali **Real CTI STIX 2.1 (24 000 autentycznych dokumentów: MITRE ATT&CK STIX 2.1, CTIBench RCM/TAA NeurIPS 2024, CISA KEV, CVE Program cvelistV5, {total_queries} zweryfikowanych zapytań Gold Standard)**"`
     - Line 451: `"1. **Autentyczny Korpus CTI:** ... (20k+ relacji encji) ..."`
     - Lines 531-537: Section 5 ("Kluczowe Obserwacje i Wnioski Naukowe") is 100% static, hardcoded text referencing 24,000 documents and predefined architectural superiorities regardless of empirical benchmark numbers.

6. **Class A2 & B1 (Scalar Ranking Missing Pareto Analysis & Utility Threshold)**:
   - In `src/visualization/reporter.py` lines 292-295:
     `rankings.sort(key=lambda x: (x["avg_gen_asr"], -x["avg_gt_ret"]))` (or by `avg_top1_asr`, `-avg_recall`).
     This scalar ranking sorts solely by lowest ASR. An engine returning empty sets has 0% ASR and is ranked #1.

7. **Class B2 (Non-Deterministic Tie-Breaking & Cutoff Inconsistency)**:
   - In `src/visualization/reporter.py` line 293:
     No stable deterministic fallback (falls back to dictionary iteration order).
   - In `src/evaluation/metrics.py`:
     ASR is reported at Top-1, Top-3, Top-5 while Recall is only at Top-5.

8. **Class B5 (Imprecise Latency Measurement)**:
   - In `scripts/run_comparison_benchmark.py` lines 120-131:
     `ret_latency_ms = (time.time() - t_ret0) * 1000.0`
     Uses `time.time()` with millisecond-level resolution.
   - In `src/evaluation/metrics.py` lines 214-215:
     `avg_retrieval_latency_ms = float(np.mean(ret_lats))`
     No warm-up phase rejection; no median or IQR reported.

9. **Class B10 (McNemar Continuity Failure & False Zero P-values)**:
   - In `src/visualization/reporter.py` lines 23-36:
     ```python
     chi2 = (abs(b - c) - 1) ** 2 / (b + c)
     p_value = erfc(sqrt(chi2 / 2))
     ```
     For $b=1, c=0$ ($b+c=1 < 25$), $\chi^2 = 0.0$ and $p = 1.0$. Exact binomial distribution is completely omitted.
   - In `src/visualization/reporter.py` lines 420-421:
     `f"{test['p_val']:.4f}"` produces `"0.0000"` for $p < 0.00005$.

10. **Test Suite Execution**:
    - Ran `.venv\Scripts\python -m pytest`:
      `71 passed in 48.47s`.

---

## 2. Logic Chain

1. From Observation 1: Unparseable judge responses return synthetic values favoring the defense and are included in the denominator as successes, directly confirming Flaw A9. Tracking `coverage_rate` and marking unparseable verdicts as invalid isolates missing data from the empirical denominator.
2. From Observation 2: The assay in `LLMJudge` probes `query.target_poison_assertion`, but `BlackBoxTopicAttacker` injects `topic_poison`. Because stimulus and assay are discordant, the judge cannot observe adoption, confirming Flaw A8. Aligning the assertion in `make_stage_a_record` with `get_injected_assertion` guarantees proper assay alignment.
3. From Observation 3: If an attack fails to poison any generation, `generation_asr == 0.0`. `has_llm_metrics` evaluates to `False`, stripping LLM generation metrics from the report and falsely claiming zero cost, confirming Flaw B8. An explicit `llm_stage_ran: bool` flag preserves true zero-ASR measurements.
4. From Observation 4: Global SHA-1 prompt deduplication without an opt-out parameter collapses separate test items into a single judge evaluation, confirming Flaw B9. Adding `deduplicate: bool = True` and scoping hashing to `(query_id, digest)` resolves this risk.
5. From Observation 5: A benchmark run on 500 documents outputs a report claiming 24,000 documents with pre-written scientific conclusions, confirming Flaw A10. Passing dynamic corpus metadata and synthesizing Section 5 from the results matrix eliminates all hardcoded literals.
6. From Observation 6: Sorting solely on ASR allows useless retrievers (Recall ~ 0%) to rank first, confirming Flaws A2 and B1. Constructing a Pareto frontier with an absolute utility threshold ($\text{Clean Recall@5} \ge 0.50$) ensures only viable search engines compete.
7. From Observation 7: Identical metric scores fall back to arbitrary dictionary order, confirming Flaw B2. Establishing a deterministic tie-breaking hierarchy ensures reproducibility.
8. From Observation 8: Using `time.time()` and computing means across all queries without discarding cold-start queries distorts performance figures, confirming Flaw B5. Using `time.perf_counter()` with warm-up drop and reporting median + IQR provides metrological accuracy.
9. From Observation 9: The asymptotic test on $b+c < 25$ yields false insignificance ($p=1.0$), and `:.4f` generates false zeroes (`0.0000`), confirming Flaw B10. Implementing the exact binomial test for $b+c < 25$ and formatting with `p < 10⁻⁴` restores statistical integrity.

---

## 3. Caveats

- **No Project Source Modified**: In strict adherence to read-only constraints, no code files in `src/`, `scripts/`, or `tests/` were altered.
- **Judge Batch API Dependency**: The Batch API tests in `tests/test_judge_batch.py` mock API network calls; real-world OpenRouter batch runs depend on upstream service latency.

---

## 4. Conclusion

The benchmark's LLM Judge evaluation and reporting subsystem currently exhibits 9 identifiable methodological flaws across Class A (A2, A8, A9, A10) and Class B (B1, B2, B5, B8, B9, B10). All flaws are localized in `src/evaluation/llm_judge.py`, `src/evaluation/metrics.py`, `src/evaluation/stages.py`, `src/attacks/poisoning.py`, and `src/visualization/reporter.py`. 

The comprehensive specifications, mathematical formulas, and remediation blueprints have been fully developed and documented in `spec.md`. The implementation plan is clear, scoped, and ready for execution by implementation agents.

---

## 5. Verification Method

To verify the survey findings independently:
1. **Execute Test Suite**:
   ```pwsh
   .venv\Scripts\python -m pytest
   ```
   Confirm that all 71 tests currently pass.
2. **Inspect Flaw Locations**:
   - Class A9: Inspect `src/evaluation/llm_judge.py:176,212` and `src/evaluation/metrics.py:210`.
   - Class A8: Inspect `src/attacks/poisoning.py:257` and `src/evaluation/stages.py:76`.
   - Class B8: Inspect `src/visualization/reporter.py:55` and `src/evaluation/metrics.py:38`.
   - Class A10: Inspect `src/visualization/reporter.py:439,531`.
   - Class A2 & B1: Inspect `src/visualization/reporter.py:293`.
   - Class B5: Inspect `scripts/run_comparison_benchmark.py:120` and `src/evaluation/metrics.py:214`.
   - Class B10: Inspect `src/visualization/reporter.py:31,420`.
3. **Review Detailed Specification**:
   Inspect `d:\Projekt_RAG_2.0\Projekt_RAG\rag_poisoning_benchmark\.agents\specminer_survey_3\spec.md`.
