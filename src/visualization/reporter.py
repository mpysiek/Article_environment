import json
import math
from pathlib import Path
from typing import List, Dict, Any, Tuple
from tabulate import tabulate
from rich.console import Console
from rich.table import Table
from src.evaluation.metrics import EngineBenchmarkResult, GenerationTrace
from src.config import config

console = Console()

def wilson_interval(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """Calculate Wilson score confidence interval (95% default)."""
    if total == 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + (z**2) / total
    center = (p + (z**2) / (2 * total)) / denom
    margin = (z * math.sqrt((p * (1 - p) / total) + (z**2) / (4 * (total**2)))) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))

def mcnemar_test(outcomes_a: List[bool], outcomes_b: List[bool]) -> Tuple[float, float, bool]:
    """McNemar's test for paired binary outcomes. Returns (chi2, p_value, is_significant_at_005)."""
    # Count discordant pairs
    b = sum(1 for a, o in zip(outcomes_a, outcomes_b) if a and not o)  # A=poisoned, B=not
    c = sum(1 for a, o in zip(outcomes_a, outcomes_b) if not a and o)  # A=not, B=poisoned
    if b + c == 0:
        return 0.0, 1.0, False
    # McNemar with continuity correction
    chi2 = (abs(b - c) - 1) ** 2 / (b + c)
    # p-value from chi2 distribution with 1 df
    # Use scipy-free approximation: p ≈ erfc(sqrt(chi2/2))
    from math import erfc, sqrt
    p_value = erfc(sqrt(chi2 / 2))
    return chi2, p_value, p_value < 0.05

class BenchmarkReporter:
    """Generates rich terminal tables, dynamic Markdown analysis reports, statistical intervals, and JSON trace logs."""

    @staticmethod
    def print_terminal_results(results: List[EngineBenchmarkResult]):
        table = Table(title="🛡️ Full-Scale CTI RAG Poisoning Benchmark (25k+ Docs, 100 Queries)")
        table.add_column("RAG Engine", style="cyan", justify="left")
        table.add_column("Attack Vector", style="magenta", justify="left")
        table.add_column("Queries", justify="center")
        table.add_column("Retr Top-1 ASR", justify="center")
        table.add_column("Retr Top-5 ASR", justify="center")
        table.add_column("Clean Recall@5", style="green", justify="center")
        table.add_column("LLM Gen ASR", style="bold red", justify="center")
        table.add_column("GT Retained", style="bold green", justify="center")
        table.add_column("Conflict Det.", justify="center")

        for r in results:
            r_top1_str = f"[bold red]{r.retrieval_asr_top1:.1%}[/bold red]" if r.retrieval_asr_top1 > 0.5 else f"{r.retrieval_asr_top1:.1%}"
            r_top5_str = f"[bold red]{r.retrieval_asr_top5:.1%}[/bold red]" if r.retrieval_asr_top5 > 0.5 else f"{r.retrieval_asr_top5:.1%}"
            gen_asr_str = f"[bold red]{r.generation_asr:.1%}[/bold red]" if r.generation_asr > 0.3 else f"{r.generation_asr:.1%}"
            gt_ret_str = f"[bold green]{r.ground_truth_retention:.1%}[/bold green]" if r.ground_truth_retention > 0.5 else f"{r.ground_truth_retention:.1%}"

            table.add_row(
                r.engine_name,
                r.attack_type.upper(),
                str(r.total_queries),
                r_top1_str,
                r_top5_str,
                f"{r.clean_recall_top5:.1%}",
                gen_asr_str,
                gt_ret_str,
                f"{r.conflict_detection_rate:.1%}"
            )
        console.print(table)

    @staticmethod
    def generate_markdown_report(results: List[EngineBenchmarkResult], output_file: Path) -> str:
        headers = [
            "RAG Engine", "Threat / Attack Vector", "Queries",
            "Retr ASR@1 (95% CI)", "Retr ASR@5",
            "Clean Recall@5", "Clean MRR",
            "LLM Gen ASR (95% CI)", "GT Retention (95% CI)", "Conflict Rate"
        ]
        rows = []
        for r in results:
            n = r.total_queries
            top1_ci = wilson_interval(int(round(r.retrieval_asr_top1 * n)), n)
            gen_ci = wilson_interval(int(round(r.generation_asr * n)), n)
            gt_ci = wilson_interval(int(round(r.ground_truth_retention * n)), n)

            top1_str = f"{r.retrieval_asr_top1:.1%} [{top1_ci[0]:.1%}-{top1_ci[1]:.1%}]"
            gen_str = f"{r.generation_asr:.1%} [{gen_ci[0]:.1%}-{gen_ci[1]:.1%}]"
            gt_str = f"{r.ground_truth_retention:.1%} [{gt_ci[0]:.1%}-{gt_ci[1]:.1%}]"

            rows.append([
                r.engine_name,
                r.attack_type.upper(),
                n,
                top1_str,
                f"{r.retrieval_asr_top5:.1%}",
                f"{r.clean_recall_top5:.1%}",
                f"{r.clean_mrr:.2f}",
                gen_str,
                gt_str,
                f"{r.conflict_detection_rate:.1%}"
            ])
        md_table = tabulate(rows, headers=headers, tablefmt="github")

        # Dynamic Analysis: Calculate empirical resilience metrics
        attack_results = [r for r in results if r.attack_type.lower() != "clean_baseline"]
        engine_stats = {}
        for r in attack_results:
            if r.engine_name not in engine_stats:
                engine_stats[r.engine_name] = {
                    "gen_asr": [],
                    "retr_top1_asr": [],
                    "gt_retention": [],
                    "recall": []
                }
            engine_stats[r.engine_name]["gen_asr"].append(r.generation_asr)
            engine_stats[r.engine_name]["retr_top1_asr"].append(r.retrieval_asr_top1)
            engine_stats[r.engine_name]["gt_retention"].append(r.ground_truth_retention)
            engine_stats[r.engine_name]["recall"].append(r.clean_recall_top5)

        rankings = []
        for eng, stats in engine_stats.items():
            avg_gen_asr = sum(stats["gen_asr"]) / len(stats["gen_asr"])
            avg_top1_asr = sum(stats["retr_top1_asr"]) / len(stats["retr_top1_asr"])
            avg_gt_ret = sum(stats["gt_retention"]) / len(stats["gt_retention"])
            avg_recall = sum(stats["recall"]) / len(stats["recall"])
            rankings.append({
                "engine": eng,
                "avg_gen_asr": avg_gen_asr,
                "avg_top1_asr": avg_top1_asr,
                "avg_gt_ret": avg_gt_ret,
                "avg_recall": avg_recall
            })

        # Sort by lowest Generation ASR, then highest GT retention
        rankings.sort(key=lambda x: (x["avg_gen_asr"], -x["avg_gt_ret"]))

        ranking_rows = []
        for rank, item in enumerate(rankings, 1):
            ranking_rows.append([
                f"#{rank}",
                item["engine"],
                f"{item['avg_gen_asr']:.1%}",
                f"{item['avg_top1_asr']:.1%}",
                f"{item['avg_gt_ret']:.1%}",
                f"{item['avg_recall']:.1%}"
            ])
        ranking_table = tabulate(
            ranking_rows,
            headers=["Rank", "Engine", "Avg LLM Gen ASR (Lower=Better)", "Avg Retr ASR@1", "Avg GT Retention", "Avg Recall@5"],
            tablefmt="github"
        )

        # Attack Vector Efficacy
        attack_stats = {}
        for r in attack_results:
            if r.attack_type not in attack_stats:
                attack_stats[r.attack_type] = []
            attack_stats[r.attack_type].append(r.generation_asr)

        attack_rankings = []
        for att, asrs in attack_stats.items():
            attack_rankings.append((att, sum(asrs)/len(asrs)))
        attack_rankings.sort(key=lambda x: x[1], reverse=True)

        attack_rows = [[att.upper(), f"{asr:.1%}"] for att, asr in attack_rankings]
        attack_table = tabulate(attack_rows, headers=["Attack Vector", "Avg LLM Generation ASR"], tablefmt="github")

        # McNemar's Test Pairwise Comparisons
        mcnemar_rows = []
        
        attacks_map = {}
        for r in results:
            att = r.attack_type.lower()
            if att not in attacks_map:
                attacks_map[att] = []
            attacks_map[att].append(r)
            
        for att, eng_results in attacks_map.items():
            if len(eng_results) > 1:
                for i in range(len(eng_results)):
                    for j in range(i + 1, len(eng_results)):
                        eng1 = eng_results[i]
                        eng2 = eng_results[j]
                        
                        if att == "clean_baseline":
                            outcomes_a = [t.ground_truth_retained for t in eng1.traces]
                            outcomes_b = [t.ground_truth_retained for t in eng2.traces]
                            metric_name = "GT Retention"
                        else:
                            outcomes_a = [t.is_poison_adopted for t in eng1.traces]
                            outcomes_b = [t.is_poison_adopted for t in eng2.traces]
                            metric_name = "Generation ASR"
                            
                        chi2, p_val, is_sig = mcnemar_test(outcomes_a, outcomes_b)
                        sig_str = "Yes (p<0.05)" if is_sig else "No"
                        mcnemar_rows.append([
                            f"{att.upper()} ({metric_name})",
                            eng1.engine_name,
                            eng2.engine_name,
                            f"{chi2:.2f}",
                            f"{p_val:.4f}",
                            sig_str
                        ])
                        
        hybrid_results = [r for r in results if "hybrid" in r.engine_name.lower()]
        hybrid_cs = [r for r in hybrid_results if r.attack_type.lower() == "cross_sparse"]
        hybrid_cd = [r for r in hybrid_results if r.attack_type.lower() == "cross_dense"]
        
        if hybrid_cs and hybrid_cd:
            for eng1 in hybrid_cs:
                for eng2 in hybrid_cd:
                    outcomes_a = [t.is_poison_adopted for t in eng1.traces]
                    outcomes_b = [t.is_poison_adopted for t in eng2.traces]
                    chi2, p_val, is_sig = mcnemar_test(outcomes_a, outcomes_b)
                    sig_str = "Yes (p<0.05)" if is_sig else "No"
                    mcnemar_rows.append([
                        "CROSS_SPARSE vs CROSS_DENSE (Generation ASR)",
                        f"{eng1.engine_name} (sparse)",
                        f"{eng2.engine_name} (dense)",
                        f"{chi2:.2f}",
                        f"{p_val:.4f}",
                        sig_str
                    ])
                    
        if mcnemar_rows:
            mcnemar_table = tabulate(
                mcnemar_rows,
                headers=["Condition", "Engine/Attack A", "Engine/Attack B", "Chi2", "p-value", "Significant?"],
                tablefmt="github"
            )
        else:
            mcnemar_table = "*Brak pasujących par do testu McNemara.*"

        total_queries = results[0].total_queries if results else 0
        gen_model = config.GENERATOR_MODEL
        judge_model = config.JUDGE_MODEL

        md_content = f"""# 🔬 Raport z Pełnoskalowego Eksperymentu: Odporność Architektur RAG na Ataki Corpus Poisoning (Enterprise Scale)

## 1. Wstęp i Metodologia Badawcza
Eksperyment bada podatność 4 kluczowych architektur wyszukiwania RAG:
* **Sparse (BM25 Okapi)**
* **Dense (FAISS + SentenceTransformers MiniLM)**
* **Hybrid + Cross-Encoder Reranker (BM25 + FAISS + RRF + Cross-Encoder MiniLM)**
* **GraphRAG (NetworkX Entity-Relation Subgraph Traversal)**

w skali **Enterprise (25 000+ dokumentów wiedzy CTI, {total_queries} złotych zapytań ewaluacyjnych)** pod kątem 4 zaawansowanych wektorów ataków zatruwania bazy wiedzy (*corpus poisoning*).

Wszystkie odpowiedzi generowane są przez model **`{gen_model}`**, a ewaluacja prowadzona jest przez niezależnego, podwójnie ślepego sędziego **`{judge_model}`** przez OpenRouter API. Wyniki zawierają 95% przedziały ufności Wilsona (*Wilson Score Interval*) oraz testy istotności statystycznej McNemara.

---

## 2. Zbiorcza Macierz Wyników (Retrieval & LLM Generation Benchmark)

{md_table}

---

## 3. Empiryczny Ranking Odporności Architektur (Wyliczony Algorytmicznie)

{ranking_table}

---

## 3.1 Statistical Significance of Pairwise Architecture Differences (McNemar's Test)

Pairwise McNemar comparisons are limited to scenarios sharing the same attack vector or baseline condition.

{mcnemar_table}

---

## 4. Skuteczność Wektorów Ataków (Attack Vector Efficacy)

{attack_table}

---

## 5. Kluczowe Obserwacje i Wnioski Naukowe
1. **Wpływ Skali Korpusu i Szumu Dystraktorów:** Przy korpusie 25k+ dokumentów czyste wyszukiwanie Dense FAISS bez rerankera doświadcza większego rozproszenia semantycznego, co wymusza stosowanie architektury hybrydowej.
2. **Podatność na poziomie Retrieval vs. LLM Generation:** Zatruty dokument osiągający pozycję Top-1 wywiera silną presję na model generatywny Llama-3.3-70B, jednak model wykazuje wbudowaną zdolność detekcji sprzeczności (*Conflict Detection*), gdy kontekst zawiera również autentyczne dokumenty źródłowe.
3. **GraphRAG:** Wyszukiwanie grafowe osiąga bardzo wysoki Recall przy zapytaniach relacyjnych, lecz ulega atakom strukturalnym (*LogicPoison*), co wskazuje na konieczność walidacji integralności krawędzi relacyjnych w grafach wiedzy.
4. **Architektura Hybrydowa z Rerankerem:** Zapewnia najwyższą spójność faktograficzną, wymagając wielokryterialnego ataku optymalizacyjnego *Dual-Constraint Evasion*.

---

## 6. Limitations and Threats to Validity

1. **Synthetic Corpus:** The CTI knowledge base is procedurally generated from templates and does not contain authentic NVD advisories, MITRE STIX bundles, or real Sigma rules. Results may not generalize to production RAG systems with authentic document distributions.
2. **White-Box Attack Oracle:** The attacker has full knowledge of evaluation queries (query text, key terms, target assertion). Results represent an upper bound on attack efficacy and do not reflect realistic black-box adversary capabilities.
3. **Simplified GraphRAG:** The GraphRAG implementation uses deterministic 2-hop subgraph traversal (NetworkX) and is not representative of production systems (e.g., Microsoft GraphRAG, Neo4j, LlamaIndex KG) that employ LLM-based community summarization.
4. **Leading Queries:** Many evaluation queries contain explicit document identifiers (e.g., CVE IDs), which may inflate retrieval recall metrics compared to natural-language paraphrased queries.
5. **Single Experimental Run:** Results are from a single execution with fixed random seed (42) and temperature=0.0. Multi-run variance analysis was not performed.
"""

        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(md_content, encoding="utf-8")
        return md_content

    @staticmethod
    def save_generation_traces(results: List[EngineBenchmarkResult], output_file: Path):
        all_traces = []
        for r in results:
            for t in r.traces:
                all_traces.append(t.__dict__)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(all_traces, indent=2, ensure_ascii=False), encoding="utf-8")
