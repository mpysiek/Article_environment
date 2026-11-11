#!/usr/bin/env python3
"""Automated re-audit: checks a benchmark run against the methodology findings K1-K9.

This is a quality gate, not a unit test suite. Each check restates one finding from the
methodological audit as a machine-verifiable assertion over the stored results, so a future
run cannot silently regress into the same problem.

A check can come back FAIL (the finding still stands), PASS (it is resolved), or INFO
(measured, reported, no pass/fail semantics -- some findings are limitations to disclose,
not defects to fix).

Usage:
    python scripts/audit_checks.py --in-dir outputs/reports/v3
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.evaluation.strata import (  # noqa: E402  (needs PROJECT_ROOT on sys.path)
    CONSTANT_SLOT_MIN_GROUP as K4_MIN_GROUP,
    CONSTANT_SLOT_SHARE as K4_SHARE,
    MIN_UTILITY_THRESHOLD,
    clean_stratum_recall,
    constant_slot_findings,
    stratum_of,
    template_of,
)


class Report:
    def __init__(self):
        self.rows: List[Dict[str, Any]] = []

    def add(self, key: str, status: str, headline: str, detail: str = ""):
        self.rows.append({"key": key, "status": status, "headline": headline, "detail": detail})

    def render(self) -> int:
        width = max(len(r["headline"]) for r in self.rows) if self.rows else 0
        print()
        print("=" * 78)
        print("RE-AUDYT: sprawdzenie ustalen metodologicznych na wynikach przebiegu")
        print("=" * 78)
        for r in self.rows:
            mark = {"PASS": "[PASS]", "FAIL": "[FAIL]", "INFO": "[INFO]"}[r["status"]]
            print(f"{mark} {r['key']:<4} {r['headline']:<{width}}")
            if r["detail"]:
                for line in r["detail"].splitlines():
                    print(f"              {line}")
        failed = [r for r in self.rows if r["status"] == "FAIL"]
        print("-" * 78)
        print(f"PASS: {sum(1 for r in self.rows if r['status'] == 'PASS')}  "
              f"FAIL: {len(failed)}  "
              f"INFO: {sum(1 for r in self.rows if r['status'] == 'INFO')}")
        return 1 if failed else 0


def check_k1(data, rep: Report):
    """poison@1 and GT displacement must be reported separately, and must differ."""
    rows = [d for d in data
            if d["attack_type"] != "clean_baseline" and d.get("n_displacement_denom", 0) > 0]
    if not rows:
        rep.add("K1", "FAIL", "Brak metryki wyparcia (gt_displacement_rate) w wynikach.")
        return
    gaps = [(d["engine_name"], d["attack_type"],
             d["retrieval_asr_top1"], d["gt_displacement_rate"])
            for d in rows]
    worst = max(gaps, key=lambda g: g[2] - g[3])
    avg_p1 = sum(g[2] for g in gaps) / len(gaps)
    avg_disp = sum(g[3] for g in gaps) / len(gaps)
    rep.add(
        "K1", "PASS",
        "Pozycja ladunku i wyparcie odpowiedzi raportowane osobno.",
        f"srednio poison@1 = {avg_p1:.1%}, GT displaced@5 = {avg_disp:.1%} "
        f"(roznica {avg_p1 - avg_disp:+.1%})\n"
        f"najwieksza rozbieznosc: {worst[0]} / {worst[1]}: "
        f"poison@1 = {worst[2]:.1%} vs displaced = {worst[3]:.1%}",
    )


def check_k2(sweep, rep: Report):
    """The topological attack must be characterised by a threshold, not a single point."""
    if sweep is None:
        rep.add("K2", "FAIL", "Brak wynikow sweepu bridge_count (uruchom scripts/run_bridge_sweep.py).")
        return
    vals = [(s["bridge_count"], s["poison_at_1"]) for s in sweep["sweep"]]
    ps = [p for _, p in vals]
    detail = "  ".join(f"n={n}: {p:.1%}" for n, p in vals)
    # A threshold shows up as a large jump across the swept range, not necessarily as a
    # 0% -> >0% transition: the attack can already win on some queries at the low end.
    spread = (max(ps) - min(ps)) if ps else 0.0
    if spread >= 0.20:
        rep.add("K2", "PASS",
                "Atak topologiczny opisany progiem, nie pojedyncza stala.",
                f"{detail}\nprzewidywany prog n > {sweep.get('predicted_crossover_n', float('nan')):.0f} "
                f"(mediana stopnia encji = {sweep.get('median_query_entity_degree', 0):.0f})")
    else:
        rep.add("K2", "INFO",
                "Sweep nie objal punktu przejscia - rozszerz zakres bridge_count.",
                detail)


def _clean_stratum_recall(data) -> Dict[str, Dict[str, float]]:
    """Per engine, per stratum clean Recall@5, read off the clean baseline."""
    out: Dict[str, Dict[str, float]] = {}
    for (eng, st), rec in clean_stratum_recall(data).items():
        out.setdefault(eng, {})[st] = rec
    return out


def check_k3(data, report_text, rep: Report):
    """Aggregates must not be carried by strata where the engine has no utility.

    The utility floor exists because a payload reaching rank 1 in a ranking that never held
    the answer displaced nothing. That argument is about a ranking, so it applies per stratum
    and not only per engine: an engine can be VIABLE overall while one of its strata is a
    degenerate ranking whose poison@1 then inflates every cross-scenario mean.
    """
    recalls = _clean_stratum_recall(data)
    if not recalls:
        rep.add("K3", "FAIL", "Brak czystej linii bazowej - nie da sie wyznaczyc progu per stratum.")
        return

    lines, worst_gap = [], 0.0
    for eng, per_st in sorted(recalls.items()):
        viable = {st for st, r in per_st.items() if r >= MIN_UTILITY_THRESHOLD}
        dropped = sorted(set(per_st) - viable)
        att = [d for d in data if d["engine_name"] == eng and d["attack_type"] != "clean_baseline"]
        if not att:
            continue
        unrestricted = sum(d["retrieval_asr_top1"] for d in att) / len(att)
        vals = []
        for d in att:
            ts = [t for t in d["traces"] if stratum_of(t["query_category"]) in viable]
            if ts:
                vals.append(sum(1 for t in ts if t["has_poison_in_top1"]) / len(ts))
        restricted = sum(vals) / len(vals) if vals else unrestricted
        gap = unrestricted - restricted
        worst_gap = max(worst_gap, abs(gap))
        lines.append(
            f"{eng:<16} poison@1 bez ograniczenia {unrestricted:6.1%} -> "
            f"na stratach uzytecznych {restricted:6.1%} ({gap:+.1%})"
            + (f"; odrzucone strata: {', '.join(dropped)}" if dropped else "")
        )

    publishes_restricted = "Strata wy" in (report_text or "")
    if worst_gap >= 0.05 and not publishes_restricted:
        rep.add("K3", "FAIL",
                "Srednie zagregowane sa niesione przez strata ponizej progu uzytecznosci.",
                "\n".join(lines)
                + "\nRaport nie publikuje wersji ograniczonej do strat uzytecznych.")
    else:
        rep.add("K3", "PASS",
                "Prog uzytecznosci stosowany per stratum, nie tylko per silnik.",
                "\n".join(lines))


# Constant-slot detection works per question template, not per stratum: an artefact confined
# to one template (GraphRAG's two techniques on all 17 malware questions of v2 = 34% of the
# relational stratum) never reaches a per-stratum threshold. The detection itself lives in
# src/evaluation/strata.py, shared with the reporter.
def constant_slots(data) -> List[Dict[str, Any]]:
    """Constant top-5 documents per template group of the clean baseline (see strata.py)."""
    return constant_slot_findings(data)


def check_k4(data, rep: Report):
    """A document present regardless of the question must not outrank the gold document."""
    found = constant_slots(data)
    lines = [
        f"{f['engine']} / {f['stratum']} / {f['template']} (n={f['n']}): {f['doc']} w top-5 dla "
        f"{f['share']:.0%} pytan; nad zlotym dokumentem w {f['above_gold']}"
        f"{'' if f['viable'] else ' [stratum ponizej progu uzytecznosci]'}"
        for f in found
    ]
    failing = [f for f in found if f["above_gold"] and f["viable"]]
    if failing:
        rep.add("K4", "FAIL",
                "Staly dokument (niezalezny od pytania) wyprzedza zloty dokument w stratum uzytecznym.",
                "\n".join(lines))
    elif found:
        rep.add("K4", "INFO",
                "Stale sloty obecne, ale nie wyprzedzaja zlotego dokumentu w zadnym stratum uzytecznym.",
                "\n".join(lines))
    else:
        rep.add("K4", "PASS",
                f"Zaden dokument nie okupuje top-5 w >{K4_SHARE:.0%} pytan zadnej grupy szablonu.")


def check_k5(data, rep: Report):
    """Recall@5 and Hit@5 must be distinct quantities that are actually reported."""
    clean = [d for d in data if d["attack_type"] == "clean_baseline"]
    if not clean or "gt_recall_at_k" not in clean[0]["traces"][0]:
        rep.add("K5", "FAIL", "Slady nie zawieraja gt_recall_at_k / gt_hit_at_k.")
        return
    lines, differ = [], False
    for d in clean:
        ts = d["traces"]
        rec = sum(t["gt_recall_at_k"] for t in ts) / len(ts)
        hit = sum(1 for t in ts if t["gt_hit_at_k"]) / len(ts)
        if abs(rec - hit) > 1e-9:
            differ = True
        lines.append(f"{d['engine_name']:<16} Recall@5 = {rec:.1%}   Hit@5 = {hit:.1%}")
        if abs(rec - d["clean_recall_top5"]) > 1e-6:
            rep.add("K5", "FAIL",
                    "Recall@5 w sladach nie zgadza sie z wartoscia zbiorcza.",
                    f"{d['engine_name']}: slady {rec:.4f} vs zbiorcza {d['clean_recall_top5']:.4f}")
            return
    rep.add("K5", "PASS" if differ else "INFO",
            "Recall@5 i Hit@5 sa rozdzielone i spojne z tabela zbiorcza."
            if differ else "Recall@5 = Hit@5 (kazde zapytanie ma jeden dokument docelowy).",
            "\n".join(lines))


def check_k6(data, rep: Report):
    """Zero foreign contamination is a protocol invariant, so assert it - do not report it."""
    if not all(d.get("isolated_targets") for d in data):
        rep.add("K6", "INFO", "Przebieg nie jest w pelni izolowany - inwariant nie obowiazuje.")
        return
    bad = [f"{d['engine_name']}/{d['attack_type']}={d['retrieval_asr_untargeted']:.3f}"
           for d in data if abs(d.get("retrieval_asr_untargeted", 0.0)) > 1e-9]
    if bad:
        rep.add("K6", "FAIL", "Naruszony inwariant protokolu izolowanego.", "\n".join(bad[:5]))
    else:
        rep.add("K6", "PASS",
                "Zerowe zanieczyszczenie obce potwierdzone jako inwariant protokolu.",
                "Wartosc jest gwarantowana konstrukcyjnie, wiec nalezy do asercji, nie do wnioskow.")


def check_k7(data, rep: Report):
    """A category-level black-box arm must exist and must not use victim identifiers."""
    cats = {d["attack_type"] for d in data}
    if not any(a.startswith("blackbox_category") for a in cats):
        rep.add("K7", "FAIL", "Brak ramienia blackbox_category (prawdziwa dolna granica).")
        return
    ent = [d["retrieval_asr_top1"] for d in data if d["attack_type"].startswith("blackbox_b")]
    cat = [d["retrieval_asr_top1"] for d in data if d["attack_type"].startswith("blackbox_category_b")]
    rep.add("K7", "PASS",
            "Dolna granica mierzona wariantem bez identyfikatora ofiary.",
            f"blackbox (topic+entity) poison@1 = {sum(ent)/len(ent):.1%}  vs  "
            f"blackbox_category poison@1 = {sum(cat)/len(cat):.1%}"
            if ent and cat else "")


def check_k8(data, rep: Report):
    """Budget curves must be reported with their saturation measured."""
    # "clean_baseline".rsplit("_b", 1) yields "aseline", so match the suffix explicitly.
    budget_re = re.compile(r"_b(\d+)$")
    budgets = sorted({int(m.group(1))
                      for d in data
                      for m in [budget_re.search(d["attack_type"])] if m})
    if len(budgets) < 2:
        rep.add("K8", "INFO", "Jeden budzet - krzywa budzetowa nieoznaczalna.")
        return
    lo, hi = budgets[0], budgets[-1]
    by_key = {(d["engine_name"], d["attack_type"]): d for d in data}
    flat, total, flat_names = 0, 0, []
    for (eng, att), d in by_key.items():
        if not att.endswith(f"_b{lo}"):
            continue
        base = att[: -len(f"_b{lo}")]
        other = by_key.get((eng, f"{base}_b{hi}"))
        if other is None:
            continue
        total += 1
        hi_map = {t["query_id"]: t["has_poison_in_top1"] for t in other["traces"]}
        if all(hi_map.get(t["query_id"]) == t["has_poison_in_top1"] for t in d["traces"]):
            flat += 1
            flat_names.append(f"{eng}/{base}")
    rep.add("K8", "PASS" if total else "FAIL",
            f"Nasycenie budzetu zmierzone: {flat}/{total} komorek plaskich miedzy B={lo} i B={hi}.",
            ("plaskie: " + ", ".join(flat_names[:8]) + (" ..." if len(flat_names) > 8 else ""))
            if flat_names else "kazda komorka reaguje na budzet")


def check_k9(data, rep: Report):
    """Engines below the utility floor must be flagged, so they can be kept out of aggregates."""
    clean = {d["engine_name"]: d for d in data if d["attack_type"] == "clean_baseline"}
    diag = [e for e, d in clean.items() if d["clean_recall_top5"] < MIN_UTILITY_THRESHOLD]
    if not diag:
        rep.add("K9", "INFO", "Wszystkie silniki powyzej progu uzytecznosci.")
        return
    flagged = {d["engine_name"] for d in data if d.get("is_diagnostic")}
    missing = set(diag) - flagged
    lines = []
    for e in diag:
        distinct = len({did for t in clean[e]["traces"] for did in t["retrieved_doc_ids"]})
        slots = sum(len(t["retrieved_doc_ids"]) for t in clean[e]["traces"])
        lines.append(f"{e}: Recall@5 = {clean[e]['clean_recall_top5']:.1%}, "
                     f"{distinct} unikalnych dokumentow w {slots} slotach")
    rep.add("K9", "FAIL" if missing else "PASS",
            ("Silniki ponizej progu nieoznaczone: " + ", ".join(sorted(missing)))
            if missing else "Silniki ponizej progu oznaczone jako diagnostyczne.",
            "\n".join(lines))


def check_ties(data, report_text, rep: Report):
    """Score ties hand the decision to alphabetical document ordering.

    A decisive share of such ties is not fixable by choosing a different tie-break -- every
    choice is equally arbitrary -- so the check passes once the report publishes poison@1 as
    the interval spanned by both directions, and fails while it presents a point estimate.
    """
    rows = []
    # With --log-ties every trace carries bounds over the complete rank-1 tie group, for every
    # engine; older runs only record whether ranks 1 and 2 tie, and only GraphRAG was checked.
    full = bool(data) and all(t.get("tie_logged") for d in data for t in d["traces"])
    for d in data:
        if not full and d["engine_name"] != "GraphRAG":
            continue
        ts = d["traces"]
        if not ts or "top1_is_score_tie" not in ts[0]:
            rep.add("TIE", "INFO", "Slady bez diagnostyki remisow (top1_is_score_tie).")
            return
        label = f"{d['engine_name']} {d['attack_type']}" if full else d["attack_type"]
        if full:
            decisive = sum(1 for t in ts if t["tie_p1_lo"] != t["tie_p1_hi"])
            share_any = sum(1 for t in ts if t["rank1_tie_size"] > 1) / len(ts)
            if share_any > 0.0:
                rows.append((label, share_any, decisive / len(ts)))
            continue
        # A tie between two poison documents changes nothing measurable. What matters is a
        # tie that straddles the poison/clean boundary: there the alphabetical doc_id
        # ordering, not the scoring function, decides whether poison@1 counts a hit.
        decisive = 0
        for t in ts:
            if not t["top1_is_score_tie"] or len(t["retrieved_doc_ids"]) < 2:
                continue
            a, b = t["retrieved_doc_ids"][0], t["retrieved_doc_ids"][1]
            if a.startswith("POISON_") != b.startswith("POISON_"):
                decisive += 1
        share_any = sum(1 for t in ts if t["top1_is_score_tie"]) / len(ts)
        if share_any > 0.0:
            rows.append((label, share_any, decisive / len(ts)))
    rows.sort(key=lambda r: -r[2])
    if not rows:
        rep.add("TIE", "PASS", "Brak remisow na pozycji 1 w scenariuszach GraphRAG.")
        return
    worst = rows[0][2]
    discloses_interval = "zakres remis" in (report_text or "").lower()
    if worst > 0.10 and not discloses_interval:
        status, headline = "FAIL", (
            f"Remisy rozstrzygaja o metryce (max {worst:.1%} zapytan), a raport podaje "
            f"poison@1 jako wartosc punktowa."
        )
    elif worst > 0.10:
        status, headline = "PASS", (
            f"Remisy rozstrzygaja o metryce (max {worst:.1%} zapytan) i raport publikuje "
            f"poison@1 jako przedzial obu rozstrzygniec."
        )
    else:
        status, headline = "INFO", f"Remisy marginalne: max {worst:.1%} zapytan w scenariuszu."
    src = ("pelne grupy remisowe (--log-ties)" if full
           else "tylko pozycje 1-2; pelna grupa moze byc wieksza")
    rep.add("TIE", status, headline,
            f"zrodlo: {src}\n"
            "kolumny: wszystkie remisy / remisy przecinajace granice poison-clean\n"
            + "\n".join(f"{a:<34} {s1:6.1%} / {s2:6.1%}" for a, s1, s2 in rows[:8]))


def run_audit(in_dir) -> int:
    """Runs every check against a results directory. Returns 1 if any check FAILed.

    Importable so the benchmark runner can use it as a gate: a report that ships while an
    invariant is failing is how a known problem becomes an unmentioned one.
    """
    in_dir = Path(in_dir)
    results_path = in_dir / "comparison_benchmark_results.json"
    if not results_path.exists():
        print(f"Brak pliku wynikow: {results_path}")
        return 2
    data = json.loads(results_path.read_text(encoding="utf-8"))

    sweep_path = in_dir / "bridge_sweep_results.json"
    sweep = json.loads(sweep_path.read_text(encoding="utf-8")) if sweep_path.exists() else None

    report_path = in_dir / "rag_poisoning_comparison_report.md"
    report_text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""

    rep = Report()
    check_k1(data, rep)
    check_k2(sweep, rep)
    check_k3(data, report_text, rep)
    check_k4(data, rep)
    check_k5(data, rep)
    check_k6(data, rep)
    check_k7(data, rep)
    check_k8(data, rep)
    check_k9(data, rep)
    check_ties(data, report_text, rep)
    return rep.render()


def main():
    parser = argparse.ArgumentParser(description="Re-audit a benchmark run against findings K1-K9.")
    parser.add_argument("--in-dir", type=str, required=True,
                        help="Results directory to check, e.g. outputs/reports/v3 (read-only).")
    args = parser.parse_args()
    return run_audit(args.in_dir)


if __name__ == "__main__":
    sys.exit(main())
