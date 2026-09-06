"""
Data integrity guards for the benchmark corpus and gold queries.

These tests exist because the benchmark previously scored retrieval against gold
document IDs that did not exist in the corpus, and padded the corpus with invented
CVE records labelled as official NVD data. Each test below fails on exactly that
class of defect.

Runnable with pytest, or standalone: `python tests/test_data_integrity.py`
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.corpus.real_cti_loader import RealCTILoader
from src.corpus.real_query_loader import RealQueryLoader

# Boilerplate emitted by the removed corpus-padding routine. Any document matching
# these is fabricated data masquerading as an official vulnerability record.
FABRICATION_MARKERS = [
    "NIST NVD Official Vulnerability Record",
    "Enterprise Security Advisory",
    "An issue was discovered in enterprise software systems.",
]

STIX_UUID_RE = re.compile(r"^(attack-pattern|intrusion-set|malware|tool|campaign|course-of-action|relationship)--")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

_CORPUS = None
_QUERIES = None


def corpus():
    """The authentic corpus, built once per test session (uses the on-disk cache)."""
    global _CORPUS
    if _CORPUS is None:
        _CORPUS = RealCTILoader().load_full_real_corpus()
    return _CORPUS


def queries():
    global _QUERIES
    if _QUERIES is None:
        _QUERIES = RealQueryLoader().load_gold_queries(limit=200)
    return _QUERIES


def test_every_gold_doc_exists_in_corpus():
    """The defect that invalidated the previous benchmark run: gold IDs with no document."""
    corpus_ids = {d.id for d in corpus()}
    missing = {}
    for q in queries():
        absent = set(q.ground_truth_doc_ids) - corpus_ids
        if absent:
            missing[q.id] = sorted(absent)
    assert not missing, f"Gold queries reference documents absent from the corpus: {list(missing.items())[:5]}"


def test_corpus_contains_no_fabricated_records():
    """No document may carry the boilerplate of the removed padding routine."""
    offenders = [
        d.id for d in corpus()
        if any(marker in d.text or marker in d.title for marker in FABRICATION_MARKERS)
    ]
    assert not offenders, f"{len(offenders)} fabricated documents found, e.g. {offenders[:5]}"


def test_cve_documents_have_wellformed_ids():
    """Padding used out-of-range serials like CVE-2019-02233; real CVE IDs are not zero-padded to 5."""
    malformed = [
        d.id for d in corpus()
        if d.doc_type == "cve" and (not CVE_RE.match(d.id) or re.match(r"^CVE-\d{4}-0\d{4}$", d.id))
    ]
    assert not malformed, f"Malformed CVE identifiers: {malformed[:10]}"


def test_document_ids_are_unique():
    ids = [d.id for d in corpus()]
    duplicates = {i for i in ids if ids.count(i) > 1} if len(ids) != len(set(ids)) else set()
    assert not duplicates, f"Duplicate document IDs: {sorted(duplicates)[:10]}"


def test_stix_relations_are_resolved_to_document_ids():
    """Relations must name real entities, not opaque STIX UUIDs the engines cannot use."""
    unresolved = [
        (d.id, r)
        for d in corpus()
        for r in d.relations
        if STIX_UUID_RE.match(str(r.get("source", ""))) or STIX_UUID_RE.match(str(r.get("target", "")))
    ]
    assert not unresolved, f"{len(unresolved)} relations still hold raw STIX UUIDs, e.g. {unresolved[:3]}"


def test_corpus_carries_real_attack_relations():
    """GraphRAG is meaningless without the ATT&CK edge set; guard against silently losing it."""
    total = sum(len(d.relations) for d in corpus())
    assert total > 15000, f"Only {total} relations in corpus; ATT&CK edges appear to be missing"


def test_ground_truth_answers_are_substantive():
    """Answers must come from source data, not from a generic template."""
    generic = [
        q.id for q in queries()
        if len(q.ground_truth_answer) < 40
        or "is associated with software vulnerabilities" in q.ground_truth_answer
    ]
    assert not generic, f"Templated or empty ground truth answers: {generic[:5]}"


def test_poison_assertion_contradicts_ground_truth():
    """A poison assertion identical to the ground truth would make ASR unmeasurable."""
    degenerate = [q.id for q in queries() if q.target_poison_assertion.strip() == q.ground_truth_answer.strip()]
    assert not degenerate, f"Poison assertion equals ground truth for: {degenerate[:5]}"


def test_gold_queries_cover_multiple_categories():
    cats = {q.category for q in queries()}
    assert len(cats) >= 3, f"Gold query set collapsed to categories: {cats}"


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL  {t.__name__}\n      {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
