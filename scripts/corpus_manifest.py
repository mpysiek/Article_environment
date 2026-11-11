#!/usr/bin/env python3
"""Corpus manifest: records which 24,000 documents the article's runs used, without their text.

The source texts cannot all be redistributed (CTIBench, ATT&CK and CVE records stay under their
publishers' terms), so the repository ships a manifest instead of the corpus: one row per
document, in corpus order, with its ID, type, source and SHA-256 hashes of its content.

    # write the manifest from a corpus file (done once, on the corpus used in the article)
    python scripts/corpus_manifest.py build \
        --corpus data/processed/real_cti_corpus_v2_24000.json \
        --out data/corpus_manifest_v2_24000.csv.xz

    # check a locally assembled corpus against it
    python scripts/corpus_manifest.py verify \
        --corpus data/processed/real_cti_corpus_v2_24000.json \
        --manifest data/corpus_manifest_v2_24000.csv.xz

`verify` reports missing, extra, reordered and changed documents and the corpus fingerprint
that run_comparison_benchmark.py writes to run_manifest.json (corpus_id_fingerprint_sha256_16).
The corpus file (real_cti_corpus_v2_24000.json) is the same for runs v2, v2_rerun and v3.
"""
import argparse
import csv
import hashlib
import io
import json
import lzma
import sys
from collections import Counter
from pathlib import Path

FIELDS = ["idx", "id", "doc_type", "source", "text_sha256", "doc_sha256"]

#: Document text prefix -> source. Every loader in src/corpus/real_cti_loader.py writes its
#: documents from a fixed template, so the opening words identify the source unambiguously.
CVE_SOURCES = (
    ("CVE Program record", "CVE Program cvelistV5"),
    ("CISA Known Exploited Vulnerability", "CISA KEV"),
    ("Vulnerability advisory", "CTIBench RCM"),
)
ATTACK_TYPES = {"campaign", "mitigation", "threat_actor", "malware", "tool", "mitre_technique"}


def source_of(doc: dict) -> str:
    text, doc_type = doc.get("text", ""), doc.get("doc_type", "")
    if doc_type == "cve":
        for prefix, source in CVE_SOURCES:
            if text.startswith(prefix):
                return source
    elif doc_type == "threat_report" and text.startswith("Threat intelligence report"):
        return "CTIBench TAA"
    elif doc_type in ATTACK_TYPES:
        return "MITRE ATT&CK"
    return "unknown"


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def rows_from_corpus(path: Path):
    docs = json.loads(path.read_text(encoding="utf-8"))
    for i, d in enumerate(docs):
        yield {
            "idx": str(i),
            "id": d["id"],
            "doc_type": d.get("doc_type", ""),
            "source": source_of(d),
            "text_sha256": sha256(d.get("text", "")),
            # every field the engines see (title, text, entities, relations, flags)
            "doc_sha256": sha256(json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":"))),
        }


def fingerprint(ids) -> str:
    """Same hash as corpus_id_fingerprint_sha256_16 in scripts/run_comparison_benchmark.py."""
    h = hashlib.sha256()
    for doc_id in ids:
        h.update(doc_id.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()[:16]


def open_text(path: Path, mode: str):
    if path.suffix == ".xz":
        raw = lzma.open(path, "wb", preset=9) if mode == "w" else lzma.open(path, "rb")
        return io.TextIOWrapper(raw, encoding="utf-8", newline="")
    return open(path, mode, encoding="utf-8", newline="")


def build(args) -> int:
    rows = list(rows_from_corpus(Path(args.corpus)))
    unknown = [r["id"] for r in rows if r["source"] == "unknown"]
    if unknown:
        print(f"[!] {len(unknown)} documents with unrecognised source, e.g. {unknown[:5]}")
        return 1
    with open_text(Path(args.out), "w") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"[+] {len(rows)} documents -> {args.out}")
    print(f"    corpus_id_fingerprint_sha256_16 = {fingerprint(r['id'] for r in rows)}")
    for (src, dt), n in sorted(Counter((r["source"], r["doc_type"]) for r in rows).items()):
        print(f"    {n:6d}  {src:<22} {dt}")
    return 0


def verify(args) -> int:
    with open_text(Path(args.manifest), "r") as f:
        ref = list(csv.DictReader(f))
    got = list(rows_from_corpus(Path(args.corpus)))
    ref_by_id = {r["id"]: r for r in ref}
    got_by_id = {r["id"]: r for r in got}

    missing = [i for i in ref_by_id if i not in got_by_id]
    extra = [i for i in got_by_id if i not in ref_by_id]
    common = [i for i in ref_by_id if i in got_by_id]
    text_changed = [i for i in common if ref_by_id[i]["text_sha256"] != got_by_id[i]["text_sha256"]]
    doc_changed = [i for i in common if ref_by_id[i]["doc_sha256"] != got_by_id[i]["doc_sha256"]
                   and i not in text_changed]
    moved = [i for i in common if ref_by_id[i]["idx"] != got_by_id[i]["idx"]]

    fp_ref, fp_got = fingerprint(r["id"] for r in ref), fingerprint(r["id"] for r in got)
    print(f"manifest: {len(ref)} documents, fingerprint {fp_ref}")
    print(f"corpus:   {len(got)} documents, fingerprint {fp_got}")
    report = [
        ("missing from corpus", missing),
        ("not in manifest", extra),
        ("text differs", text_changed),
        ("metadata differs (entities/relations/title)", doc_changed),
        ("different position", moved),
    ]
    for label, ids in report:
        print(f"  {label:<44} {len(ids):6d}" + (f"   e.g. {ids[:5]}" if ids else ""))
        if ids:
            by_src = Counter(ref_by_id.get(i, got_by_id.get(i))["source"] for i in ids)
            print("  " + " " * 44 + "        by source: " + ", ".join(f"{s} {n}" for s, n in by_src.most_common()))

    identical = not any(ids for _, ids in report)
    print("RESULT: identical to the article's corpus" if identical
          else "RESULT: differs from the article's corpus")
    return 0 if identical else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="write a manifest from a corpus file")
    b.add_argument("--corpus", required=True)
    b.add_argument("--out", required=True)
    v = sub.add_parser("verify", help="compare a corpus file with a manifest")
    v.add_argument("--corpus", required=True)
    v.add_argument("--manifest", default="data/corpus_manifest_v2_24000.csv.xz")
    args = ap.parse_args()
    return build(args) if args.cmd == "build" else verify(args)


if __name__ == "__main__":
    sys.exit(main())
