"""The corpus manifest in data/ matches the runs it documents, and verify() catches changes."""
import csv
import importlib.util
import io
import json
import lzma
from argparse import Namespace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "data" / "corpus_manifest_v2_24000.csv.xz"

_spec = importlib.util.spec_from_file_location("corpus_manifest", ROOT / "scripts" / "corpus_manifest.py")
cm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cm)


def _rows():
    with io.TextIOWrapper(lzma.open(MANIFEST, "rb"), encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def test_manifest_matches_fingerprint_of_every_reported_run():
    rows = _rows()
    assert len(rows) == 24000
    assert [int(r["idx"]) for r in rows] == list(range(24000))
    fp = cm.fingerprint(r["id"] for r in rows)
    for run in ("v2", "v2_rerun", "v3"):
        manifest = json.loads((ROOT / "outputs" / "reports" / run / "run_manifest.json").read_text(encoding="utf-8"))
        assert manifest["corpus_id_fingerprint_sha256_16"] == fp, run
        assert manifest["corpus_documents"] == len(rows)


def test_manifest_doc_types_match_run_manifest():
    rows = _rows()
    manifest = json.loads((ROOT / "outputs" / "reports" / "v3" / "run_manifest.json").read_text(encoding="utf-8"))
    counts = {}
    for r in rows:
        counts[r["doc_type"]] = counts.get(r["doc_type"], 0) + 1
    assert counts == manifest["corpus_doc_types"]
    assert all(r["source"] != "unknown" for r in rows)


def _doc(i, doc_type="cve", text=None):
    return {"id": f"CVE-2024-{i:05d}", "title": "t", "doc_type": doc_type,
            "text": text or f"CVE Program record CVE-2024-{i:05d} affecting x.",
            "entities": [], "relations": [], "is_poisoned": False}


def test_build_then_verify_roundtrip_and_detects_changes(tmp_path, capsys):
    corpus = [_doc(i) for i in range(5)]
    cpath, mpath = tmp_path / "c.json", tmp_path / "m.csv.xz"
    cpath.write_text(json.dumps(corpus), encoding="utf-8")
    assert cm.build(Namespace(corpus=str(cpath), out=str(mpath))) == 0
    assert cm.verify(Namespace(corpus=str(cpath), manifest=str(mpath))) == 0

    corpus[2]["text"] += " changed"
    corpus[3]["relations"] = [{"source": "a", "relation": "USES", "target": "b"}]
    del corpus[0]
    cpath.write_text(json.dumps(corpus), encoding="utf-8")
    capsys.readouterr()
    assert cm.verify(Namespace(corpus=str(cpath), manifest=str(mpath))) == 1
    out = capsys.readouterr().out
    assert "missing from corpus                               1" in out
    assert "text differs                                      1" in out
    assert "metadata differs (entities/relations/title)       1" in out


def test_source_is_read_from_document_template():
    assert cm.source_of(_doc(1)) == "CVE Program cvelistV5"
    assert cm.source_of(_doc(1, text="CISA Known Exploited Vulnerability CVE-1")) == "CISA KEV"
    assert cm.source_of(_doc(1, text="Vulnerability advisory CVE-1.")) == "CTIBench RCM"
    assert cm.source_of(_doc(1, "threat_report", "Threat intelligence report ...")) == "CTIBench TAA"
    assert cm.source_of(_doc(1, "malware", "Security analysis for x")) == "MITRE ATT&CK"
    assert cm.source_of(_doc(1, text="something else")) == "unknown"
