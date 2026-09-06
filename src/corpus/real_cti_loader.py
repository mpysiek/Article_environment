import os
import json
import csv
import io
import re
import random
import zipfile
import urllib.request
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import logging

from src.corpus.dataset import CTIDocument
from src.corpus.stix_index import StixIndex
from src.config import config

logger = logging.getLogger(__name__)


class RealCTILoader:
    """
    Ingests authentic, non-synthetic Cyber Threat Intelligence (CTI) datasets:
    1. MITRE ATT&CK Enterprise Matrix STIX 2.1 (official GitHub feed), including
       its 20k+ resolved entity relations.
    2. CTIBench (NeurIPS 2024 Spotlight / HuggingFace AI4Sec) CVE->CWE records
       and threat actor attribution reports.
    3. CISA Known Exploited Vulnerabilities catalog (real, actively exploited CVEs).
    4. CVE Program cvelistV5 bulk release (386k+ authentic CVE records) for scale.

    This loader never fabricates records. If the requested corpus size exceeds
    what the real sources provide, it returns what exists and logs a warning
    rather than padding the corpus with invented documents.
    """

    MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    CTIBENCH_RCM_URL = "https://huggingface.co/datasets/AI4Sec/cti-bench/raw/main/cti-rcm.tsv"
    CTIBENCH_TAA_URL = "https://huggingface.co/datasets/AI4Sec/cti-bench/raw/main/cti-taa.tsv"
    CTIBENCH_ATE_URL = "https://huggingface.co/datasets/AI4Sec/cti-bench/raw/main/cti-ate.tsv"
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CVELIST_RELEASE_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or config.DATA_DIR
        self.raw_dir = self.data_dir / "raw"
        self.processed_dir = self.data_dir / "processed"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self._stix_index: Optional[StixIndex] = None

    # ------------------------------------------------------------------ utils

    def _fetch_url(self, url: str, target_file: Path) -> str:
        """Downloads a remote URL and caches it locally in data/raw/."""
        if target_file.exists() and target_file.stat().st_size > 0:
            logger.info(f"Loading cached file: {target_file.name}")
            return target_file.read_text(encoding="utf-8", errors="ignore")

        logger.info(f"Downloading from {url} to {target_file.name}...")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (RAG-CTI-Benchmark/2.0)"})
        with urllib.request.urlopen(req, timeout=90) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            target_file.write_text(content, encoding="utf-8")
            return content

    def stix_index(self) -> StixIndex:
        """Parsed MITRE ATT&CK bundle with all entity relations resolved to document IDs."""
        if self._stix_index is None:
            stix_file = self.raw_dir / "enterprise_attack_stix21.json"
            raw_json = self._fetch_url(self.MITRE_STIX_URL, stix_file)
            self._stix_index = StixIndex(json.loads(raw_json))
        return self._stix_index

    # ------------------------------------------------------------- MITRE STIX

    def load_mitre_stix_documents(self) -> List[CTIDocument]:
        """
        Parses the official MITRE ATT&CK Enterprise STIX 2.1 bundle into CTIDocuments,
        attaching the real relations (USES, MITIGATES, SUBTECHNIQUE_OF, ...) that the
        bundle actually asserts between techniques, groups, malware, tools and campaigns.
        """
        index = self.stix_index()
        docs: List[CTIDocument] = []

        for obj in index.documents():
            stix_id = obj["id"]
            doc_id = index.doc_id_by_stix_id[stix_id]
            obj_type = obj.get("type", "")
            name = obj.get("name", "")
            desc = obj.get("description", "")
            attack_id = StixIndex.attack_id(obj) or doc_id
            relations = index.relations_for(stix_id)
            related_entities = sorted({r["target"] for r in relations})[:25]

            if obj_type == "attack-pattern":
                tactics = [p.get("phase_name", "").replace("-", " ").title() for p in obj.get("kill_chain_phases", [])]
                platforms = obj.get("x_mitre_platforms", [])
                docs.append(CTIDocument(
                    id=doc_id,
                    title=f"MITRE ATT&CK {doc_id}: {name}",
                    text=(
                        f"Technique {doc_id} ({name}) [Tactics: {', '.join(tactics)}] "
                        f"[Platforms: {', '.join(platforms)}]. {desc[:1200]}"
                    ),
                    doc_type="mitre_technique",
                    entities=[doc_id, name] + tactics + related_entities,
                    relations=relations + [
                        {"source": doc_id, "relation": "BELONGS_TO_TACTIC", "target": t} for t in tactics
                    ],
                ))

            elif obj_type == "intrusion-set":
                aliases = [a for a in obj.get("aliases", []) if a != name]
                docs.append(CTIDocument(
                    id=doc_id,
                    title=f"Threat Actor: {name} ({', '.join(aliases[:3]) if aliases else attack_id})",
                    text=f"Adversary group {name} ({attack_id}; aliases: {', '.join(aliases) or 'none'}). {desc[:1400]}",
                    doc_type="threat_actor",
                    entities=[name, attack_id] + aliases[:6] + related_entities,
                    relations=relations + [
                        {"source": name, "relation": "HAS_ALIAS", "target": a} for a in aliases[:5]
                    ],
                ))

            elif obj_type in ("malware", "tool"):
                aliases = [a for a in obj.get("x_mitre_aliases", []) if a != name]
                used_by = index.sources_of(doc_id, "USES", "intrusion-set")
                kind = "Malware" if obj_type == "malware" else "Tool"
                attribution = f"Attributed to: {', '.join(used_by[:8])}. " if used_by else ""
                alias_str = f"; aliases: {', '.join(aliases)}" if aliases else ""
                docs.append(CTIDocument(
                    id=doc_id,
                    title=f"{kind}: {name} ({attack_id})",
                    text=(
                        f"Security analysis for {name} ({obj_type}, {attack_id}{alias_str}). "
                        f"{attribution}{desc[:1100]}"
                    ),
                    doc_type="malware" if obj_type == "malware" else "tool",
                    entities=[name, attack_id, obj_type] + aliases[:5] + related_entities,
                    relations=relations,
                ))

            elif obj_type == "campaign":
                docs.append(CTIDocument(
                    id=doc_id,
                    title=f"Campaign: {name} ({attack_id})",
                    text=(
                        f"Intrusion campaign {name} ({attack_id}) "
                        f"[{obj.get('first_seen', '?')} - {obj.get('last_seen', '?')}]. {desc[:1100]}"
                    ),
                    doc_type="campaign",
                    entities=[name, attack_id] + related_entities,
                    relations=relations,
                ))

            elif obj_type == "course-of-action":
                docs.append(CTIDocument(
                    id=doc_id,
                    title=f"Mitigation: {name} ({attack_id})",
                    text=f"ATT&CK mitigation {attack_id} ({name}). {desc[:900]}",
                    doc_type="mitigation",
                    entities=[name, attack_id] + related_entities,
                    relations=relations,
                ))

        logger.info(
            f"Loaded {len(docs)} authentic MITRE STIX 2.1 documents "
            f"with {sum(len(d.relations) for d in docs)} real relations."
        )
        return docs

    # --------------------------------------------------------------- CTIBench

    def load_ctibench_documents(self) -> List[CTIDocument]:
        """Parses real CVE root-cause records and threat actor reports from CTIBench (NeurIPS 2024)."""
        docs: List[CTIDocument] = []

        # 1. CTIBench RCM: authentic NVD CVE descriptions with verified CWE ground truth
        for cve_id, desc, gt_cwe in self.iter_ctibench_rcm_rows():
            docs.append(CTIDocument(
                id=cve_id,
                title=f"{cve_id}: NVD Vulnerability Advisory ({gt_cwe})",
                text=f"Vulnerability advisory {cve_id}. Root cause classified under {gt_cwe}. {desc}",
                doc_type="cve",
                entities=[cve_id, gt_cwe, "Vulnerability"],
                relations=[{"source": cve_id, "relation": "EXPLOITS_WEAKNESS", "target": gt_cwe}],
            ))

        # 2. CTIBench TAA: authentic threat actor attribution reports
        taa_file = self.raw_dir / "ctibench_taa.tsv"
        taa_raw = self._fetch_url(self.CTIBENCH_TAA_URL, taa_file)
        reader_taa = csv.reader(io.StringIO(taa_raw), delimiter="\t")
        next(reader_taa, None)

        for idx, row in enumerate(reader_taa, 1):
            if len(row) >= 2:
                url, report_text = row[0], row[1]
                docs.append(CTIDocument(
                    id=f"CTI-REPORT-{idx:04d}",
                    title=f"CTI Threat Telemetry Report #{idx:04d}",
                    text=f"Threat intelligence report ({url}): {report_text[:1200]}",
                    doc_type="threat_report",
                    entities=[f"CTI-REPORT-{idx:04d}", "Threat Telemetry"],
                    relations=[],
                ))

        logger.info(f"Loaded {len(docs)} authentic CTIBench documents.")
        return docs

    def iter_ctibench_rcm_rows(self):
        """Yields (cve_id, description, ground_truth_cwe) for every real CTIBench RCM record."""
        rcm_file = self.raw_dir / "ctibench_rcm.tsv"
        rcm_raw = self._fetch_url(self.CTIBENCH_RCM_URL, rcm_file)
        reader = csv.reader(io.StringIO(rcm_raw), delimiter="\t")
        next(reader, None)

        for row in reader:
            if len(row) < 4:
                continue
            url, desc, _prompt, gt_cwe = row[0], row[1], row[2], row[3]
            cve_id = url.rsplit("/", 1)[-1].strip()
            gt_cwe = gt_cwe.strip()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id) or not re.fullmatch(r"CWE-\d+", gt_cwe):
                continue
            yield cve_id, desc.strip(), gt_cwe

    # -------------------------------------------------------------- CISA KEV

    def load_kev_documents(self, exclude_ids: Optional[Set[str]] = None) -> List[CTIDocument]:
        """Parses the CISA Known Exploited Vulnerabilities catalog (real, actively exploited CVEs)."""
        exclude_ids = exclude_ids or set()
        kev_file = self.raw_dir / "cisa_kev.json"
        data = json.loads(self._fetch_url(self.KEV_URL, kev_file))

        docs: List[CTIDocument] = []
        for entry in data.get("vulnerabilities", []):
            cve_id = entry.get("cveID", "")
            if not cve_id or cve_id in exclude_ids:
                continue
            vendor = entry.get("vendorProject", "")
            product = entry.get("product", "")
            cwes = [c for c in entry.get("cwes", []) if c]
            docs.append(CTIDocument(
                id=cve_id,
                title=f"{cve_id}: {vendor} {product} - {entry.get('vulnerabilityName', 'Known Exploited Vulnerability')}",
                text=(
                    f"CISA Known Exploited Vulnerability {cve_id} affecting {vendor} {product} "
                    f"(added {entry.get('dateAdded', 'n/a')}, remediation due {entry.get('dueDate', 'n/a')}). "
                    f"{entry.get('shortDescription', '')} Required action: {entry.get('requiredAction', 'n/a')} "
                    f"Known ransomware campaign use: {entry.get('knownRansomwareCampaignUse', 'Unknown')}."
                ),
                doc_type="cve",
                entities=[cve_id, vendor, product, "Known Exploited Vulnerability"] + cwes,
                relations=(
                    [{"source": cve_id, "relation": "EXPLOITS_WEAKNESS", "target": c} for c in cwes]
                    + [{"source": cve_id, "relation": "TARGETS_VENDOR", "target": vendor}]
                ),
            ))
        logger.info(f"Loaded {len(docs)} authentic CISA KEV documents.")
        return docs

    # ------------------------------------------------------------- cvelistV5

    def cvelist_archive(self, download: bool = True) -> Optional[Path]:
        """Returns the path to the cvelistV5 bulk archive, downloading the latest release if needed."""
        archive = self.raw_dir / "cvelistV5_all.zip"
        if archive.exists() and archive.stat().st_size > 0:
            return archive
        if not download:
            return None

        req = urllib.request.Request(self.CVELIST_RELEASE_API, headers={"User-Agent": "RAG-CTI-Benchmark/2.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            release = json.loads(resp.read().decode("utf-8"))
        asset = next((a for a in release.get("assets", []) if "all_CVEs" in a.get("name", "")), None)
        if not asset:
            logger.warning("No cvelistV5 bulk asset found in latest release.")
            return None

        logger.info(f"Downloading cvelistV5 bulk archive ({asset['size'] / 1e6:.0f} MB)...")
        req = urllib.request.Request(asset["browser_download_url"], headers={"User-Agent": "RAG-CTI-Benchmark/2.0"})
        with urllib.request.urlopen(req, timeout=600) as r, open(archive, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        return archive

    def load_cvelist_documents(
        self,
        limit: int,
        exclude_ids: Optional[Set[str]] = None,
        min_year: int = 2015,
        seed: int = 42,
        download: bool = True,
    ) -> List[CTIDocument]:
        """
        Samples `limit` authentic CVE records from the CVE Program cvelistV5 bulk release.

        Records are real CNA submissions: real descriptions, real CWE mappings and real
        affected vendors/products. REJECTED and description-less records are skipped.
        """
        exclude_ids = exclude_ids or set()
        if limit <= 0:
            return []

        archive = self.cvelist_archive(download=download)
        if archive is None:
            logger.warning("cvelistV5 archive unavailable; skipping bulk CVE ingestion.")
            return []

        outer = zipfile.ZipFile(archive)
        inner_name = next((n for n in outer.namelist() if n.endswith("cves.zip")), None)
        inner = zipfile.ZipFile(io.BytesIO(outer.read(inner_name))) if inner_name else outer

        year_re = re.compile(r"CVE-(\d{4})-")
        candidates = []
        for n in inner.namelist():
            if not n.endswith(".json"):
                continue
            m = year_re.search(n)
            if not m or int(m.group(1)) < min_year:
                continue
            if n.rsplit("/", 1)[-1][:-5] in exclude_ids:
                continue
            candidates.append(n)

        rng = random.Random(seed)
        rng.shuffle(candidates)

        docs: List[CTIDocument] = []
        for name in candidates:
            if len(docs) >= limit:
                break
            try:
                rec = json.loads(inner.read(name))
            except Exception:
                continue
            doc = self._cvelist_record_to_document(rec)
            if doc is not None:
                docs.append(doc)

        logger.info(f"Loaded {len(docs)} authentic cvelistV5 CVE records.")
        return docs

    @staticmethod
    def _cvelist_record_to_document(rec: Dict[str, Any]) -> Optional[CTIDocument]:
        meta = rec.get("cveMetadata", {})
        cve_id = meta.get("cveId", "")
        if not cve_id or meta.get("state") != "PUBLISHED":
            return None

        cna = rec.get("containers", {}).get("cna", {})
        desc = next(
            (d.get("value", "") for d in cna.get("descriptions", []) if d.get("lang", "en").startswith("en")),
            "",
        ).strip()
        if len(desc) < 40:
            return None

        cwes = []
        for pt in cna.get("problemTypes", []):
            for d in pt.get("descriptions", []):
                cwe = d.get("cweId")
                if cwe and cwe not in cwes:
                    cwes.append(cwe)

        affected = cna.get("affected", []) or []
        vendors = sorted({a.get("vendor", "") for a in affected if a.get("vendor") and a.get("vendor") != "n/a"})
        products = sorted({a.get("product", "") for a in affected if a.get("product") and a.get("product") != "n/a"})

        cvss = ""
        for m in cna.get("metrics", []):
            for key, val in m.items():
                if key.startswith("cvssV") and isinstance(val, dict) and val.get("baseScore") is not None:
                    cvss = f" CVSS {val.get('baseScore')} ({val.get('baseSeverity', '')})."
                    break

        title = cna.get("title") or (products[0] if products else "Vulnerability Advisory")
        cwe_str = ", ".join(cwes) if cwes else "unclassified"
        vendor_str = f" affecting {', '.join(vendors[:3])}" if vendors else ""
        product_str = f" ({', '.join(products[:3])})" if products else ""
        relations = [{"source": cve_id, "relation": "EXPLOITS_WEAKNESS", "target": c} for c in cwes]
        relations += [{"source": cve_id, "relation": "TARGETS_VENDOR", "target": v} for v in vendors[:5]]

        return CTIDocument(
            id=cve_id,
            title=f"{cve_id}: {title}"[:200],
            text=(
                f"CVE Program record {cve_id}{vendor_str}{product_str}. "
                f"Root cause classified under {cwe_str}.{cvss} {desc[:1200]}"
            ),
            doc_type="cve",
            entities=[cve_id] + cwes + vendors[:4] + products[:4],
            relations=relations,
        )

    # --------------------------------------------------------------- assembly

    def load_full_real_corpus(self, target_cves: int = 24000, allow_download: bool = True) -> List[CTIDocument]:
        """
        Loads the combined authentic CTI corpus, cached in data/processed/.

        `target_cves` is an upper bound on total corpus size. Every document comes from a
        real source; if the real sources cannot reach the target, the corpus is returned
        smaller and a warning is logged. No records are ever fabricated to hit a number.
        """
        cache_path = self.processed_dir / f"real_cti_corpus_v2_{target_cves}.json"
        if cache_path.exists():
            logger.info(f"Loading real CTI corpus from cache: {cache_path}")
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            return [CTIDocument(**d) for d in data]

        logger.info("Building authentic CTI corpus from real sources...")
        all_docs: List[CTIDocument] = []
        seen: Set[str] = set()

        def extend(new_docs: List[CTIDocument]):
            for d in new_docs:
                if d.id in seen:
                    continue
                seen.add(d.id)
                all_docs.append(d)

        # 1. MITRE ATT&CK STIX 2.1 - techniques, groups, malware, tools, campaigns, mitigations
        extend(self.load_mitre_stix_documents())
        # 2. CTIBench - verified CVE root-cause records and threat actor reports
        extend(self.load_ctibench_documents())
        # 3. CISA KEV - real, actively exploited vulnerabilities
        extend(self.load_kev_documents(exclude_ids=seen))
        # 4. cvelistV5 bulk - authentic CVE records to reach the requested scale
        remaining = target_cves - len(all_docs)
        if remaining > 0:
            extend(self.load_cvelist_documents(limit=remaining, exclude_ids=seen, download=allow_download))

        if len(all_docs) < target_cves:
            logger.warning(
                f"Real sources yielded {len(all_docs)} documents, below the requested {target_cves}. "
                f"Returning the authentic corpus as-is (no synthetic padding)."
            )

        cache_path.write_text(
            json.dumps([d.__dict__ for d in all_docs], indent=2, ensure_ascii=False), encoding="utf-8"
        )
        logger.info(f"Cached {len(all_docs)} authentic CTI documents to {cache_path}")
        return all_docs
