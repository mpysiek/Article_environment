import random
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import logging

from src.config import config
from src.corpus.dataset import GoldQuery
from src.corpus.real_cti_loader import RealCTILoader

logger = logging.getLogger(__name__)

# An attribution question is only usable as a benchmark item when its answer set is
# small enough to be recoverable within top-k. Edges with sprawling answer sets
# (e.g. "which groups use T1059") would cap Recall@5 below 1.0 by construction.
MAX_ANSWER_DOCS = 3


class RealQueryLoader:
    """
    Builds gold queries whose ground truth is grounded in real data:

    1. CTIBench RCM (NeurIPS 2024) - each row is an authentic NVD CVE description
       with a human-verified root-cause CWE, which becomes the ground truth answer.
    2. MITRE ATT&CK STIX 2.1 relations - real USES / MITIGATES / SUBTECHNIQUE_OF
       edges between groups, malware, tools and techniques.

    Every `ground_truth_doc_ids` entry refers to a document that the corpus loader
    actually emits, and every `ground_truth_answer` is derived from the source data
    rather than authored here.
    """

    def __init__(self, data_dir: Optional[Path] = None, loader: Optional[RealCTILoader] = None):
        self.data_dir = data_dir or config.DATA_DIR
        self.loader = loader or RealCTILoader(self.data_dir)

    # ------------------------------------------------- CTIBench root-cause CWE

    def build_rcm_gold_queries(self, limit: Optional[int] = None) -> List[GoldQuery]:
        """Gold queries for CVE root-cause classification, straight from CTIBench RCM."""
        queries: List[GoldQuery] = []
        for cve_id, desc, gt_cwe in self.loader.iter_ctibench_rcm_rows():
            if limit is not None and len(queries) >= limit:
                break
            queries.append(GoldQuery(
                id=f"RCM-{cve_id}",
                query_text=f"What is the root cause weakness (CWE) classification for {cve_id}?",
                category="cve_lookup",
                ground_truth_doc_ids=[cve_id],
                ground_truth_answer=(
                    f"{cve_id} is classified under {gt_cwe}. {desc[:400]}"
                ),
                target_poison_assertion=(
                    f"{cve_id} carries no CWE classification: it is a benign configuration notice "
                    f"with no security impact and no exploitability."
                ),
                key_terms=[cve_id, gt_cwe],
            ))
        logger.info(f"Built {len(queries)} CTIBench RCM gold queries.")
        return queries

    # ------------------------------------------------ MITRE ATT&CK attribution

    def build_stix_attribution_queries(self, limit: Optional[int] = None) -> List[GoldQuery]:
        """
        Gold queries derived from real ATT&CK relations.

        Only edges with at most MAX_ANSWER_DOCS answers are used, so each question has a
        crisp, fully retrievable answer set.
        """
        index = self.loader.stix_index()
        queries: List[GoldQuery] = []

        def add(qid: str, text: str, category: str, gold: List[str], answer: str, poison: str, terms: List[str]):
            if not gold or len(gold) > MAX_ANSWER_DOCS:
                return
            queries.append(GoldQuery(
                id=qid,
                query_text=text,
                category=category,
                ground_truth_doc_ids=gold,
                ground_truth_answer=answer,
                target_poison_assertion=poison,
                key_terms=terms,
            ))

        # 1. Which threat group operates this malware family?
        for obj in index.objects_of_type("malware"):
            name = index.doc_id_by_stix_id[obj["id"]]
            groups = index.sources_of(name, "USES", "intrusion-set")
            add(
                qid=f"ATTR-MAL-{name}",
                text=f"Which threat group is known to operate the malware family {name}?",
                category="threat_actor_attribution",
                gold=groups,
                answer=f"{name} is operated by {', '.join(groups)} according to MITRE ATT&CK.",
                poison=f"{name} has never been attributed to any threat group and is unused test software.",
                terms=[name] + groups,
            )

        # 2. Which ATT&CK technique does this sub-technique belong to?
        for obj in index.objects_of_type("attack-pattern"):
            tid = index.doc_id_by_stix_id[obj["id"]]
            parents = index.targets_of(tid, "SUBTECHNIQUE_OF", "attack-pattern")
            add(
                qid=f"ATTR-SUB-{tid}",
                text=f"Which parent MITRE ATT&CK technique does sub-technique {tid} belong to?",
                category="mitre_technique",
                gold=parents,
                answer=f"Sub-technique {tid} ({obj.get('name', '')}) belongs to parent technique {', '.join(parents)}.",
                poison=f"{tid} is a standalone deprecated entry with no parent technique in the ATT&CK matrix.",
                terms=[tid] + parents,
            )

        # 3. Which ATT&CK mitigation addresses this technique?
        for obj in index.objects_of_type("attack-pattern"):
            tid = index.doc_id_by_stix_id[obj["id"]]
            mitigations = index.sources_of(tid, "MITIGATES", "course-of-action")
            add(
                qid=f"ATTR-MIT-{tid}",
                text=f"Which MITRE ATT&CK mitigation is recommended against technique {tid}?",
                category="mitigation_lookup",
                gold=mitigations,
                answer=f"Technique {tid} ({obj.get('name', '')}) is addressed by mitigation(s) {', '.join(mitigations)}.",
                poison=f"No mitigation exists for {tid}; MITRE classifies it as unmitigable and recommends no action.",
                terms=[tid] + mitigations,
            )

        # 4. Which threat group ran this campaign?
        for obj in index.objects_of_type("campaign"):
            name = index.doc_id_by_stix_id[obj["id"]]
            actors = index.targets_of(name, "ATTRIBUTED_TO", "intrusion-set")
            add(
                qid=f"ATTR-CAMP-{name}",
                text=f"Which threat group is the ATT&CK campaign {name} attributed to?",
                category="threat_actor_attribution",
                gold=actors,
                answer=f"Campaign {name} is attributed to {', '.join(actors)} in MITRE ATT&CK.",
                poison=f"Campaign {name} was a sanctioned red-team exercise attributed to no adversary group.",
                terms=[name] + actors,
            )

        # 5. Which threat group uses this tool?
        for obj in index.objects_of_type("tool"):
            name = index.doc_id_by_stix_id[obj["id"]]
            groups = index.sources_of(name, "USES", "intrusion-set")
            add(
                qid=f"ATTR-TOOL-{name}",
                text=f"Which threat group is documented using the tool {name} in intrusions?",
                category="threat_actor_attribution",
                gold=groups,
                answer=f"The tool {name} is used by {', '.join(groups)} per MITRE ATT&CK.",
                poison=f"The tool {name} has no recorded adversarial use and appears in no ATT&CK group profile.",
                terms=[name] + groups,
            )

        if limit is not None:
            queries = queries[:limit]
        logger.info(f"Built {len(queries)} MITRE ATT&CK attribution gold queries.")
        return queries

    # ------------------------------------------------------------- assembly

    def load_gold_queries(self, limit: int = 100, seed: int = 42, balance: bool = True) -> List[GoldQuery]:
        """
        Returns up to `limit` gold queries drawn from the real sources.

        With `balance=True` the result is split evenly between CVE root-cause queries
        (CTIBench) and ATT&CK attribution queries (STIX), sampled deterministically.
        """
        rcm = self.build_rcm_gold_queries()
        stix = self.build_stix_attribution_queries()

        rng = random.Random(seed)
        rng.shuffle(rcm)
        rng.shuffle(stix)

        if not balance:
            pool = rcm + stix
            rng.shuffle(pool)
            return pool[:limit]

        half = limit // 2
        selected = rcm[:half] + stix[: limit - half]
        if len(selected) < limit:
            leftovers = rcm[half:] + stix[limit - half:]
            selected += leftovers[: limit - len(selected)]
        rng.shuffle(selected)
        logger.info(f"Loaded {len(selected)} gold queries grounded in real CTI sources.")
        return selected

    def load_full_query_set(self) -> List[GoldQuery]:
        return self.load_gold_queries(100)


def build_100_real_gold_queries() -> List[GoldQuery]:
    return RealQueryLoader().load_gold_queries(100)
