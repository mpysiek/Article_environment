import json
from typing import Dict, List, Any, Optional, Tuple, Set

# STIX object types that become retrievable documents in this benchmark.
DOCUMENT_TYPES = {"attack-pattern", "intrusion-set", "malware", "tool", "campaign", "course-of-action"}


class StixIndex:
    """
    Resolves a MITRE ATT&CK STIX 2.1 bundle into benchmark document IDs and
    real entity relations.

    The bundle stores every relationship as a pair of opaque STIX UUIDs
    (``intrusion-set--899ce53f-...`` -> ``malware--...``). Those UUIDs are
    useless both to the retrieval engines and to the knowledge graph, so this
    index maps each STIX object to the document ID convention used by the rest
    of the benchmark and rewrites all 21k+ edges in terms of those IDs:

        attack-pattern  -> ATT&CK external_id   (T1059.001)
        intrusion-set   -> group name           (APT29)
        malware / tool  -> name                 (Snake, ROADTools)
        campaign        -> campaign name
        course-of-action-> mitigation name
    """

    def __init__(self, data: Dict[str, Any]):
        self.objects_by_id: Dict[str, Dict[str, Any]] = {}
        self.doc_id_by_stix_id: Dict[str, str] = {}
        self.stix_id_by_doc_id: Dict[str, str] = {}
        # (source_doc_id, RELATION, target_doc_id, source_type, target_type)
        self.edges: List[Tuple[str, str, str, str, str]] = []

        objects = data.get("objects", [])
        for obj in objects:
            self.objects_by_id[obj.get("id", "")] = obj

        for obj in objects:
            if obj.get("type") not in DOCUMENT_TYPES or self.is_retired(obj):
                continue
            doc_id = self.doc_id_for(obj)
            if not doc_id:
                continue
            self.doc_id_by_stix_id[obj["id"]] = doc_id
            self.stix_id_by_doc_id.setdefault(doc_id, obj["id"])

        for obj in objects:
            if obj.get("type") != "relationship" or self.is_retired(obj):
                continue
            src = self.doc_id_by_stix_id.get(obj.get("source_ref", ""))
            tgt = self.doc_id_by_stix_id.get(obj.get("target_ref", ""))
            if not src or not tgt:
                continue  # edge points at a retired or non-document object
            src_type = self.objects_by_id[obj["source_ref"]]["type"]
            tgt_type = self.objects_by_id[obj["target_ref"]]["type"]
            relation = obj.get("relationship_type", "related-to").upper().replace("-", "_")
            self.edges.append((src, relation, tgt, src_type, tgt_type))

        self._by_source: Dict[str, List[Tuple[str, str, str, str, str]]] = {}
        self._by_target: Dict[str, List[Tuple[str, str, str, str, str]]] = {}
        for e in self.edges:
            self._by_source.setdefault(e[0], []).append(e)
            self._by_target.setdefault(e[2], []).append(e)

    @staticmethod
    def is_retired(obj: Dict[str, Any]) -> bool:
        """MITRE marks removals with `revoked` and `x_mitre_deprecated` (not `deprecated`)."""
        return bool(obj.get("revoked", False)) or bool(obj.get("x_mitre_deprecated", False))

    @staticmethod
    def attack_id(obj: Dict[str, Any]) -> Optional[str]:
        """Returns the ATT&CK external ID (T1059.001, G0016, S0003, M1049)."""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                return ref["external_id"]
        return None

    @classmethod
    def doc_id_for(cls, obj: Dict[str, Any]) -> Optional[str]:
        if obj.get("type") == "attack-pattern":
            return cls.attack_id(obj)
        return obj.get("name") or None

    def documents(self) -> List[Dict[str, Any]]:
        """Live STIX objects that should become retrievable documents."""
        return [
            self.objects_by_id[sid]
            for sid in self.doc_id_by_stix_id
        ]

    def relations_for(self, stix_id: str) -> List[Dict[str, str]]:
        """Outgoing edges of one object, in the {source, relation, target} shape used by CTIDocument."""
        doc_id = self.doc_id_by_stix_id.get(stix_id)
        if not doc_id:
            return []
        return [
            {"source": src, "relation": rel, "target": tgt}
            for src, rel, tgt, _, _ in self._by_source.get(doc_id, [])
        ]

    def sources_of(self, target_doc_id: str, relation: str, source_type: Optional[str] = None) -> List[str]:
        """Which documents point at `target_doc_id` with `relation` (e.g. which groups USE T1059.001)."""
        out = []
        for src, rel, _tgt, s_type, _t_type in self._by_target.get(target_doc_id, []):
            if rel == relation and (source_type is None or s_type == source_type):
                out.append(src)
        return sorted(dict.fromkeys(out))

    def targets_of(self, source_doc_id: str, relation: str, target_type: Optional[str] = None) -> List[str]:
        """What `source_doc_id` points at with `relation` (e.g. which malware APT29 USES)."""
        out = []
        for _src, rel, tgt, _s_type, t_type in self._by_source.get(source_doc_id, []):
            if rel == relation and (target_type is None or t_type == target_type):
                out.append(tgt)
        return sorted(dict.fromkeys(out))

    def objects_of_type(self, stix_type: str) -> List[Dict[str, Any]]:
        return [o for o in self.documents() if o.get("type") == stix_type]
