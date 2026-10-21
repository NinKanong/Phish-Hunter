from __future__ import annotations

from typing import Any


def build_graph(result: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    """Build a read-only IOC/technique graph from observable analysis evidence."""
    nodes: dict[str, dict[str, str]] = {}
    edges: list[dict[str, str]] = []

    def node(node_id: str, kind: str, label: str) -> None:
        nodes.setdefault(node_id, {"id": node_id, "kind": kind, "label": label[:240]})

    def edge(source: str, relation: str, target: str) -> None:
        edges.append({"source": source, "relation": relation, "target": target})

    root_label = str(result.get("filename") or result.get("url") or "analysis")
    root_id = "scan:" + root_label[:200]
    node(root_id, "analysis", root_label)

    for kind, values in (result.get("iocs") or {}).items():
        if not isinstance(values, list):
            continue
        for value in values[:200]:
            text = str(value).strip()
            if not text:
                continue
            target = f"{kind}:{text}"
            node(target, kind, text)
            edge(root_id, f"contains_{kind}", target)

    for technique in result.get("mitre_techniques") or []:
        code = str(technique.get("id", "")).strip()
        name = str(technique.get("name", "Technique"))
        if code:
            target = f"mitre:{code}"
            node(target, "mitre", f"{code} {name}")
            edge(root_id, "maps_to", target)

    return {"nodes": list(nodes.values()), "edges": edges[:1000]}
