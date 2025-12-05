from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional

NodeId = str
EdgeId = str

@dataclass
class AttackGraph:
    nodes: Set[NodeId]
    edges: Dict[EdgeId, Tuple[NodeId, NodeId]]
    sources: Set[NodeId]
    targets: Set[NodeId]
    p_edge: Dict[EdgeId, float]
    I_base: Dict[NodeId, float]
    _in_degree: Dict[NodeId, int] | None = None
    _out_degree: Dict[NodeId, int] | None = None

    def __post_init__(self) -> None:
        if not self.sources.issubset(self.nodes):
            raise ValueError("All sources must be contained in nodes")
        if not self.targets.issubset(self.nodes):
            raise ValueError("All targets must be contained in nodes")
        if self.sources & self.targets:
            raise ValueError("Sources and targets must be disjoint")
        in_deg: Dict[NodeId, int] = {n: 0 for n in self.nodes}
        out_deg: Dict[NodeId, int] = {n: 0 for n in self.nodes}
        for e_id, (u, v) in self.edges.items():
            if u not in self.nodes or v not in self.nodes:
                raise ValueError(f"Edge {e_id} references unknown node(s) {u}, {v}")
            out_deg[u] += 1
            in_deg[v] += 1
        for s in self.sources:
            if in_deg[s] != 0:
                raise ValueError(f"Source node {s} must have in-degree 0")
            if out_deg[s] == 0:
                raise ValueError(f"Source node {s} must have out-degree > 0")
        for t in self.targets:
            if out_deg[t] != 0:
                raise ValueError(f"Target node {t} must have out-degree 0")
            if in_deg[t] == 0:
                raise ValueError(f"Target node {t} must have in-degree > 0")
        for e_id in self.edges.keys():
            if e_id not in self.p_edge:
                raise ValueError(f"Missing base probability p_edge[{e_id}]")
            p = self.p_edge[e_id]
            if not (0.0 <= p <= 1.0):
                raise ValueError(f"p_edge[{e_id}] must be in [0,1], got {p}")
        for f in self.targets:
            if f not in self.I_base:
                raise ValueError(f"Missing base impact I_base[{f}] for target {f}")
            I = self.I_base[f]
            if I < 0.0:
                raise ValueError(f"I_base[{f}] must be >= 0, got {I} for {f}")
        self._in_degree = in_deg
        self._out_degree = out_deg

@dataclass
class Countermeasure:
    id: str
    cost: float
    scope_edges: Set[EdgeId]
    scope_targets: Set[NodeId]
    effectiveness: object | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("Countermeasure id must be a non-empty string")
        if self.cost < 0.0:
            raise ValueError(f"Cost for countermeasure {self.id} must be >= 0")
        if not isinstance(self.scope_edges, set):
            self.scope_edges = set(self.scope_edges)
        if not isinstance(self.scope_targets, set):
            self.scope_targets = set(self.scope_targets)

@dataclass
class CountermeasureCatalog:
    items: List[Countermeasure]

    def __post_init__(self) -> None:
        seen: Set[str] = set()
        for cm in self.items:
            if cm.id in seen:
                raise ValueError(f"Duplicate countermeasure id: {cm.id}")
            seen.add(cm.id)

    def by_id(self) -> Dict[str, Countermeasure]:
        return {cm.id: cm for cm in self.items}

@dataclass
class OptimizationConfig:
    risk_threshold: Optional[float] = None
    budget: Optional[float] = None

    def __post_init__(self) -> None:
        if self.risk_threshold is not None and self.risk_threshold < 0.0:
            raise ValueError("risk_threshold must be >= 0")
        if self.budget is not None and self.budget < 0.0:
            raise ValueError("budget must be >= 0")

@dataclass
class ModelInput:
    graph: AttackGraph
    catalog: CountermeasureCatalog
    config: OptimizationConfig

    def __post_init__(self) -> None:
        edge_ids = set(self.graph.edges.keys())
        target_ids = set(self.graph.targets)
        for cm in self.catalog.items:
            if not cm.scope_edges.issubset(edge_ids):
                unknown = cm.scope_edges - edge_ids
                raise ValueError(
                    f"Countermeasure {cm.id} references unknown edges: {unknown}"
                )
            if not cm.scope_targets.issubset(target_ids):
                unknown = cm.scope_targets - target_ids
                raise ValueError(
                    f"Countermeasure {cm.id} references unknown targets: {unknown}"
                )
