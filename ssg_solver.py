from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence, Tuple

import pulp

from models import (
    AttackGraph,
    NodeId,
    EdgeId,
    Countermeasure,
    CountermeasureCatalog,
    OptimizationConfig,
    ModelInput,
)

def _parse_percent_effectiveness(cm: Countermeasure) -> Tuple[float, float]:
    eff = cm.effectiveness
    p_factor = 1.0
    I_factor = 1.0
    if eff is None:
        return p_factor, I_factor
    if isinstance(eff, (int, float)):
        p_factor = float(eff)
    elif isinstance(eff, dict):
        if "p_factor" in eff:
            p_factor = float(eff["p_factor"])
        if "I_factor" in eff:
            I_factor = float(eff["I_factor"])
    for name, value in (("p_factor", p_factor), ("I_factor", I_factor)):
        if value != 1.0:
            if not (0.0 < value <= 1.0):
                raise ValueError(
                    f"{name} for countermeasure {cm.id} must be in (0,1], got {value}"
                )
    return p_factor, I_factor

def _safe_log(x: float, eps: float = 1e-12) -> float:
    return math.log(max(x, eps))

def attacker_best_response(
    graph: AttackGraph,
    log_p_edge: Dict[EdgeId, float],
    log_I: Dict[NodeId, float],
) -> Tuple[Optional[List[NodeId]], Optional[List[EdgeId]], Optional[float]]:
    nodes = list(graph.nodes)
    sources = graph.sources
    targets = graph.targets
    if not sources or not targets:
        return None, None, None
    dist: Dict[NodeId, float] = {n: float("-inf") for n in nodes}
    parent: Dict[NodeId, Optional[NodeId]] = {n: None for n in nodes}
    parent_edge: Dict[NodeId, Optional[EdgeId]] = {n: None for n in nodes}
    for s in sources:
        dist[s] = 0.0
    num_nodes = len(nodes)
    for _ in range(num_nodes - 1):
        updated = False
        for e_id, (u, v) in graph.edges.items():
            if dist[u] == float("-inf"):
                continue
            w = log_p_edge.get(e_id, float("-inf"))
            if w == float("-inf"):
                continue
            cand = dist[u] + w
            if cand > dist[v]:
                dist[v] = cand
                parent[v] = u
                parent_edge[v] = e_id
                updated = True
        if not updated:
            break
    best_target: Optional[NodeId] = None
    best_score: float = float("-inf")
    for t in targets:
        if dist[t] == float("-inf"):
            continue
        if t not in log_I:
            continue
        score = dist[t] + log_I[t]
        if score > best_score:
            best_score = score
            best_target = t
    if best_target is None:
        return None, None, None
    path_nodes: List[NodeId] = []
    path_edges: List[EdgeId] = []
    cur = best_target
    while cur is not None:
        path_nodes.append(cur)
        prev = parent[cur]
        if prev is not None:
            e_id = parent_edge[cur]
            assert e_id is not None
            path_edges.append(e_id)
        cur = prev
    path_nodes.reverse()
    path_edges.reverse()
    return path_nodes, path_edges, best_score

def compute_log_p_and_log_I(
    graph: AttackGraph,
    catalog: CountermeasureCatalog,
    x_vals: Dict[str, float],
) -> Tuple[Dict[EdgeId, float], Dict[NodeId, float]]:
    log_p_edge: Dict[EdgeId, float] = {
        e_id: _safe_log(graph.p_edge[e_id]) for e_id in graph.edges.keys()
    }
    log_I: Dict[NodeId, float] = {
        f: _safe_log(graph.I_base[f]) for f in graph.targets
    }
    for cm in catalog.items:
        x = x_vals.get(cm.id, 0.0)
        if x <= 0.0:
            continue
        p_factor, I_factor = _parse_percent_effectiveness(cm)
        log_p_factor = math.log(p_factor) if p_factor != 1.0 else 0.0
        log_I_factor = math.log(I_factor) if I_factor != 1.0 else 0.0
        if log_p_factor != 0.0:
            for e_id in cm.scope_edges:
                if e_id not in log_p_edge:
                    raise KeyError(
                        f"Countermeasure {cm.id} references unknown edge {e_id}"
                    )
                log_p_edge[e_id] += x * log_p_factor
        if log_I_factor != 0.0:
            for f in cm.scope_targets:
                if f not in log_I:
                    raise KeyError(
                        f"Countermeasure {cm.id} references unknown target {f}"
                    )
                log_I[f] += x * log_I_factor
    return log_p_edge, log_I

def build_path_constraint_coeffs(
    path_nodes: Sequence[NodeId],
    path_edges: Sequence[EdgeId],
    target: NodeId,
    graph: AttackGraph,
    catalog: CountermeasureCatalog,
) -> Tuple[float, Dict[str, float]]:
    if not path_nodes:
        raise ValueError("path_nodes must be non-empty")
    if path_nodes[-1] != target:
        raise ValueError("target must coincide with last node of path_nodes")
    if len(path_edges) != max(0, len(path_nodes) - 1):
        raise ValueError(
            "path_edges length must be len(path_nodes)-1 (one edge per hop)"
        )
    const_term = 0.0
    for e_id in path_edges:
        const_term += _safe_log(graph.p_edge[e_id])
    if graph.I_base.get(target, 0.0) > 0.0:
        const_term += _safe_log(graph.I_base[target])
    else:
        const_term += -1e9
    coeffs: Dict[str, float] = {}
    for cm in catalog.items:
        p_factor, I_factor = _parse_percent_effectiveness(cm)
        log_p_factor = math.log(p_factor) if p_factor != 1.0 else 0.0
        log_I_factor = math.log(I_factor) if I_factor != 1.0 else 0.0
        contrib = 0.0
        if log_p_factor != 0.0 and path_edges:
            k_edges = sum(1 for e_id in path_edges if e_id in cm.scope_edges)
            if k_edges > 0:
                contrib += k_edges * log_p_factor
        if log_I_factor != 0.0 and target in cm.scope_targets:
            contrib += log_I_factor
        if contrib != 0.0:
            coeffs[cm.id] = contrib
    return const_term, coeffs

def _solve_min_cost_given_risk_cap_and_budget(
    graph: AttackGraph,
    catalog: CountermeasureCatalog,
    budget: float,
    risk_cap: float,
    iter_max: int = 50,
    tol: float = 1e-6,
) -> Dict[str, object]:
    if budget < 0.0:
        raise ValueError("budget must be >= 0")
    if risk_cap < 0.0:
        raise ValueError("risk_cap must be >= 0")
    log_R_cap = _safe_log(risk_cap) if risk_cap > 0.0 else math.log(1e-12)
    prob = pulp.LpProblem("MinCostGivenRiskCapAndBudget", pulp.LpMinimize)
    x_vars: Dict[str, pulp.LpVariable] = {
        cm.id: pulp.LpVariable(f"x2_{cm.id}", 0, 1, cat="Binary")
        for cm in catalog.items
    }
    prob += pulp.lpSum(cm.cost * x_vars[cm.id] for cm in catalog.items), "TotalCost"
    prob += (
        pulp.lpSum(cm.cost * x_vars[cm.id] for cm in catalog.items) <= budget,
        "BudgetConstraint",
    )
    active_paths: List[List[NodeId]] = []
    best_solution: Optional[Dict[str, object]] = None
    for it in range(iter_max):
        prob.solve(pulp.PULP_CBC_CMD(msg=False))
        if pulp.LpStatus[prob.status] != "Optimal":
            best_solution = {
                "status": pulp.LpStatus[prob.status],
                "selected_cms": [],
                "x_values": {},
                "total_cost": None,
                "worst_path": None,
                "worst_path_risk": None,
                "active_paths": active_paths,
            }
            break
        x_vals: Dict[str, float] = {
            cm.id: x_vars[cm.id].value() or 0.0 for cm in catalog.items
        }
        log_p, log_I = compute_log_p_and_log_I(graph, catalog, x_vals)
        path, path_edges, log_risk = attacker_best_response(graph, log_p, log_I)
        if path is None or log_risk is None:
            worst_risk = 0.0
        else:
            worst_risk = math.exp(log_risk)
        if worst_risk <= risk_cap + tol:
            best_solution = {
                "status": "Optimal",
                "selected_cms": [
                    cm.id for cm in catalog.items if x_vals[cm.id] > 0.5
                ],
                "x_values": x_vals,
                "total_cost": sum(
                    cm.cost * x_vals[cm.id] for cm in catalog.items
                ),
                "worst_path": path,
                "worst_path_risk": worst_risk,
                "active_paths": active_paths,
            }
            break
        target = path[-1]
        const_term, coeffs = build_path_constraint_coeffs(
            path, path_edges, target, graph, catalog
        )
        prob += (
            const_term
            + pulp.lpSum(coeffs[cid] * x_vars[cid] for cid in coeffs.keys())
            <= log_R_cap
        ), f"path2_constraint_{it}"
        active_paths.append(list(path))
    if best_solution is None:
        best_solution = {
            "status": "IterLimit",
            "selected_cms": [],
            "x_values": {},
            "total_cost": None,
            "worst_path": None,
            "worst_path_risk": None,
            "active_paths": active_paths,
        }
    return best_solution

def solve_min_cost_given_risk_threshold(
    model_input: ModelInput,
    iter_max: int = 50,
    tol: float = 1e-6,
) -> Dict[str, object]:
    graph = model_input.graph
    catalog = model_input.catalog
    config = model_input.config
    if config.risk_threshold is None:
        raise ValueError("risk_threshold is not set in OptimizationConfig")
    R_max = config.risk_threshold
    if R_max < 0.0:
        raise ValueError("risk_threshold must be >= 0")
    log_R_max = _safe_log(R_max) if R_max > 0.0 else math.log(1e-12)
    prob = pulp.LpProblem("MinCostUnderRiskThreshold", pulp.LpMinimize)
    x_vars: Dict[str, pulp.LpVariable] = {
        cm.id: pulp.LpVariable(f"x_{cm.id}", 0, 1, cat="Binary")
        for cm in catalog.items
    }
    prob += (
        pulp.lpSum(cm.cost * x_vars[cm.id] for cm in catalog.items),
        "TotalCost",
    )
    active_paths: List[List[NodeId]] = []
    best_solution: Optional[Dict[str, object]] = None
    for it in range(iter_max):
        prob.solve(pulp.PULP_CBC_CMD(msg=False))
        if pulp.LpStatus[prob.status] != "Optimal":
            best_solution = {
                "status": pulp.LpStatus[prob.status],
                "selected_cms": [],
                "x_values": {},
                "total_cost": None,
                "worst_path": None,
                "worst_path_risk": None,
                "active_paths": active_paths,
            }
            break
        x_vals: Dict[str, float] = {
            cm.id: x_vars[cm.id].value() or 0.0 for cm in catalog.items
        }
        log_p, log_I = compute_log_p_and_log_I(graph, catalog, x_vals)
        path, path_edges, log_risk = attacker_best_response(graph, log_p, log_I)
        if path is None or log_risk is None:
            worst_risk = 0.0
        else:
            worst_risk = math.exp(log_risk)
        if worst_risk <= R_max + tol:
            best_solution = {
                "status": "Optimal",
                "selected_cms": [
                    cm.id for cm in catalog.items if x_vals[cm.id] > 0.5
                ],
                "x_values": x_vals,
                "total_cost": sum(
                    cm.cost * x_vals[cm.id] for cm in catalog.items
                ),
                "worst_path": path,
                "worst_path_risk": worst_risk,
                "active_paths": active_paths,
            }
            break
        target = path[-1]
        const_term, coeffs = build_path_constraint_coeffs(
            path, path_edges, target, graph, catalog
        )
        prob += (
            const_term
            + pulp.lpSum(
                coeffs[cid] * x_vars[cid] for cid in coeffs.keys()
            )
            <= log_R_max
        ), f"path_constraint_{it}"
        active_paths.append(list(path))
    if best_solution is None:
        best_solution = {
            "status": "IterLimit",
            "selected_cms": [],
            "x_values": {},
            "total_cost": None,
            "worst_path": None,
            "worst_path_risk": None,
            "active_paths": active_paths,
        }
        return best_solution
    if best_solution["status"] != "Optimal" or best_solution["total_cost"] is None:
        return best_solution
    cost_star = float(best_solution["total_cost"])
    lex_config = OptimizationConfig(risk_threshold=None, budget=cost_star)
    lex_input = ModelInput(graph=graph, catalog=catalog, config=lex_config)
    refined = solve_min_risk_given_budget(
        lex_input,
        iter_max=iter_max,
        tol=tol,
    )
    return refined

def solve_min_risk_given_budget(
    model_input: ModelInput,
    iter_max: int = 50,
    tol: float = 1e-6,
) -> Dict[str, object]:
    graph = model_input.graph
    catalog = model_input.catalog
    config = model_input.config
    if config.budget is None:
        raise ValueError("budget is not set in OptimizationConfig")
    budget = config.budget
    prob = pulp.LpProblem("MinRiskGivenBudget", pulp.LpMinimize)
    x_vars: Dict[str, pulp.LpVariable] = {
        cm.id: pulp.LpVariable(f"x_{cm.id}", 0, 1, cat="Binary")
        for cm in catalog.items
    }
    z_var = pulp.LpVariable("z", lowBound=1e-12, upBound=None, cat="Continuous")
    prob += z_var, "MinLogRisk"
    prob += (
        pulp.lpSum(cm.cost * x_vars[cm.id] for cm in catalog.items) <= budget,
        "BudgetConstraint",
    )
    active_paths: List[List[NodeId]] = []
    best_solution: Optional[Dict[str, object]] = None
    risk_cap: Optional[float] = None
    for it in range(iter_max):
        prob.solve(pulp.PULP_CBC_CMD(msg=False))
        if pulp.LpStatus[prob.status] != "Optimal":
            best_solution = {
                "status": pulp.LpStatus[prob.status],
                "selected_cms": [],
                "x_values": {},
                "total_cost": None,
                "worst_path": None,
                "worst_path_risk": None,
                "active_paths": active_paths,
            }
            break
        x_vals: Dict[str, float] = {
            cm.id: x_vars[cm.id].value() or 0.0 for cm in catalog.items
        }
        log_p, log_I = compute_log_p_and_log_I(graph, catalog, x_vals)
        path, path_edges, log_risk = attacker_best_response(graph, log_p, log_I)
        if path is None or log_risk is None:
            worst_risk = 0.0
            worst_log_risk = math.log(1e-12)
        else:
            worst_risk = math.exp(log_risk)
            worst_log_risk = log_risk
        z_val = z_var.value()
        if z_val is not None and z_val + tol >= worst_log_risk:
            best_solution = {
                "status": "Optimal",
                "selected_cms": [
                    cm.id for cm in catalog.items if x_vals[cm.id] > 0.5
                ],
                "x_values": x_vals,
                "total_cost": sum(
                    cm.cost * x_vals[cm.id] for cm in catalog.items
                ),
                "worst_path": path,
                "worst_path_risk": worst_risk,
                "active_paths": active_paths,
            }
            risk_cap = worst_risk
            break
        target = path[-1]
        const_term, coeffs = build_path_constraint_coeffs(
            path, path_edges, target, graph, catalog
        )
        prob += (
            z_var
            >= const_term
            + pulp.lpSum(coeffs[cid] * x_vars[cid] for cid in coeffs.keys())
        ), f"path_constraint_{it}"
        active_paths.append(list(path))
    if best_solution is None:
        best_solution = {
            "status": "IterLimit",
            "selected_cms": [],
            "x_values": {},
            "total_cost": None,
            "worst_path": None,
            "worst_path_risk": None,
            "active_paths": active_paths,
        }
        return best_solution
    if best_solution["status"] != "Optimal" or risk_cap is None:
        return best_solution
    refined = _solve_min_cost_given_risk_cap_and_budget(
        graph=graph,
        catalog=catalog,
        budget=budget,
        risk_cap=risk_cap,
        iter_max=iter_max,
        tol=tol,
    )
    return refined