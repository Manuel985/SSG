# STAR-OPT — Stackelberg-based Threat Analysis & Risk Optimization

**STAR-OPT** is a Stackelberg-based framework for attacker-aware cyber risk assessment and defensive optimization.  
It models adversarial behavior over a multi-stage attack graph and computes the optimal set of countermeasures under:

- **Risk threshold constraint** → minimize cost  
- **Budget constraint** → minimize residual risk  

The attacker is modeled as a rational best-response agent, and countermeasures modify likelihoods and impacts across the graph.

---

## 📁 Project Structure

### `utilities.py`
Core data models:  
- `AttackGraph` (nodes, edges, probabilities, impacts)  
- `Countermeasure` and `CountermeasureCatalog`  
- `OptimizationConfig` and `ModelInput`  

### `staropt.py`
Optimization engine:  
- Computes updated log-probabilities and impacts  
- Determines attacker best-response path  
- MILP-based solvers for:  
  - minimal cost given risk threshold  
  - minimal residual risk given budget  

### `input.py`
Full case study setup:  
- Builds attack graph & countermeasure catalog  
- Computes baseline attacker strategy  
- Runs both optimization modes  
- Prints optimal defensive strategies

---

## ▶️ How to Run

```bash
pip install pulp
python input.py
