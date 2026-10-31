r"""Bayesian compromise model: P(asset compromised | exposure, exploitation, telemetry).

A small, fully explainable Bayesian network:

    exposed (E) --+
    exploited-in-the-wild (X) --+--> attacked (A) --> compromised (C) --> beacon to known C2 (B)
    internet-facing (Z) --------+                                    \-> host anomaly (N)

Prior P(A | E, X, Z) and P(C | A) come from config/scoring.json ("bayes"); telemetry enters as likelihood
ratios P(obs | C) / P(obs | not C). Unobserved telemetry is left out (absence of monitoring is not evidence).
The posterior replaces hard-coded "compromise" overrides; every factor is reported so an analyst can audit it.
"""

from __future__ import annotations


def posterior(cfg: dict, *, exposed: bool, exploited: bool, internet: bool,
              beacon: bool | None = None, anomaly: bool | None = None) -> dict:
    b = cfg["bayes"]
    if not exposed:
        p_attack = b["p_attack_not_exposed"]
    else:
        key = f"p_attack_{'exploited' if exploited else 'not_exploited'}_{'internet' if internet else 'internal'}"
        p_attack = b[key]
    prior = p_attack * b["p_compromise_given_attack"] + (1 - p_attack) * b["p_compromise_other_vector"]
    odds = prior / (1 - prior)
    factors = [{"factor": "prior from exposure, exploitation and reachability", "value": round(prior, 4),
                "detail": f"exposed={exposed}, exploited in the wild={exploited}, internet-facing={internet}"}]
    for name, observed, (p_true, p_false) in (("beacon to known C2", beacon, b["beacon_tpr_fpr"]),
                                              ("host behaviour anomaly", anomaly, b["anomaly_tpr_fpr"])):
        if observed is None:
            continue
        lr = (p_true / p_false) if observed else ((1 - p_true) / (1 - p_false))
        odds *= lr
        factors.append({"factor": name, "value": round(lr, 2),
                        "detail": f"{'observed' if observed else 'monitored, not observed'}: likelihood ratio x{lr:.2f}"})
    p = odds / (1 + odds)
    decision = ("compromised" if p >= b["threshold_compromise"] else
                "hunt" if p >= b["threshold_hunt"] else "no evidence of compromise")
    return {"p_compromise": round(p, 4), "prior": round(prior, 4), "factors": factors, "decision": decision}
