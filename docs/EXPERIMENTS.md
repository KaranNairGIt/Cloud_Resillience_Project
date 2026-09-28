# Experiments: baseline comparison and fault-tolerance boundary

Implements PDF Sections 7 (step 5), 9 and 10. All values are **modeled ticks on synthetic evidence**, not wall-clock measurements from a deployed cluster.

## Commands

```powershell
python -m resilience.cli experiment --repeats 3   # distributed vs centralized, five scenarios
python -m resilience.cli boundary                 # sweep compromised nodes k for n = 4, 7, 10
python -m resilience.cli boundary --sizes 4       # just the PDF's 4-node case
```

## Centralized baseline (`resilience/baseline.py`)

An executed single controller: it verifies signed sensor evidence and contains on any one verified anomaly at or above the evidence threshold. It has no quorum, type-diversity rule, trust model or independent validation. Its controller can be put in `block`, `silent`, `false-accuse` or `rubber-stamp` mode. (This replaces the earlier hard-coded table of illustrative values.)

## Metrics reported

Time to detect / isolate / recover, false-isolation rate, missed-containment rate, recovery success, false reintegration, availability, and trust-recovery time (distributed only; the baseline has no trust model). `false_isolation` uses scenario ground truth (`false-evidence` and `healthy-window` targets are actually healthy).

## Boundary sweep results (n = 4, f = 1)

| Attack by k compromised nodes | Correct through | First failure | Reading |
|---|---|---|---|
| `silent` (withhold votes on a real attack) | k = 1 | k = 2 = f+1 | liveness breaks exactly at theory |
| `block` (mask evidence + refuse to lead) | k = 1 | k = 2 = f+1 | same |
| `false-accuse` (collude to isolate a healthy service) | k = 2 | k = 3 = 2f+1 | safety holds beyond f because the evidence gate needs 2f+1 distinct reporters |

The pattern is the same for n = 7 and n = 10 (liveness fails at f+1, false isolation only at 2f+1). Nothing failed at k <= f, which is the property the design claims.

Compromising the **centralized controller** (k = 1 of 1) broke it under every attack: it falsely isolated a healthy service, or failed to contain a real attack. With a tainted restore, a `rubber-stamp` controller reintegrated the still-compromised workload (false reintegration) while the distributed run kept it quarantined.

Single-sensor scenario results from `experiment`: the distributed model has 0% false isolation everywhere; the centralized baseline has 100% on `false-evidence` and 100% missed containment on `block-vote`. The distributed model has **100% missed containment on `two-compromised`** (beyond f=1). That is the honest limit the PDF asks to be reported, not hidden.

## Limitations

- Byzantine replicas only withhold or refuse. Equivocation is not modeled beyond the assumption that k >= 2f+1 attackers can commit on their own (PBFT gives no guarantee beyond f).
- The compromised set always includes the initial primary (worst case for liveness).
- Not yet run on a real cluster; see `docs/KUBERNETES.md`.
