"""Small, dependency-free statistics used by the study analysis.

Everything is deterministic given the seed.  Percentiles use linear
interpolation between order statistics (NumPy ``method='linear'``, i.e. Hyndman-
Fan type 7). Historical outputs using a different estimator should not be
compared directly with the current analysis.
"""
from __future__ import annotations

import math
import random
from typing import Dict, List, Sequence, Tuple


def percentile(xs: Sequence[float], p: float) -> float:
    if not xs:
        return float("nan")
    s = sorted(xs)
    k = (len(s) - 1) * p / 100.0
    lo = math.floor(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def wilson_ci(successes: int, n: int, z: float = 1.959964) -> Tuple[float, float]:
    """95% Wilson score interval; valid at 0 and n (unlike the Wald interval)."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def rate(successes: int, n: int) -> Dict[str, object]:
    lo, hi = wilson_ci(successes, n)
    return {"k": successes, "n": n, "rate": (successes / n) if n else None,
            "ci95": [lo, hi] if n else None}


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from discordant counts b (A only) and c (B only)."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def paired_binary(a: Sequence[bool], b: Sequence[bool]) -> Dict[str, object]:
    """Compare two configurations on the SAME scenarios (outcome = True/False)."""
    assert len(a) == len(b), "paired samples must be the same length"
    only_a = sum(1 for x, y in zip(a, b) if x and not y)
    only_b = sum(1 for x, y in zip(a, b) if y and not x)
    return {"n": len(a), "a_only": only_a, "b_only": only_b, "diff": (sum(a) - sum(b)) / len(a) if a else None,
            "mcnemar_exact_p": mcnemar_exact(only_a, only_b)}


def paired_bootstrap_median_diff(a: Sequence[float], b: Sequence[float], iters: int = 5000,
                                 seed: int = 7) -> Dict[str, object]:
    """Bootstrap CI for median(a)-median(b), resampling SCENARIOS (clusters) with
    replacement so that repeated observations of one scenario are not treated as
    independent.  ``a[i]`` and ``b[i]`` must be the per-scenario summary for scenario i."""
    assert len(a) == len(b) and a
    rnd = random.Random(seed)
    n = len(a)
    stats: List[float] = []
    for _ in range(iters):
        idx = [rnd.randrange(n) for _ in range(n)]
        stats.append(percentile([a[i] for i in idx], 50) - percentile([b[i] for i in idx], 50))
    stats.sort()
    return {"point": percentile(a, 50) - percentile(b, 50),
            "ci95": [stats[int(0.025 * iters)], stats[int(0.975 * iters) - 1]], "iters": iters, "seed": seed}
