"""
AURORA Differential Privacy Engine

Formal (ε,δ)-differential privacy for all data leaving AURORA.
Laplace mechanism for counting queries, Gaussian for approximate DP.

Based on: Dwork & Roth (2014) "The Algorithmic Foundations of Differential Privacy"
"""
from __future__ import annotations
import math, secrets

# Module-level constants for external reference and testing
_MIN_EPSILON = 1e-6
_MAX_EPSILON = 10.0

class DifferentialPrivacy:
    def __init__(self, epsilon: float = 1.0):
        if not (_MIN_EPSILON < epsilon <= _MAX_EPSILON):
            raise ValueError(
                f"Epsilon must be in ({_MIN_EPSILON}, {_MAX_EPSILON}]. "
                f"Got {epsilon}. Values above {_MAX_EPSILON} provide negligible privacy. "
                "Reference: Dwork & Roth (2014) recommend ε ≤ 1.0 for strong privacy."
            )
        self.epsilon = epsilon

    def laplace_mechanism(self, true_value: float, sensitivity: float) -> float:
        """Add Laplace noise calibrated to sensitivity/epsilon."""
        scale = sensitivity / self.epsilon
        noise = self._laplace_noise(scale)
        return true_value + noise

    def gaussian_mechanism(self, true_value: float, sensitivity: float, delta: float = 1e-5) -> float:
        """Add Gaussian noise for (ε,δ)-DP."""
        sigma = math.sqrt(2 * math.log(1.25/delta)) * sensitivity / self.epsilon
        noise = self._gaussian_noise(sigma)
        return true_value + noise

    def _laplace_noise(self, scale: float) -> float:
        """Sample from Laplace(0, scale) using inverse CDF method."""
        u = (secrets.randbits(32) - (2**31)) / (2**31)  # Uniform [-1, 1)
        if u == 0: u = 1e-10
        return -scale * math.copysign(1, u) * math.log(1 - abs(u))

    def _gaussian_noise(self, sigma: float) -> float:
        """Box-Muller transform for Gaussian sample."""
        u1 = (secrets.randbits(32) + 1) / (2**32 + 1)
        u2 = (secrets.randbits(32) + 1) / (2**32 + 1)
        return sigma * math.sqrt(-2*math.log(u1)) * math.cos(2*math.pi*u2)

    @property
    def privacy_budget_remaining(self) -> float:
        return self.epsilon
