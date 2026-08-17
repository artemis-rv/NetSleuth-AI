"""
normalization.py
----------------
M2 Phase 4 — Numeric normalization strategies.

Provides deterministic, fitted-on-training-data scaling for M2 feature vectors.
All scalers store their fitted parameters as plain Python floats for serialization.

RULES:
  - Scalers must ONLY be fitted on training data.
  - transform() applies stored parameters — no re-fitting.
  - All numeric operations must be deterministic.
  - NaN / None inputs are handled as missing: returned as 0.0 (the safe default
    for a normalized feature vector with an explicit 'present' flag).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MinMaxScaler:
    """Scales features to [0, 1] range based on training min/max.

    Applies the transform:
        x_scaled = (x - min) / (max - min + epsilon)

    Attributes:
        min_val: Minimum value seen during fit.
        max_val: Maximum value seen during fit.
        epsilon: Small constant to prevent division by zero.
    """
    min_val: float = 0.0
    max_val: float = 1.0
    epsilon: float = 1e-10
    fitted: bool = False

    def fit(self, values: list[float]) -> "MinMaxScaler":
        finite = [v for v in values if v is not None and math.isfinite(v)]
        if not finite:
            return self
        self.min_val = min(finite)
        self.max_val = max(finite)
        self.fitted = True
        return self

    def transform(self, value: Optional[float]) -> float:
        if value is None or not math.isfinite(value):
            return 0.0
        return (value - self.min_val) / (self.max_val - self.min_val + self.epsilon)

    def to_dict(self) -> dict:
        return {"type": "minmax", "min_val": self.min_val, "max_val": self.max_val,
                "epsilon": self.epsilon, "fitted": self.fitted}

    @classmethod
    def from_dict(cls, d: dict) -> "MinMaxScaler":
        s = cls()
        s.min_val = d["min_val"]
        s.max_val = d["max_val"]
        s.epsilon = d.get("epsilon", 1e-10)
        s.fitted = d.get("fitted", True)
        return s


@dataclass
class StandardScaler:
    """Scales features to zero mean, unit variance.

    Applies the transform:
        x_scaled = (x - mean) / (std + epsilon)

    Attributes:
        mean: Mean value seen during fit.
        std: Standard deviation seen during fit.
        epsilon: Small constant to prevent division by zero.
    """
    mean: float = 0.0
    std: float = 1.0
    epsilon: float = 1e-10
    fitted: bool = False

    def fit(self, values: list[float]) -> "StandardScaler":
        finite = [v for v in values if v is not None and math.isfinite(v)]
        if not finite:
            return self
        n = len(finite)
        self.mean = sum(finite) / n
        variance = sum((v - self.mean) ** 2 for v in finite) / n
        self.std = math.sqrt(variance)
        self.fitted = True
        return self

    def transform(self, value: Optional[float]) -> float:
        if value is None or not math.isfinite(value):
            return 0.0
        return (value - self.mean) / (self.std + self.epsilon)

    def to_dict(self) -> dict:
        return {"type": "standard", "mean": self.mean, "std": self.std,
                "epsilon": self.epsilon, "fitted": self.fitted}

    @classmethod
    def from_dict(cls, d: dict) -> "StandardScaler":
        s = cls()
        s.mean = d["mean"]
        s.std = d["std"]
        s.epsilon = d.get("epsilon", 1e-10)
        s.fitted = d.get("fitted", True)
        return s


@dataclass
class LogScaler:
    """Log1p transform followed by MinMax scaling.

    Appropriate for heavily right-skewed quantities:
    bytes, packets, flow_counts, request_counts, domain_counts.

    The log1p(x) transform compresses large values before min/max scaling.
    """
    inner: MinMaxScaler = field(default_factory=MinMaxScaler)
    fitted: bool = False

    def fit(self, values: list[float]) -> "LogScaler":
        finite = [v for v in values if v is not None and math.isfinite(v) and v >= 0]
        log_vals = [math.log1p(v) for v in finite]
        self.inner.fit(log_vals)
        self.fitted = True
        return self

    def transform(self, value: Optional[float]) -> float:
        if value is None or not math.isfinite(value) or value < 0:
            return 0.0
        return self.inner.transform(math.log1p(value))

    def to_dict(self) -> dict:
        return {"type": "log", "inner": self.inner.to_dict(), "fitted": self.fitted}

    @classmethod
    def from_dict(cls, d: dict) -> "LogScaler":
        s = cls()
        s.inner = MinMaxScaler.from_dict(d["inner"])
        s.fitted = d.get("fitted", True)
        return s


def load_scaler(d: dict):
    """Deserialize a scaler from its dict representation."""
    t = d["type"]
    if t == "minmax":
        return MinMaxScaler.from_dict(d)
    elif t == "standard":
        return StandardScaler.from_dict(d)
    elif t == "log":
        return LogScaler.from_dict(d)
    else:
        raise ValueError(f"Unknown scaler type: {t}")
