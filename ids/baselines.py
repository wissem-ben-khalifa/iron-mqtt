"""Non-ML baseline: a volumetric threshold rule on client->broker payload per window.

The simplest thing a defender would try first, and the honest yardstick for the ML IDS
in the MVP: flag a window as attack if its upstream payload bytes exceed a threshold.
The threshold is chosen on the TRAINING data only (the knee between benign and attack),
then applied unchanged to test data.
"""

from __future__ import annotations

import numpy as np

from ids.features import FEATURES

FEATURE = "payload_up"  # upstream application-layer bytes per 5 s window


class ThresholdRule:
    def __init__(self, feature: str = FEATURE):
        self.feature = feature
        self.idx = FEATURES.index(feature)
        self.threshold_: float | None = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> "ThresholdRule":
        """Pick the threshold that maximises F1 on the training set (swept over benign/attack values)."""
        values = X[:, self.idx]
        candidates = np.unique(values)
        if len(candidates) > 200:
            candidates = np.quantile(values, np.linspace(0, 1, 200))
        best_f1, best_t = -1.0, float(values.max()) + 1
        for t in candidates:
            pred = (values > t).astype(int)
            tp = int(((pred == 1) & (y == 1)).sum())
            fp = int(((pred == 1) & (y == 0)).sum())
            fn = int(((pred == 0) & (y == 1)).sum())
            f1 = tp / (tp + 0.5 * (fp + fn)) if (tp + fp + fn) else 0.0
            if f1 > best_f1:
                best_f1, best_t = f1, float(t)
        self.threshold_ = best_t
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (X[:, self.idx] > self.threshold_).astype(int)

    def score(self, X: np.ndarray) -> np.ndarray:
        """A monotone 'attack-ness' score for ROC/PR: payload over the threshold."""
        return X[:, self.idx] - (self.threshold_ or 0)
