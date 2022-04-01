"""
    Time series modelling.
"""

import numpy


class Welford:
    """Welford algorithm.

    Online computation of mean and variance.
    See: https://www.johndcook.com/blog/standard_deviation
    """

    def __init__(self):
        self.n = 0
        self.mean = 0
        self.S = 0

    def update(self, x):
        """Update model with a new observation.

        Args:
            x (float): Observation.
        """
        self.n += 1

        if self.n == 1:
            self.mean = x
            self.S = 0
            return

        new_mean = self.mean + (x - self.mean) / self.n
        self.S = self.S + (x - self.mean) * (x - new_mean)
        self.mean = new_mean

    @property
    def var(self):
        """Estimated variance."""
        if self.n <= 1:
            return 0
        return self.S / (self.n)

    @property
    def std(self):
        """Estimated standard deviation."""
        return numpy.sqrt(self.var)


class SimpleExpSmoothing:
    """Brown's simple exponential smoothing.

    Args:
        alpha (float): Smoothing argument.

    Raises:
        ValueError: Invalid alpha (must be in <0, 1>).
    """

    def __init__(self, alpha):
        if not 0 <= alpha <= 1:
            raise ValueError(f"{alpha} not in <0, 1>")

        self.alpha = alpha
        self.y = None
        self.welford = Welford()

    def update(self, x):
        """Update model with a new observation.

        Args:
            x (float): Observation.
        """
        if not self.y:
            self.y = x
            return

        self.welford.update(x - self.y)
        self.y = self.alpha * x + (1 - self.alpha) * self.y

    @property
    def pred(self):
        """Prediction for the next time."""
        return self.y

    @property
    def std_e(self):
        """Standard deviation of prediction errors."""
        return self.welford.std
