"""
    Classifiers.
"""

from abc import ABC, abstractmethod
from binascii import hexlify
from datetime import datetime, timedelta
from enum import Enum

import ahocorasick
import pandas
from fet.pstats import extract_features, feature_cols, swap_directions

from bota.anomaly import SimpleExpSmoothing
from bota.filter import IPListFilter


def flow_reason(data):
    """Base reason for flow-related detections.

    Includes:

    - time_first
    - time_last
    - dst_ip
    - src_ip
    - dst_port
    - src_port
    - protocol

    Args:
        data (dict): Received message's data.

    Returns:
        dict: Reason dictionary.
    """
    reason_keys = [
        "time_first",
        "time_last",
        "dst_ip",
        "src_ip",
        "dst_port",
        "src_port",
        "protocol",
    ]

    return {k: data[k] for k in reason_keys}


class Classifier(ABC):
    """Base classifier class.

    Attributes:
        positive (bool): Positiveness of the classification decision.
        reason (dict): Classification explanation.
    """

    def __init__(self):
        self.positive = False
        self.reason = {}

    @abstractmethod
    def on_message(self, message):
        """Abstract on_message method.

        Receives message and should process according to the
        classifier's purpose.

        Args:
            message (dict): Message including message type and data.

        Raises:
            NotImplementedError: Abstract method.
        """
        raise NotImplementedError

    def sync(self, time_new):
        """Synchronize time within the classifier.

        Empty implementation in the base class. Derived classes
        should implement their own sync function based on their needs.

        Args:
            time_new (datetime.datetime): Synced time.
        """
        pass

    def flush(self):
        """Reset classification decision."""
        self.positive = False
        self.reason = {}


class DHTClassifier(Classifier):
    """DHT classifier.

    Consumes idpcontent messages and detects
    BitTorrent DHT data prefix.
    """

    #: DHT prefix.
    prefix = hexlify(b"d1:ad2:id20:").decode()

    def on_message(self, message):
        """DHT classifier message processing.

        Records the first positive reason (flow) with
        DHT prefix in idp_content.

        Args:
            message (dict): Message with idpcontent type data.
        """
        if self.positive:
            return

        content = message["data"]["idp_content"]

        if content.startswith(self.prefix):
            self.positive = True
            self.reason = flow_reason(message["data"])


class StratumClassifier(Classifier):
    """Stratum classifier.

    Consumes idpcontent messages and is able to detect
    Stratum content by implementing a set of boolean
    AND pattern rules.
    """

    #: Matching patterns.
    patterns = {
        0: b'"id":',
        1: b'"jsonrpc":',
        2: b'"method":',
        3: b'"params":',
        4: b'"login"',
        5: b'"job"',
    }

    #: Boolean AND patterns rules.
    rules = {"stratum_login": {0, 1, 2, 3, 4}, "stratum_job": {1, 2, 3, 5}}

    def __init__(self):
        super().__init__()

        self.automaton = ahocorasick.Automaton()

        for i, p in self.patterns.items():
            self.automaton.add_word(hexlify(p).decode(), i)

        self.automaton.make_automaton()

    def on_message(self, message):
        """Stratum classifier message processing.

        Records the first positive reason (flow) matching
        any of class rules.

        Args:
            message (dict): Message with idpcontent type data.
        """
        if self.positive:
            return

        content = message["data"]["idp_content"]

        matches = set([x[1] for x in self.automaton.iter(content)])

        for name, rule in self.rules.items():
            if rule.issubset(matches):
                self.positive = True
                self.reason = flow_reason(message["data"])
                self.reason["rule"] = name


class TorClassifier(Classifier):
    """Tor classifier.

    Consumes basic messages and detects Tor relays present
    in already initialized relays_filter.
    """

    #: IP list filter updated with prepared Tor relays.
    relays_filter = IPListFilter([])

    def on_message(self, message):
        """Tor classifier message processing.

        Records the first flow with either the source or the destination
        IP address present in the list of Tor relays.

        Args:
            message (dict): Message with basic type data.
        """
        if self.positive:
            return

        # prefilter
        if message["data"]["packets"] + message["data"]["packets_rev"] < 3:
            return

        dst_ip = message["data"]["dst_ip"]
        src_ip = message["data"]["src_ip"]

        if self.relays_filter.apply(dst_ip) or self.relays_filter.apply(src_ip):
            self.positive = True
            self.reason = flow_reason(message["data"])

    @classmethod
    def update_relays(cls, relays):
        """Update global list of relays for the classifier.

        Args:
            relays (list): List of string represented IP addresses.
        """
        cls.relays_filter = IPListFilter(relays)


cnc_removed_cols = ["bytes_rev_rate", "bytes_total_rate"]


class CNCClassifier(Classifier):
    """CNC traffic classifier.

    Consumes pstats messages, extracts features and evaluates
    message instance through pre-fitted machine learning
    classifier.
    """

    #: CNC classification model.
    model = None

    #: DataFrame columns.
    cols = [x for x in feature_cols if x not in cnc_removed_cols]

    def on_message(self, message):
        """CNC classifier message processing.

        Records the first positive flow predict as cnc traffic by
        the underlying machine learning classifier. Flows with fewer
        packets than 3 or flows shorted than 30 seconds are filtered out.

        Args:
            message (dict): Message with pstats type data.
        """
        if self.positive:
            return

        # prefilter
        if message["data"]["packets"] + message["data"]["packets_rev"] < 3:
            return

        if message["data"]["ppi_pkt_times"] == "[]":
            return

        df = pandas.DataFrame(message["data"], index=[0])

        # swap directions
        if message["direction_role"] == "destination":
            swap_directions(df, [True], inplace=True)

        extract_features(df, inplace=True, min_packets=3)

        # consider only flows longer than 50 seconds
        duration = df.iloc[0]["duration"]
        if duration < 50:
            return

        if self.model.predict(df[self.cols].iloc[0:1]) == ["cnc"]:
            proba = self.model.predict_proba(df[self.cols].iloc[0:1])
            self.positive = True
            self.reason = flow_reason(message["data"])
            self.reason["probability"] = round(proba[0][1], 6)

    @classmethod
    def update_model(cls, model):
        """Update global model for the classifier.

        Args:
            model (object): Object with a predict method.
        """
        cls.model = model


class AnomalyAgg(Enum):
    """Aggregation types enumeration."""

    SUM = 1
    UNIQUE = 2


class AnomalyClassifier(Classifier):
    """Time series anomaly detection classifier.

    Consumes basic messages where the endpoint acts as
    a source of the communication. Uses simple exponential
    smoothing and base minimal thresholds to detect
    anomalies.

    Args:
        field (string): Data field to monitor (e.g. bytes).
        agg (string): Aggregate function (sum or unique).
        threshold (int): Minimum threshold to trigger anomaly.

    Raises:
        ValueError: Invalid aggregate function.
    """

    #: Aggregation window interval in seconds.
    interval = 60

    #: Time format present in the data.
    time_fmt = "%Y-%m-%dT%H:%M:%S.%f"

    def __init__(self, field, agg, threshold):
        self.threshold = threshold
        self.field = field

        self.time_next = None

        if agg == "sum":
            self.kind = AnomalyAgg.SUM
        elif agg == "unique":
            self.kind = AnomalyAgg.UNIQUE
        else:
            raise ValueError(f"unsupported {agg}")

        self._reset()

        self.smoothing = SimpleExpSmoothing(0.1)
        self.anomalies = {"prediction": 0, "threshold": 0}
        self.windows = 0
        self.max = 0

    @property
    def positive(self):
        """Positiveness of the classification decision.

        Evaluated as the presence of at least one statistical
        anomaly and at least three threshold anomalies.
        """
        if self.anomalies["prediction"] > 0 and self.anomalies["threshold"] > 1:
            return True
        else:
            return False

    @property
    def reason(self):
        """Classification explanation - dict with field and its maximum value."""
        if self.positive:
            return {
                "max": self.max,
                "over_prediction": self.anomalies["prediction"],
                "over_threshold": self.anomalies["threshold"],
            }
        else:
            return {}

    def on_message(self, message):
        """Anomaly classifier message processing.

        Expects outgoing flows (endpoint is a source of the communication).
        Aggregates values within class-specific interval.

        Args:
            message (dict): Message with basic data.
        """
        time_last = datetime.strptime(message["data"]["time_last"], self.time_fmt)

        if time_last < self.time_next:
            self._aggregate(message["data"])
        else:
            self._process_window(time_last)
            self._reset()
            self._aggregate(message["data"])

    def sync(self, time_new):
        """Overridden implementation of the synchronization procedure.

        Args:
            time_new (datetime.datetime): Synced time.
        """
        if self.time_next and self.time_next < time_new:
            self._process_window(time_new)
            self._reset()

        self.time_next = time_new + timedelta(seconds=self.interval)

    def flush(self):
        """Overridden classification decision reset."""
        self.max = 0
        self.anomalies = {"prediction": 0, "threshold": 0}

    def _reset(self):
        if self.kind == AnomalyAgg.SUM:
            self.current = 0
        if self.kind == AnomalyAgg.UNIQUE:
            self.current = set()

    def _aggregate(self, data):
        if self.kind == AnomalyAgg.SUM:
            self.current += data[self.field]
        elif self.kind == AnomalyAgg.UNIQUE:
            self.current.add(data[self.field])

    def _process_window(self, time_last):
        self.windows += 1

        if self.kind == AnomalyAgg.SUM:
            current = self.current
        elif self.kind == AnomalyAgg.UNIQUE:
            current = len(self.current)

        # prediction-based anomaly
        if self.windows > 2:
            pred_upper = self.smoothing.pred + 5 * self.smoothing.std_e
            if current > pred_upper:
                self.anomalies["prediction"] += 1

        # threshold-based anomaly
        if current > self.threshold:
            self.anomalies["threshold"] += 1

        # update maximum for explanation
        self.max = max(self.max, current)

        # smooth
        self.smoothing.update(current)

        # smooth missing intervals
        missing = (time_last - self.time_next).seconds // self.interval
        for _ in range(missing):
            self.windows += 1
            self.smoothing.update(0)

        self.time_next += timedelta(seconds=self.interval) * (missing + 1)
