"""
    Endpoint handling.
"""

from abc import ABC, abstractmethod

import numpy

from bota.classifier import (
    AnomalyClassifier,
    CNCClassifier,
    DHTClassifier,
    StratumClassifier,
    TorClassifier,
)


class Endpoint(ABC):
    """Endpoint base class.

    Args:
        config (dict): Anomaly min thresholds config.
    """

    #: Keys for anomaly related classifiers.
    anomaly_k = ["bytes", "packets", "dst_ip", "dst_port"]

    def __init__(self, config):
        anomaly = config["anomaly"]
        self.classifiers = {
            "dht": DHTClassifier(),
            "stratum": StratumClassifier(),
            "tor": TorClassifier(),
            "cnc": CNCClassifier(),
            "bytes": AnomalyClassifier("bytes", "sum", anomaly["bytes"]),
            "packets": AnomalyClassifier("packets", "sum", anomaly["packets"]),
            "dst_ip": AnomalyClassifier("dst_ip", "unique", anomaly["dst_ip"]),
            "dst_port": AnomalyClassifier("dst_port", "unique", anomaly["dst_port"]),
        }

        if "prior" in config:
            prior = config["prior"]
            for k in self.anomaly_k:
                for v in numpy.random.poisson(prior[k], size=300):
                    self.classifiers[k].smoothing.update(v)
                self.classifiers[k].windows = 300

    @abstractmethod
    def direction_role(self, data):
        """Abstract direction_role method.

        Args:
            data (dict): Message's data.

        Raises:
            NotImplementedError: Abstract method.
        """
        raise NotImplementedError

    def on_message(self, message):
        """Endpoint's message processing.

        Args:
            message (dict): Message having a type and UniRec data.
        """
        direction_role = self.direction_role(message["data"])
        message["direction_role"] = direction_role

        if message["type"] == "basic":
            self.classifiers["tor"].on_message(message)

            # anomaly only outgoing
            if direction_role == "source":
                for k in self.anomaly_k:
                    self.classifiers[k].on_message(message)

        elif message["type"] == "pstats":
            self.classifiers["cnc"].on_message(message)

        elif message["type"] == "idpcontent":
            self.classifiers["dht"].on_message(message)
            self.classifiers["stratum"].on_message(message)

    def sync(self, time_new):
        """Time synchronisation. Pass the timestamp to underlying classifiers.

        Args:
            time_new (datetime.datetime): Synced time.
        """
        for v in self.classifiers.values():
            v.sync(time_new)

    def flush(self):
        """Detection decision reset. Pass to underlying classifiers."""
        for v in self.classifiers.values():
            v.flush()

    def verdict(self):
        """Decide endpoint's maliciousness.

        Returns:
            tuple: Tuple containing:

            - positive (bool): Positivness of the decision.
            - reason (dict): Dictionary of all the recorded reasons.
        """
        positives = {}
        reasons = {}

        for k, v in self.classifiers.items():
            positives[k] = v.positive
            reasons[k] = v.reason

        positive = any(
            [
                positives["cnc"] and (any(positives[k] for k in self.anomaly_k)),
                positives["tor"] and (any(positives[k] for k in self.anomaly_k)),
                positives["dht"] and positives["stratum"],
            ]
        )

        reason = {k: v for k, v in reasons.items() if v != {}}

        return positive, reason


class IPEndpoint(Endpoint):
    """Endpoint addressable via IP address.

    Args:
        ip (string): String representation of an IP address.
        config (dict): Anomaly min thresholds config.
    """

    def __init__(self, ip, config):
        super().__init__(config)
        self.ip = ip

    def direction_role(self, data):
        """IP addresses specific direction_role.

        Args:
            data (dict): Message's data.

        Returns:
            str: Direction role.
        """
        if data["src_ip"] == self.ip:
            return "source"
        else:
            return "destination"


class MACEndpoint(Endpoint):
    """Endpoint addressable via MAC address.

    Args:
        mac (string): String representation of a MAC address.
        config (dict): Anomaly min thresholds config.
    """

    def __init__(self, mac, config):
        super().__init__(config)
        self.mac = mac

    def direction_role(self, data):
        """MAC addresses specific direction_role.

        Args:
            data (dict): Message's data.

        Returns:
            str: Direction role.
        """
        if data["src_mac"] == self.mac:
            return "source"
        else:
            return "destination"
