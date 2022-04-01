"""
    Monitoring entrypoint.
"""

import json
import os
import pickle
import uuid
from datetime import datetime, timedelta

from bota.classifier import CNCClassifier, TorClassifier
from bota.endpoint import IPEndpoint, MACEndpoint
from bota.filter import FilterBy, IPListFilter, IPRangeFilter, MACListFilter


class Monitor:
    """Monitor of endpoints.

    Monitor handles incoming messages, time binning and reporting
    of detected malicious devices.

    Args:
        config (dict): BOTA config.

    Raises:
        ValueError: Invalid filter value.
    """

    #: Evaluation interval in seconds.
    interval = 500

    #: Time format present in the data.
    time_fmt = "%Y-%m-%dT%H:%M:%S.%f"

    def __init__(self, config):
        self.config = config
        self.endpoints = {}

        filter_type = config["filter"]["type"]
        filter_value = config["filter"]["value"]

        if filter_type == "mac_list":
            self.filter = MACListFilter(filter_value)
        elif filter_type == "ip_list":
            self.filter = IPListFilter(filter_value)
        elif filter_type == "ip_range":
            self.filter = IPRangeFilter(filter_value)
        else:
            raise ValueError("invalid filter type")

        self.time_start = None
        self.time_next = None
        self.time_last = None
        self.eof_count = 0
        self.end = False

        # init global CNC model
        with open(os.path.join(config["model"]["cnc"]), "rb") as f:
            CNCClassifier.update_model(pickle.load(f))

        # init global Tor model
        relays = []
        with open(os.path.join(config["model"]["tor"])) as f:
            for line in f:
                relays.append(line.strip())
            TorClassifier.update_relays(relays)

    def on_message(self, message):
        """Monitor's message processing.

        In case of new window, processes and reports endpoints'
        results. Otherwise, filters and passes messages to
        managed endpoints.

        Args:
            message (dict): Message having a type and UniRec data.
        """
        if message["type"] == "eof":
            self.eof_count += 1
            if self.eof_count == 3:
                if self.time_last:
                    self._process_window(self.time_last)
                self.end = True
            return

        self.time_last = datetime.strptime(
            message["data"]["time_last"], self.time_fmt
        )

        if not self.time_start:
            self._set_time(self.time_last)
        elif self.time_last > self.time_next:
            # new time window
            self._process_window(self.time_last)
            self._set_time(self.time_next)

        endpoint_id = None

        if self.filter.filter_by == FilterBy.IP:
            src_ip = message["data"]["src_ip"]
            dst_ip = message["data"]["dst_ip"]

            if self.filter.apply(src_ip):
                endpoint_id = src_ip
            elif self.filter.apply(dst_ip):
                endpoint_id = dst_ip

        elif self.filter.filter_by == FilterBy.MAC:
            src_mac = message["data"]["src_mac"]
            dst_mac = message["data"]["dst_mac"]

            if self.filter.apply(src_mac):
                endpoint_id = src_mac
            elif self.filter.apply(dst_mac):
                endpoint_id = dst_mac

        # not in monitored endpoints
        if not endpoint_id:
            return

        # first time seeing endpoint traffic
        if endpoint_id not in self.endpoints:
            self._register_endpoint(endpoint_id)
            self.endpoints[endpoint_id].sync(self.time_start)

        self.endpoints[endpoint_id].on_message(message)

    def _set_time(self, time_start):
        self.time_start = time_start
        self.time_next = time_start + timedelta(seconds=self.interval)

    def _register_endpoint(self, endpoint_id):
        if self.filter.filter_by == FilterBy.IP:
            self.endpoints[endpoint_id] = IPEndpoint(
                endpoint_id, self.config["model"]
            )
        elif self.filter.filter_by == FilterBy.MAC:
            self.endpoints[endpoint_id] = MACEndpoint(
                endpoint_id, self.config["model"]
            )

    def _process_window(self, time_last):
        verdict = {}

        for k, v in self.endpoints.items():
            v.sync(time_last)
            positive, reason = v.verdict()
            v.flush()
            verdict[k] = {"positive": positive, "reason": reason}

        self._report_detail(verdict)
        self._report_idea(verdict)

        return verdict

    def _report_detail(self, verdict):
        with open(self.config["output"]["detail"], "a+") as f:
            for e, v in verdict.items():
                if v["reason"] == {}:
                    continue

                detail = {
                    "endpoint": e,
                    "time_start": self.time_start.strftime(self.time_fmt),
                    "time_end": self.time_next.strftime(self.time_fmt),
                    "alert": v["positive"],
                    "reason": v["reason"],
                }

                json.dump(detail, f)
                f.write("\n")

    def _report_idea(self, verdict):
        time_fmt = "%Y-%m-%dT%H:%M:%SZ"
        with open(self.config["output"]["idea"], "a+") as f:
            for e, v in verdict.items():
                if not v["positive"]:
                    continue

                if self.filter.filter_by == FilterBy.IP:
                    version = 6 if ":" in e else 4
                    source = [{"Type": ["Botnet"], f"IP{version}": [e]}]
                else:
                    source = [{"Type": ["Botnet"], f"MAC": [e]}]

                idea = {
                    "Format": "IDEA0",
                    "ID": f"{uuid.uuid4()}",
                    "DetectTime": f"{self.time_last.strftime(time_fmt)}",
                    "WinStartTime": f"{self.time_start.strftime(time_fmt)}",
                    "WinEndTime": f"{self.time_next.strftime(time_fmt)}",
                    "Category": ["Intrusion.Botnet"],
                    "Description": "IoT Botnet",
                    "Source": source,
                }

                json.dump(idea, f)
                f.write("\n")
