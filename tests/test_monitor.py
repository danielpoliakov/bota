import os
from datetime import datetime

import pytest
from bota.classifier import CNCClassifier, TorClassifier
from bota.monitor import Monitor


@pytest.fixture(scope="module")
def model_config(test_directory):
    return {
        "cnc": os.path.join(test_directory, "data", "cnc.pickle"),
        "tor": os.path.join(test_directory, "data", "tor.list"),
        "anomaly": {
            "bytes": 42,
            "packets": 42,
            "dst_ip": 42,
            "dst_port": 42,
        },
    }


@pytest.fixture(scope="module")
def output_config(test_directory):
    return {
        "idea": os.path.join(test_directory, "data", "idea.json"),
        "detail": os.path.join(test_directory, "data", "detail.json"),
    }


def test_monitor_basic(model_config, output_config):
    config = {
        "filter": {
            "type": "ip_range",
            "value": "10.0.0.0/24",
        },
        "model": model_config,
        "output": output_config,
    }

    monitor = Monitor(config)

    assert monitor.time_start == None
    assert monitor.time_next == None
    assert monitor.endpoints == {}

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T15:55:00.000000",
            "src_ip": "10.0.0.10",
            "dst_ip": "1.1.1.1",
            "src_port": 42000,
            "dst_port": 53,
            "protocol": 17,
            "bytes": 100,
            "packets": 100,
        },
    }

    monitor.on_message(message)

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T15:57:01.000000",
            "src_ip": "2.2.2.2",
            "dst_ip": "10.0.0.20",
            "src_port": 443,
            "dst_port": 42000,
            "protocol": 6,
            "bytes": 100,
            "packets": 100,
        },
    }

    monitor.on_message(message)

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T15:58:01.000000",
            "src_ip": "10.0.0.30",
            "dst_ip": "3.3.3.3",
            "src_port": 42000,
            "dst_port": 80,
            "protocol": 6,
            "bytes": 100,
            "packets": 100,
        },
    }

    monitor.on_message(message)

    assert str(monitor.time_start) == "2021-03-03 15:55:00"
    assert str(monitor.time_next) == "2021-03-03 16:03:20"
    assert sorted(monitor.endpoints.keys()) == ["10.0.0.10", "10.0.0.20", "10.0.0.30"]

    t_1 = monitor.endpoints["10.0.0.10"].classifiers["bytes"].time_next
    t_2 = monitor.endpoints["10.0.0.20"].classifiers["bytes"].time_next
    t_3 = monitor.endpoints["10.0.0.30"].classifiers["bytes"].time_next

    assert str(t_1) == "2021-03-03 15:56:00"
    assert str(t_2) == "2021-03-03 15:56:00"
    assert str(t_3) == "2021-03-03 15:59:00"

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T16:03:21.000000",
            "src_ip": "10.0.0.30",
            "dst_ip": "4.4.4.4",
            "src_port": 42000,
            "dst_port": 80,
            "protocol": 6,
            "bytes": 100,
            "packets": 100,
        },
    }

    monitor.on_message(message)

    assert str(monitor.time_start) == "2021-03-03 16:03:20"
    assert str(monitor.time_next) == "2021-03-03 16:11:40"


def test_monitor_verdict(model_config, output_config):
    config = {
        "filter": {
            "type": "ip_range",
            "value": "10.0.0.0/24",
        },
        "model": model_config,
        "output": output_config,
    }

    monitor = Monitor(config)

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T16:03:21.000000",
            "src_ip": "10.0.0.10",
            "dst_ip": "1.1.1.1",
            "src_port": 42000,
            "dst_port": 80,
            "protocol": 6,
            "bytes": 100,
            "packets": 100,
        },
    }
    monitor.on_message(message)

    monitor.endpoints["10.0.0.10"].classifiers["dht"].positive = True
    monitor.endpoints["10.0.0.10"].classifiers["dht"].reason = "test"
    monitor.endpoints["10.0.0.10"].classifiers["stratum"].positive = True
    monitor.endpoints["10.0.0.10"].classifiers["stratum"].reason = "test"

    verdict = monitor._process_window(datetime.now())

    assert verdict == {
        "10.0.0.10": {"positive": True, "reason": {"dht": "test", "stratum": "test"}}
    }


def test_monitor_verdict_mac(model_config, output_config):
    config = {
        "filter": {
            "type": "mac_list",
            "value": ["11:11:11:11:11:11", "22:22:22:22:22:22"],
        },
        "model": model_config,
        "output": output_config,
    }

    monitor = Monitor(config)

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T15:55:00.000000",
            "dst_mac": "11:11:11:11:11:11",
            "src_mac": "ee:ee:ee:ee:ee:ee",
            "src_ip": "10.0.0.10",
            "dst_ip": "1.1.1.1",
            "src_port": 42000,
            "dst_port": 53,
            "protocol": 17,
            "bytes": 100,
            "packets": 100,
        },
    }
    monitor.on_message(message)

    monitor.endpoints["11:11:11:11:11:11"].classifiers["dht"].positive = True
    monitor.endpoints["11:11:11:11:11:11"].classifiers["dht"].reason = "test"
    monitor.endpoints["11:11:11:11:11:11"].classifiers["stratum"].positive = True
    monitor.endpoints["11:11:11:11:11:11"].classifiers["stratum"].reason = "test"

    verdict = monitor._process_window(datetime.now())

    assert verdict == {
        "11:11:11:11:11:11": {
            "positive": True,
            "reason": {"dht": "test", "stratum": "test"},
        }
    }


def test_monitor_ip_list(model_config, output_config):
    config = {
        "filter": {
            "type": "ip_list",
            "value": ["10.0.0.10", "10.0.0.20"],
        },
        "model": model_config,
        "output": output_config,
    }

    monitor = Monitor(config)

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T15:55:00.000000",
            "src_ip": "10.0.0.10",
            "dst_ip": "1.1.1.1",
            "src_port": 42000,
            "dst_port": 53,
            "protocol": 17,
            "bytes": 100,
            "packets": 100,
        },
    }

    monitor.on_message(message)

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T15:55:00.000000",
            "src_ip": "10.0.0.20",
            "dst_ip": "1.1.1.1",
            "src_port": 42000,
            "dst_port": 53,
            "protocol": 17,
            "bytes": 100,
            "packets": 100,
        },
    }

    monitor.on_message(message)

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T15:55:00.000000",
            "src_ip": "10.0.0.30",
            "dst_ip": "1.1.1.1",
            "src_port": 42000,
            "dst_port": 53,
            "protocol": 17,
            "bytes": 100,
            "packets": 100,
        },
    }

    monitor.on_message(message)

    assert sorted(monitor.endpoints.keys()) == ["10.0.0.10", "10.0.0.20"]


def test_monitor_mac_list(model_config, output_config):
    config = {
        "filter": {
            "type": "mac_list",
            "value": ["11:11:11:11:11:11", "22:22:22:22:22:22"],
        },
        "model": model_config,
        "output": output_config,
    }

    monitor = Monitor(config)

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T15:55:00.000000",
            "dst_mac": "11:11:11:11:11:11",
            "src_mac": "ee:ee:ee:ee:ee:ee",
            "src_ip": "10.0.0.10",
            "dst_ip": "1.1.1.1",
            "src_port": 42000,
            "dst_port": 53,
            "protocol": 17,
            "bytes": 100,
            "packets": 100,
        },
    }

    monitor.on_message(message)

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T15:55:00.000000",
            "src_mac": "22:22:22:22:22:22",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "10.0.0.10",
            "dst_ip": "1.1.1.1",
            "src_port": 42000,
            "dst_port": 53,
            "protocol": 17,
            "bytes": 100,
            "packets": 100,
        },
    }

    monitor.on_message(message)

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T15:55:00.000000",
            "src_mac": "33:33:33:33:33:33",
            "dst_mac": "ff:ff:ff:ff:ff:ff",
            "src_ip": "10.0.0.10",
            "dst_ip": "1.1.1.1",
            "src_port": 42000,
            "dst_port": 53,
            "protocol": 17,
            "bytes": 100,
            "packets": 100,
        },
    }

    monitor.on_message(message)

    assert sorted(monitor.endpoints.keys()) == [
        "11:11:11:11:11:11",
        "22:22:22:22:22:22",
    ]


def test_monitor_eof(model_config, output_config):
    config = {
        "filter": {
            "type": "ip_list",
            "value": ["10.0.0.10"],
        },
        "model": model_config,
        "output": output_config,
    }

    monitor = Monitor(config)

    message = {
        "type": "basic",
        "data": {
            "time_last": "2021-03-03T15:55:00.000000",
            "src_ip": "10.0.0.10",
            "dst_ip": "1.1.1.1",
            "src_port": 42000,
            "dst_port": 53,
            "protocol": 17,
            "bytes": 100,
            "packets": 100,
        },
    }

    monitor.on_message(message)

    monitor.on_message({"type": "eof", "data": {}})
    monitor.on_message({"type": "eof", "data": {}})
    monitor.on_message({"type": "eof", "data": {}})

    assert monitor.eof_count == 3


def test_monitor_invalid(model_config, output_config):
    config = {
        "filter": {
            "type": "error",
            "value": ["x", "y"],
        },
        "model": model_config,
        "output": output_config,
    }

    with pytest.raises(ValueError) as e:
        Monitor(config)

    assert e.type == ValueError


def test_monitor_init(model_config, output_config):
    config = {
        "filter": {
            "type": "ip_list",
            "value": ["10.0.0.10"],
        },
        "model": model_config,
        "output": output_config,
    }

    Monitor(config)

    assert TorClassifier.relays_filter.items == [
        250128189,
        1192492057,
        1601169074,
        1659551192,
        1754629750,
        2734115529,
        2919223544,
        2987502196,
        3168175153,
        55828179287476426650588888404756276908,
    ]

    cnc_steps = [x[0] for x in CNCClassifier.model.steps]

    assert cnc_steps == ["smote", "scaler", "classifier"]
