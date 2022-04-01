import os
import pickle
from datetime import datetime

from bota.classifier import CNCClassifier
from bota.endpoint import DirectionRole, IPEndpoint, MACEndpoint


def test_endpoint_verdict():
    config = {
        "anomaly": {
            "bytes": 42,
            "packets": 42,
            "dst_ip": 42,
            "dst_port": 42,
        }
    }

    e = IPEndpoint("10.0.10.10", config)
    e.sync(datetime.now())

    e.classifiers["cnc"].positive = True
    e.classifiers["cnc"].reason = "test cnc"
    e.classifiers["dst_ip"].anomalies = {"prediction": 1, "threshold": 3}
    e.classifiers["dst_ip"].max = 42

    positive, reason = e.verdict()

    assert positive
    assert reason == {
        "cnc": "test cnc",
        "dst_ip": {"max": 42, "over_prediction": 1, "over_threshold": 3},
    }

    e.flush()

    positive, reason = e.verdict()

    assert not positive
    assert reason == {}

    e.classifiers["tor"].positive = True
    e.classifiers["tor"].reason = "test tor"
    e.classifiers["packets"].anomalies = {"prediction": 1, "threshold": 3}
    e.classifiers["packets"].max = 42

    positive, reason = e.verdict()

    assert positive
    assert reason == {
        "tor": "test tor",
        "packets": {"max": 42, "over_prediction": 1, "over_threshold": 3},
    }

    e.flush()

    e.classifiers["dht"].positive = True
    e.classifiers["dht"].reason = "test dht"
    e.classifiers["stratum"].positive = True
    e.classifiers["stratum"].reason = "test stratum"

    positive, reason = e.verdict()

    assert positive
    assert reason == {"dht": "test dht", "stratum": "test stratum"}

    e.flush()

    e.classifiers["cnc"].positive = True
    e.classifiers["cnc"].reason = "test cnc"
    e.classifiers["dht"].positive = True
    e.classifiers["dht"].reason = "test dht"

    positive, reason = e.verdict()

    assert not positive
    assert reason == {"dht": "test dht", "cnc": "test cnc"}


def test_endpoint_direction():
    config = {
        "anomaly": {
            "bytes": 42,
            "packets": 42,
            "dst_ip": 42,
            "dst_port": 42,
        }
    }

    e = IPEndpoint("10.0.10.10", config)

    role_1 = e.direction_role({"src_ip": "10.0.10.10", "dst_ip": "x"})
    role_2 = e.direction_role({"dst_ip": "10.0.10.10", "src_ip": "x"})

    assert role_1 == DirectionRole.SOURCE
    assert role_2 == DirectionRole.DESTINATION

    e = MACEndpoint("11:11:11:11:11:11", config)

    role_1 = e.direction_role({"src_mac": "11:11:11:11:11:11", "dst_mac": "x"})
    role_2 = e.direction_role({"dst_mac": "11:11:11:11:11:11", "src_mac": "x"})

    assert role_1 == DirectionRole.SOURCE
    assert role_2 == DirectionRole.DESTINATION


def test_endpoint_message_pass(test_directory):
    classifier = CNCClassifier()

    with open(os.path.join(test_directory, "data", "cnc.pickle"), "rb") as f:
        model = pickle.load(f)

    CNCClassifier.update_model(model)
    config = {
        "anomaly": {
            "bytes": 42,
            "packets": 42,
            "dst_ip": 42,
            "dst_port": 42,
        }
    }

    e = IPEndpoint("10.0.10.10", config)

    message = {
        "type": "idpcontent",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "src_ip": "10.0.10.10",
            "dst_ip": "10.0.10.20",
            "dst_port": 80,
            "src_port": 42000,
            "protocol": 6,
            "idp_content": (
                "64313a6164323a696432303a71"
                "803892add3def437d99f40dac9"
                "04e2a874168d65313a71343a70"
                "696e67313a74343a706e000031"
                "3a76343a55540000313a79313a"
            ),
        },
    }

    e.on_message(message)

    assert e.classifiers["dht"].positive
    assert e.classifiers["dht"].reason == {
        "time_first": "2021-01-01T00:00:00.000000",
        "time_last": "2021-01-01T00:03:00.000000",
        "src_ip": "10.0.10.10",
        "dst_ip": "10.0.10.20",
        "dst_port": 80,
        "src_port": 42000,
        "protocol": 6,
    }

    message = {
        "type": "pstats",
        "data": {
            "dst_ip": "185.130.215.13",
            "src_ip": "192.168.100.108",
            "dst_port": 57722,
            "src_port": 32878,
            "protocol": 6,
            "time_first": "2018-07-21T00:32:13.288040",
            "time_last": "2018-07-21T00:37:54.304995",
            "packets": 15,
            "packets_rev": 9,
            "bytes": 805,
            "bytes_rev": 486,
            "dir_bit_field": 0,
            "dst_mac": "78:8a:20:43:93:d5",
            "src_mac": "b8:27:eb:31:10:59",
            "tcp_flags": 26,
            "tcp_flags_rev": 26,
            "ppi_pkt_directions": "[1|-1|1|1|1|-1|-1|1|-1|-1|1|1|-1|1|1|-1|1|1|-1|1|1|-1|1|1]",
            "ppi_pkt_flags": "[2|18|16|24|24|16|16|24|24|16|16|24|24|16|24|24|16|24|24|16|24|24|16|24]",
            "ppi_pkt_lengths": "[60|60|52|56|53|52|52|54|54|52|52|54|54|52|54|54|52|54|54|52|54|54|52|54]",
            "ppi_pkt_times": "[2018-07-21T00:32:13.288040|2018-07-21T00:32:13.338516|2018-07-21T00:32:13.339257|2018-07-21T00:32:13.339756|2018-07-21T00:32:13.607355|2018-07-21T00:32:13.752531|2018-07-21T00:32:13.771512|2018-07-21T00:32:53.377487|2018-07-21T00:32:53.428709|2018-07-21T00:32:53.428723|2018-07-21T00:32:53.429197|2018-07-21T00:33:53.488284|2018-07-21T00:33:53.537998|2018-07-21T00:33:53.538744|2018-07-21T00:34:53.598076|2018-07-21T00:34:53.746736|2018-07-21T00:34:53.747233|2018-07-21T00:35:53.813309|2018-07-21T00:35:53.984959|2018-07-21T00:35:53.985457|2018-07-21T00:36:54.037797|2018-07-21T00:36:54.243179|2018-07-21T00:36:54.243918|2018-07-21T00:37:54.304995]",
        },
    }

    e.on_message(message)

    assert e.classifiers["cnc"].positive
    assert e.classifiers["cnc"].reason == {
        "time_first": "2018-07-21T00:32:13.288040",
        "time_last": "2018-07-21T00:37:54.304995",
        "dst_ip": "185.130.215.13",
        "src_ip": "192.168.100.108",
        "dst_port": 57722,
        "src_port": 32878,
        "protocol": 6,
    }


def test_endpoint_prior():
    config = {
        "anomaly": {
            "bytes": 42,
            "packets": 42,
            "dst_ip": 42,
            "dst_port": 42,
        },
        "prior": {"dst_ip": 5, "dst_port": 5, "bytes": 1000, "packets": 30},
    }

    e = IPEndpoint("10.0.10.10", config)
    e.sync(datetime.now())

    assert 2 < e.classifiers["dst_ip"].smoothing.pred < 8
    assert 2 < e.classifiers["dst_port"].smoothing.pred < 8
    assert 800 < e.classifiers["bytes"].smoothing.pred < 1200
    assert 25 < e.classifiers["packets"].smoothing.pred < 35
