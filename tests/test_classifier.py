import os
import pickle
from binascii import hexlify
from datetime import datetime, timedelta

import pytest
from bota.classifier import (
    AnomalyClassifier,
    CNCClassifier,
    DHTClassifier,
    StratumClassifier,
    TorClassifier,
)


def test_dht_classifier():
    classifier = DHTClassifier()

    message = {
        "type": "idpcontent",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "10.0.10.10",
            "src_ip": "10.0.10.20",
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

    classifier.on_message(message)

    assert classifier.positive
    assert classifier.reason == {
        "time_first": "2021-01-01T00:00:00.000000",
        "time_last": "2021-01-01T00:03:00.000000",
        "dst_ip": "10.0.10.10",
        "src_ip": "10.0.10.20",
        "dst_port": 80,
        "src_port": 42000,
        "protocol": 6,
    }

    message = {
        "type": "idpcontent",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "10.0.10.10",
            "src_ip": "10.0.10.30",
            "dst_port": 80,
            "src_port": 42001,
            "protocol": 6,
            "idp_content": "",
        },
    }

    classifier.on_message(message)

    assert classifier.positive
    assert classifier.reason == {
        "time_first": "2021-01-01T00:00:00.000000",
        "time_last": "2021-01-01T00:03:00.000000",
        "dst_ip": "10.0.10.10",
        "src_ip": "10.0.10.20",
        "dst_port": 80,
        "src_port": 42000,
        "protocol": 6,
    }

    classifier.flush()

    message = {
        "type": "idpcontent",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "10.0.10.10",
            "src_ip": "10.0.10.20",
            "dst_port": 80,
            "src_port": 42000,
            "protocol": 6,
            "idp_content": (
                "42424242424242424242424242"
                "42424242424242424242424242"
                "42424242424242424242424242"
                "42424242424242424242424242"
                "42424242424242424242424242"
            ),
        },
    }

    classifier.on_message(message)

    assert not classifier.positive
    assert classifier.reason == {}


def test_stratum_classifier():
    classifier = StratumClassifier()

    message = {
        "type": "idpcontent",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "10.0.10.10",
            "src_ip": "10.0.10.20",
            "dst_port": 6881,
            "src_port": 42000,
            "protocol": 17,
            "idp_content": (
                "7b226964223a312c226a736f6e"
                "727063223a22322e30222c226d"
                "6574686f64223a226c6f67696e"
                "222c22706172616d73223a7b22"
                "6c6f67696e223a223441437776"
                "71674175576b54617179545846"
                "374b4e6f557762754e576b5545"
            ),
        },
    }

    classifier.on_message(message)

    assert classifier.positive
    assert classifier.reason == {
        "time_first": "2021-01-01T00:00:00.000000",
        "time_last": "2021-01-01T00:03:00.000000",
        "dst_ip": "10.0.10.10",
        "src_ip": "10.0.10.20",
        "dst_port": 6881,
        "src_port": 42000,
        "protocol": 17,
        "rule": "stratum_login",
    }

    message = {
        "type": "idpcontent",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "10.0.10.10",
            "src_ip": "10.0.10.30",
            "dst_port": 6881,
            "src_port": 42001,
            "protocol": 17,
            "idp_content": "",
        },
    }

    classifier.on_message(message)

    assert classifier.positive
    assert classifier.reason == {
        "time_first": "2021-01-01T00:00:00.000000",
        "time_last": "2021-01-01T00:03:00.000000",
        "dst_ip": "10.0.10.10",
        "src_ip": "10.0.10.20",
        "dst_port": 6881,
        "src_port": 42000,
        "protocol": 17,
        "rule": "stratum_login",
    }

    classifier.flush()

    message = {
        "type": "idpcontent",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "10.0.10.10",
            "src_ip": "10.0.10.20",
            "dst_port": 6881,
            "src_port": 42000,
            "protocol": 17,
            "idp_content": (
                "42424242424242424242424242"
                "42424242424242424242424242"
                "42424242424242424242424242"
                "42424242424242424242424242"
                "42424242424242424242424242"
            ),
        },
    }

    classifier.on_message(message)

    assert not classifier.positive
    assert classifier.reason == {}

    classifier.flush()

    message = {
        "type": "idpcontent",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "10.0.10.10",
            "src_ip": "10.0.10.20",
            "dst_port": 6881,
            "src_port": 42000,
            "protocol": 17,
            "idp_content": (
                "7b226a736f6e727063223a2232"
                "2e30222c226d6574686f64223a"
                "226a6f62222c22706172616d73"
                "223a7b22626c6f62223a223063"
                "30636433666239346661303565"
                "63643236373536623838363562"
                "34663736626532333438326136"
            ),
        },
    }

    classifier.on_message(message)

    assert classifier.positive
    assert classifier.reason == {
        "time_first": "2021-01-01T00:00:00.000000",
        "time_last": "2021-01-01T00:03:00.000000",
        "dst_ip": "10.0.10.10",
        "src_ip": "10.0.10.20",
        "dst_port": 6881,
        "src_port": 42000,
        "protocol": 17,
        "rule": "stratum_job",
    }

    classifier.flush()

    mix_content = ""
    for i in [0, 1, 2, 5]:
        mix_content += hexlify(classifier.patterns[i]).decode()

    message = {
        "type": "idpcontent",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "10.0.10.10",
            "src_ip": "10.0.10.20",
            "dst_port": 6881,
            "src_port": 42000,
            "protocol": 17,
            "idp_content": mix_content,
        },
    }

    classifier.on_message(message)

    assert not classifier.positive
    assert classifier.reason == {}


def test_tor_classifier():
    classifier = TorClassifier()

    TorClassifier.update_relays(
        [
            "144.76.107.94",
            "185.248.160.21",
            "178.175.148.11",
            "2001:0678:07dc:0134:0000:0000:dead:beef",
        ]
    )

    message = {
        "type": "basic",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "144.76.107.94",
            "src_ip": "10.0.10.100",
            "dst_port": 443,
            "src_port": 42000,
            "protocol": 6,
        },
    }

    classifier.on_message(message)

    assert classifier.positive
    assert classifier.reason == {
        "time_first": "2021-01-01T00:00:00.000000",
        "time_last": "2021-01-01T00:03:00.000000",
        "dst_ip": "144.76.107.94",
        "src_ip": "10.0.10.100",
        "dst_port": 443,
        "src_port": 42000,
        "protocol": 6,
    }

    classifier.flush()

    message = {
        "type": "basic",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "2001:0678:07dc:0134:0000:0000:dead:beef",
            "src_ip": "10.0.10.100",
            "dst_port": 443,
            "src_port": 42000,
            "protocol": 6,
        },
    }

    classifier.on_message(message)

    assert classifier.positive
    assert classifier.reason == {
        "time_first": "2021-01-01T00:00:00.000000",
        "time_last": "2021-01-01T00:03:00.000000",
        "dst_ip": "2001:0678:07dc:0134:0000:0000:dead:beef",
        "src_ip": "10.0.10.100",
        "dst_port": 443,
        "src_port": 42000,
        "protocol": 6,
    }

    classifier.flush()

    message = {
        "type": "basic",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "1.1.1.1",
            "src_ip": "10.0.10.100",
            "dst_port": 53,
            "src_port": 42000,
            "protocol": 17,
        },
    }

    classifier.on_message(message)

    assert not classifier.positive
    assert classifier.reason == {}

    classifier.flush()

    for x in range(1, 4):
        message = {
            "type": "basic",
            "data": {
                "time_first": "2021-01-01T00:00:00.000000",
                "time_last": "2021-01-01T00:03:00.000000",
                "dst_ip": f"{x}.{x}.{x}.{x}",
                "src_ip": "10.0.10.100",
                "dst_port": 53,
                "src_port": 42000,
                "protocol": 17,
            },
        }
        classifier.on_message(message)

    assert not classifier.positive
    assert classifier.reason == {}

    classifier.flush()

    message = {
        "type": "basic",
        "data": {
            "time_first": "2021-01-01T00:00:00.000000",
            "time_last": "2021-01-01T00:03:00.000000",
            "dst_ip": "185.248.160.21",
            "src_ip": "10.0.10.100",
            "dst_port": 443,
            "src_port": 42000,
            "protocol": 6,
        },
    }

    classifier.on_message(message)

    for x in range(1, 4):
        message = {
            "type": "basic",
            "data": {
                "time_first": "2021-01-01T00:00:00.000000",
                "time_last": "2021-01-01T00:03:00.000000",
                "dst_ip": f"{x}.{x}.{x}.{x}",
                "src_ip": "10.0.10.100",
                "dst_port": 53,
                "src_port": 42000,
                "protocol": 17,
            },
        }
        classifier.on_message(message)

    assert classifier.positive
    assert classifier.reason == {
        "time_first": "2021-01-01T00:00:00.000000",
        "time_last": "2021-01-01T00:03:00.000000",
        "dst_ip": "185.248.160.21",
        "src_ip": "10.0.10.100",
        "dst_port": 443,
        "src_port": 42000,
        "protocol": 6,
    }


def test_cnc_classifier(test_directory):
    classifier = CNCClassifier()

    with open(os.path.join(test_directory, "data", "cnc.pickle"), "rb") as f:
        model = pickle.load(f)

    CNCClassifier.update_model(model)

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

    classifier.on_message(message)

    assert classifier.positive
    assert classifier.reason == {
        "time_first": "2018-07-21T00:32:13.288040",
        "time_last": "2018-07-21T00:37:54.304995",
        "dst_ip": "185.130.215.13",
        "src_ip": "192.168.100.108",
        "dst_port": 57722,
        "src_port": 32878,
        "protocol": 6,
    }

    message = {"type": "pstats", "data": {}}

    classifier.on_message(message)

    assert classifier.positive
    assert classifier.reason == {
        "time_first": "2018-07-21T00:32:13.288040",
        "time_last": "2018-07-21T00:37:54.304995",
        "dst_ip": "185.130.215.13",
        "src_ip": "192.168.100.108",
        "dst_port": 57722,
        "src_port": 32878,
        "protocol": 6,
    }

    classifier.flush()

    message = {
        "type": "pstats",
        "data": {
            "dst_ip": "104.155.18.91",
            "src_ip": "192.168.1.132",
            "dst_port": 443,
            "src_port": 37653,
            "protocol": 6,
            "time_first": "2018-10-25T12:46:08.221306",
            "time_last": "2018-10-25T12:48:08.373818",
            "packets": 4,
            "packets_rev": 2,
            "bytes": 238,
            "bytes_rev": 150,
            "dir_bit_field": 0,
            "dst_mac": "78:8a:20:43:93:d5",
            "src_mac": "00:17:88:75:b3:82",
            "tcp_flags": 24,
            "tcp_flags_rev": 24,
            "ppi_pkt_directions": "[1|-1|1|1|-1|1]",
            "ppi_pkt_flags": "[24|24|16|24|24|16]",
            "ppi_pkt_lengths": "[79|75|40|79|75|40]",
            "ppi_pkt_times": "[2018-10-25T12:46:08.221306|2018-10-25T12:46:08.238781|2018-10-25T12:46:08.239027|2018-10-25T12:48:08.356330|2018-10-25T12:48:08.373569|2018-10-25T12:48:08.373818]",
        },
    }

    classifier.on_message(message)

    assert not classifier.positive
    assert classifier.reason == {}

    classifier.flush()

    message = {
        "type": "pstats",
        "data": {
            "dst_ip": "10.0.0.10",
            "src_ip": "10.0.0.20",
            "dst_port": 80,
            "src_port": 42000,
            "protocol": 6,
            "time_first": "2018-07-21T00:32:13.288040",
            "time_last": "2018-07-21T00:32:26.304995",
            "packets": 3,
            "packets_rev": 3,
            "bytes": 100,
            "bytes_rev": 100,
            "dir_bit_field": 0,
            "dst_mac": "78:8a:20:43:93:d5",
            "src_mac": "b8:27:eb:31:10:59",
            "tcp_flags": 26,
            "tcp_flags_rev": 26,
            "ppi_pkt_directions": "[1|-1|1|1|-1|-1]",
            "ppi_pkt_flags": "[2|18|16|24|24|16]",
            "ppi_pkt_lengths": "[60|60|52|56|53|52]",
            "ppi_pkt_times": "[2018-07-21T00:32:13.288040|2018-07-21T00:32:13.338516|2018-07-21T00:32:13.339257|2018-07-21T00:32:13.339756|2018-07-21T00:32:13.607355|2018-07-21T00:32:13.752531]",
        },
    }

    classifier.on_message(message)

    assert not classifier.positive
    assert classifier.reason == {}

    message = {
        "type": "pstats",
        "data": {
            "dst_ip": "10.0.0.10",
            "src_ip": "10.0.0.20",
            "dst_port": 80,
            "src_port": 42000,
            "protocol": 6,
            "time_first": "2018-07-21T00:32:13.288040",
            "time_last": "2018-07-21T00:32:26.304995",
            "packets": 1,
            "packets_rev": 1,
            "bytes": 100,
            "bytes_rev": 100,
            "dir_bit_field": 0,
            "dst_mac": "78:8a:20:43:93:d5",
            "src_mac": "b8:27:eb:31:10:59",
            "tcp_flags": 26,
            "tcp_flags_rev": 26,
            "ppi_pkt_directions": "[1|-1]",
            "ppi_pkt_flags": "[2|18]",
            "ppi_pkt_lengths": "[60|60]",
            "ppi_pkt_times": "[2018-07-21T00:32:13.288040|2018-07-21T00:32:13.338516]",
        },
    }

    classifier.on_message(message)

    assert not classifier.positive
    assert classifier.reason == {}


def test_invalid_cnc(test_directory):
    classifier = CNCClassifier()

    with open(os.path.join(test_directory, "data", "cnc.pickle"), "rb") as f:
        model = pickle.load(f)

    CNCClassifier.update_model(model)

    message = {
        "type": "pstats",
        "data": {
            "dst_ip": "104.155.18.91",
            "src_ip": "192.168.1.132",
            "dst_port": 443,
            "src_port": 37653,
            "protocol": 6,
            "time_first": "2018-10-25T12:46:08.221306",
            "time_last": "2018-10-25T12:48:08.373818",
            "packets": 4,
            "packets_rev": 2,
            "bytes": 238,
            "bytes_rev": 150,
            "dir_bit_field": 0,
            "dst_mac": "78:8a:20:43:93:d5",
            "src_mac": "00:17:88:75:b3:82",
            "tcp_flags": 24,
            "tcp_flags_rev": 24,
            "ppi_pkt_directions": "[]",
            "ppi_pkt_flags": "[]",
            "ppi_pkt_lengths": "[]",
            "ppi_pkt_times": "[]",
        },
    }

    classifier.on_message(message)

    assert not classifier.positive
    assert classifier.reason == {}


def test_anomaly_classifier():
    classifier = AnomalyClassifier("packets", "sum", threshold=10000)

    time_start = datetime.now()
    classifier.sync(time_start)

    for i in range(10):
        time_last = time_start + timedelta(seconds=30 + i)
        message = {
            "type": "basic",
            "data": {
                "time_last": time_last.strftime(classifier.time_fmt),
                "packets": 1,
            },
        }
        classifier.on_message(message)

    assert classifier.windows == 0
    assert classifier.current == 10

    time_last = time_start + timedelta(seconds=190)
    message = {
        "type": "basic",
        "data": {
            "time_last": time_last.strftime(classifier.time_fmt),
            "packets": 10001,
        },
    }

    classifier.on_message(message)

    import numpy

    std_e = numpy.std([10, 9])
    assert classifier.windows == 3
    assert classifier.current == 10001
    assert classifier.smoothing.pred == 8.1
    assert numpy.allclose(classifier.smoothing.std_e, std_e)

    time_last = time_start + timedelta(seconds=191)
    message = {
        "type": "basic",
        "data": {
            "time_last": time_last.strftime(classifier.time_fmt),
            "packets": 1000,
        },
    }

    classifier.on_message(message)

    assert classifier.windows == 3
    assert classifier.current == 11001
    assert classifier.smoothing.pred == 8.1
    assert numpy.allclose(classifier.smoothing.std_e, std_e)

    time_last = time_start + timedelta(seconds=250)
    message = {
        "type": "basic",
        "data": {
            "time_last": time_last.strftime(classifier.time_fmt),
            "packets": 100,
        },
    }

    classifier.on_message(message)

    assert classifier.windows == 4
    assert classifier.current == 100
    assert classifier.anomalies == {"prediction": 1, "threshold": 1}
    assert not classifier.positive
    assert classifier.reason == {}

    time_last += timedelta(seconds=130)
    classifier.sync(time_last)

    assert classifier.windows == 6
    assert classifier.current == 0
    assert classifier.anomalies == {"prediction": 1, "threshold": 1}
    assert classifier.time_next == time_last + timedelta(seconds=classifier.interval)
    assert classifier.max == 11001

    classifier.flush()

    assert classifier.windows == 6
    assert classifier.current == 0
    assert classifier.anomalies == {"prediction": 0, "threshold": 0}
    assert classifier.max == 0

    for _ in range(5):
        time_last = time_last + timedelta(seconds=61)
        message = {
            "type": "basic",
            "data": {
                "time_last": time_last.strftime(classifier.time_fmt),
                "packets": 150000,
            },
        }
        classifier.on_message(message)

    assert classifier.windows == 11
    assert classifier.anomalies == {"prediction": 1, "threshold": 4}
    assert classifier.max == 150000
    assert classifier.positive
    assert classifier.reason == {
        "max": 150000,
        "over_prediction": 1,
        "over_threshold": 4,
    }


def test_invalid_anomaly():
    with pytest.raises(ValueError) as e:
        AnomalyClassifier("bytes", "error", 10)

    assert e.type == ValueError
