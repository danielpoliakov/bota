import collections
import os
import subprocess
import time

from bota.collector import Collector


def traffic_repeater(interface_spec):
    p = subprocess.run(["traffic_repeater", "-i", interface_spec])
    if p.returncode != 0:
        raise RuntimeError("Error running traffic_repeater.")


def test_http(test_directory):
    interfaces = [{"interface": "u:test_collector_http", "type": "http"}]

    results = []

    c = Collector(interfaces, lambda x: results.append(x))
    c.start()

    tc = os.path.join(test_directory, "data", "http.tc")
    traffic_repeater(f"f:{tc},{interfaces[0]['interface']}")

    time.sleep(1)

    assert (len(results)) == 3

    assert [x["type"] for x in results] == ["http"] * 2 + ["eof"]

    assert results[0]["data"] == {
        "dst_ip": "147.229.9.26",
        "src_ip": "10.0.10.100",
        "bytes": 394,
        "bytes_rev": 635,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:34.458000",
        "time_last": "2021-03-03T15:57:34.700000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "packets": 6,
        "packets_rev": 4,
        "dst_port": 80,
        "http_response_status_code": 301,
        "src_port": 47982,
        "dir_bit_field": 0,
        "protocol": 6,
        "tcp_flags": 27,
        "tcp_flags_rev": 27,
        "http_request_agent": "curl/7.64.0",
        "http_request_host": "fit.vut.cz",
        "http_request_method": "GET",
        "http_request_referer": "",
        "http_request_url": "/",
        "http_response_content_type": "text/html; charset=iso-8859-1",
    }

    assert results[1]["data"] == {
        "dst_ip": "35.158.59.193",
        "src_ip": "10.0.10.100",
        "bytes": 400,
        "bytes_rev": 619,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:27.855000",
        "time_last": "2021-03-03T15:57:27.901000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "packets": 6,
        "packets_rev": 4,
        "dst_port": 80,
        "http_response_status_code": 301,
        "src_port": 50066,
        "dir_bit_field": 0,
        "protocol": 6,
        "tcp_flags": 27,
        "tcp_flags_rev": 27,
        "http_request_agent": "curl/7.64.0",
        "http_request_host": "danieluhricek.cz",
        "http_request_method": "GET",
        "http_request_referer": "",
        "http_request_url": "/",
        "http_response_content_type": "text/html",
    }


def test_passivedns(test_directory):
    interfaces = [{"interface": "u:test_collector_passivedns", "type": "passivedns"}]

    results = []

    c = Collector(interfaces, lambda x: results.append(x))
    c.start()

    tc = os.path.join(test_directory, "data", "passivedns.tc")
    traffic_repeater(f"f:{tc},{interfaces[0]['interface']}")

    time.sleep(1)

    assert (len(results)) == 4

    assert [x["type"] for x in results] == ["passivedns"] * 3 + ["eof"]

    assert results[0]["data"] == {
        "dns_ip": "35.158.59.193",
        "dst_ip": "192.168.0.1",
        "src_ip": "10.0.10.100",
        "bytes": 124,
        "bytes_rev": 78,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:27.837000",
        "time_last": "2021-03-03T15:57:27.840000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "dns_rr_ttl": 1694,
        "packets": 2,
        "packets_rev": 1,
        "dns_atype": 1,
        "dns_id": 53367,
        "dst_port": 53,
        "src_port": 45622,
        "dir_bit_field": 0,
        "protocol": 17,
        "tcp_flags": 0,
        "tcp_flags_rev": 0,
        "dns_name": "danieluhricek.cz",
    }

    assert results[1]["data"] == {
        "dns_ip": "147.229.9.26",
        "dst_ip": "192.168.0.1",
        "src_ip": "10.0.10.100",
        "bytes": 112,
        "bytes_rev": 72,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:34.455000",
        "time_last": "2021-03-03T15:57:34.457000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "dns_rr_ttl": 14375,
        "packets": 2,
        "packets_rev": 1,
        "dns_atype": 1,
        "dns_id": 39179,
        "dst_port": 53,
        "src_port": 40311,
        "dir_bit_field": 0,
        "protocol": 17,
        "tcp_flags": 0,
        "tcp_flags_rev": 0,
        "dns_name": "fit.vut.cz",
    }

    assert results[2]["data"] == {
        "dns_ip": "2001:67c:1220:809::93e5:91a",
        "dst_ip": "10.0.10.100",
        "src_ip": "192.168.0.1",
        "bytes": 84,
        "bytes_rev": 0,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:34.457000",
        "time_last": "2021-03-03T15:57:34.457000",
        "dst_mac": "00:28:f8:df:f8:27",
        "src_mac": "08:55:31:83:fb:b3",
        "dns_rr_ttl": 14375,
        "packets": 1,
        "packets_rev": 0,
        "dns_atype": 28,
        "dns_id": 57901,
        "dst_port": 40311,
        "src_port": 53,
        "dir_bit_field": 0,
        "protocol": 17,
        "tcp_flags": 0,
        "tcp_flags_rev": 0,
        "dns_name": "fit.vut.cz",
    }


def test_pstats(test_directory):
    interfaces = [{"interface": "u:test_collector_pstats", "type": "pstats"}]

    results = []

    c = Collector(interfaces, lambda x: results.append(x))
    c.start()

    tc = os.path.join(test_directory, "data", "pstats.tc")
    traffic_repeater(f"f:{tc},{interfaces[0]['interface']}")

    time.sleep(1)

    assert (len(results)) == 5

    assert [x["type"] for x in results] == ["pstats"] * 4 + ["eof"]

    assert results[0]["data"] == {
        "dst_ip": "147.229.9.26",
        "src_ip": "10.0.10.100",
        "bytes": 394,
        "bytes_rev": 635,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:34.458000",
        "time_last": "2021-03-03T15:57:34.700000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "packets": 6,
        "packets_rev": 4,
        "dst_port": 80,
        "src_port": 47982,
        "dir_bit_field": 0,
        "protocol": 6,
        "tcp_flags": 27,
        "tcp_flags_rev": 27,
        "ppi_pkt_directions": "[1|-1|1|1|-1|1|1|-1|-1|1]",
        "ppi_pkt_flags": "[2|18|16|24|24|16|17|16|17|16]",
        "ppi_pkt_lengths": "[60|60|52|126|471|52|52|52|52|52]",
        "ppi_pkt_times": "[2021-03-03T15:57:34.458000|2021-03-03T15:57:34.523000|2021-03-03T15:57:34.523000|2021-03-03T15:57:34.523000|2021-03-03T15:57:34.692000|2021-03-03T15:57:34.692000|2021-03-03T15:57:34.692000|2021-03-03T15:57:34.700000|2021-03-03T15:57:34.700000|2021-03-03T15:57:34.700000]",
    }

    assert results[1]["data"] == {
        "dst_ip": "35.158.59.193",
        "src_ip": "10.0.10.100",
        "bytes": 400,
        "bytes_rev": 619,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:27.855000",
        "time_last": "2021-03-03T15:57:27.901000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "packets": 6,
        "packets_rev": 4,
        "dst_port": 80,
        "src_port": 50066,
        "dir_bit_field": 0,
        "protocol": 6,
        "tcp_flags": 27,
        "tcp_flags_rev": 27,
        "ppi_pkt_directions": "[1|-1|1|1|-1|-1|1|1|-1|1]",
        "ppi_pkt_flags": "[2|18|16|24|16|24|16|17|17|16]",
        "ppi_pkt_lengths": "[60|60|52|132|52|455|52|52|52|52]",
        "ppi_pkt_times": "[2021-03-03T15:57:27.855000|2021-03-03T15:57:27.870000|2021-03-03T15:57:27.870000|2021-03-03T15:57:27.870000|2021-03-03T15:57:27.885000|2021-03-03T15:57:27.886000|2021-03-03T15:57:27.886000|2021-03-03T15:57:27.886000|2021-03-03T15:57:27.901000|2021-03-03T15:57:27.901000]",
    }

    assert results[2]["data"] == {
        "dst_ip": "192.168.0.1",
        "src_ip": "10.0.10.100",
        "bytes": 112,
        "bytes_rev": 156,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:34.455000",
        "time_last": "2021-03-03T15:57:34.457000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "packets": 2,
        "packets_rev": 2,
        "dst_port": 53,
        "src_port": 40311,
        "dir_bit_field": 0,
        "protocol": 17,
        "tcp_flags": 0,
        "tcp_flags_rev": 0,
        "ppi_pkt_directions": "[1|1|-1|-1]",
        "ppi_pkt_flags": "[0|0|0|0]",
        "ppi_pkt_lengths": "[56|56|72|84]",
        "ppi_pkt_times": "[2021-03-03T15:57:34.455000|2021-03-03T15:57:34.455000|2021-03-03T15:57:34.457000|2021-03-03T15:57:34.457000]",
    }

    assert results[3]["data"] == {
        "dst_ip": "192.168.0.1",
        "src_ip": "10.0.10.100",
        "bytes": 124,
        "bytes_rev": 140,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:27.837000",
        "time_last": "2021-03-03T15:57:27.854000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "packets": 2,
        "packets_rev": 2,
        "dst_port": 53,
        "src_port": 45622,
        "dir_bit_field": 0,
        "protocol": 17,
        "tcp_flags": 0,
        "tcp_flags_rev": 0,
        "ppi_pkt_directions": "[1|1|-1|-1]",
        "ppi_pkt_flags": "[0|0|0|0]",
        "ppi_pkt_lengths": "[62|62|78|62]",
        "ppi_pkt_times": "[2021-03-03T15:57:27.837000|2021-03-03T15:57:27.837000|2021-03-03T15:57:27.840000|2021-03-03T15:57:27.854000]",
    }


def test_idpcontent(test_directory):
    interfaces = [{"interface": "u:test_collector_idpcontent", "type": "idpcontent"}]

    results = []

    c = Collector(interfaces, lambda x: results.append(x))
    c.start()

    tc = os.path.join(test_directory, "data", "idpcontent.tc")
    traffic_repeater(f"f:{tc},{interfaces[0]['interface']}")

    time.sleep(1)

    assert (len(results)) == 5

    assert [x["type"] for x in results] == ["idpcontent"] * 4 + ["eof"]

    assert results[0]["data"] == {
        "dst_ip": "147.229.9.26",
        "src_ip": "10.0.10.100",
        "bytes": 394,
        "bytes_rev": 635,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:34.458000",
        "time_last": "2021-03-03T15:57:34.700000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "packets": 6,
        "packets_rev": 4,
        "dst_port": 80,
        "src_port": 47982,
        "dir_bit_field": 0,
        "protocol": 6,
        "tcp_flags": 27,
        "tcp_flags_rev": 27,
        "idp_content": "474554202f20485454502f312e310d0a486f73743a206669742e7675742e637a0d0a557365722d4167656e743a206375726c2f372e36342e300d0a4163636570743a202a2f2a0d0a0d0a",
        "idp_content_rev": "485454502f312e3120333031204d6f766564205065726d616e656e746c790d0a446174653a205765642c203033204d617220323032312031353a35373a333420474d540d0a5365727665723a204170616368650d0a4c6f636174696f6e3a206874747073",
    }

    assert results[1]["data"] == {
        "dst_ip": "35.158.59.193",
        "src_ip": "10.0.10.100",
        "bytes": 400,
        "bytes_rev": 619,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:27.855000",
        "time_last": "2021-03-03T15:57:27.901000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "packets": 6,
        "packets_rev": 4,
        "dst_port": 80,
        "src_port": 50066,
        "dir_bit_field": 0,
        "protocol": 6,
        "tcp_flags": 27,
        "tcp_flags_rev": 27,
        "idp_content": "474554202f20485454502f312e310d0a486f73743a2064616e69656c7568726963656b2e637a0d0a557365722d4167656e743a206375726c2f372e36342e300d0a4163636570743a202a2f2a0d0a0d0a",
        "idp_content_rev": "485454502f312e3120333031204d6f766564205065726d616e656e746c790d0a5365727665723a206e67696e782f312e31342e3020285562756e7475290d0a446174653a205765642c203033204d617220323032312031353a35373a323720474d540d0a",
    }

    assert results[2]["data"] == {
        "dst_ip": "192.168.0.1",
        "src_ip": "10.0.10.100",
        "bytes": 112,
        "bytes_rev": 156,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:34.455000",
        "time_last": "2021-03-03T15:57:34.457000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "packets": 2,
        "packets_rev": 2,
        "dst_port": 53,
        "src_port": 40311,
        "dir_bit_field": 0,
        "protocol": 17,
        "tcp_flags": 0,
        "tcp_flags_rev": 0,
        "idp_content": "990b01000001000000000000036669740376757402637a0000010001",
        "idp_content_rev": "990b81800001000100000000036669740376757402637a0000010001c00c0001000100003827000493e5091a",
    }

    assert results[3]["data"] == {
        "dst_ip": "192.168.0.1",
        "src_ip": "10.0.10.100",
        "bytes": 124,
        "bytes_rev": 140,
        "link_bit_field": 1,
        "time_first": "2021-03-03T15:57:27.837000",
        "time_last": "2021-03-03T15:57:27.854000",
        "dst_mac": "08:55:31:83:fb:b3",
        "src_mac": "00:28:f8:df:f8:27",
        "packets": 2,
        "packets_rev": 2,
        "dst_port": 53,
        "src_port": 45622,
        "dir_bit_field": 0,
        "protocol": 17,
        "tcp_flags": 0,
        "tcp_flags_rev": 0,
        "idp_content": "d077010000010000000000000d64616e69656c7568726963656b02637a0000010001",
        "idp_content_rev": "d077818000010001000000000d64616e69656c7568726963656b02637a0000010001c00c000100010000069e0004239e3bc1",
    }


def test_multiple(test_directory):
    interfaces = [
        {"interface": "u:test_collector_http", "type": "http"},
        {"interface": "u:test_collector_passivedns", "type": "passivedns"},
        {"interface": "u:test_collector_pstats", "type": "pstats"},
    ]

    results = []

    c = Collector(interfaces, lambda x: results.append(x))
    c.start()

    tc = os.path.join(test_directory, "data", "http.tc")
    traffic_repeater(f"f:{tc},{interfaces[0]['interface']}")

    tc = os.path.join(test_directory, "data", "passivedns.tc")
    traffic_repeater(f"f:{tc},{interfaces[1]['interface']}")

    tc = os.path.join(test_directory, "data", "pstats.tc")
    traffic_repeater(f"f:{tc},{interfaces[2]['interface']}")

    time.sleep(3)

    count = collections.Counter([x["type"] for x in results])

    assert count == {"pstats": 4, "passivedns": 3, "http": 2, "eof": 3}
