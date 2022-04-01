import argparse
import json
import logging
import signal
import subprocess
import sys
import time
from functools import partial

from bota.collector import Collector
from bota.monitor import Monitor

logging.basicConfig(format="%(levelname)s: %(message)s")
log = logging.getLogger()
log.setLevel(logging.INFO)


def signal_handler(monitor, processes, sig, frame):
    log.info("captured SIGINT, ending")
    time.sleep(1)

    log.info("stopping aggregator and traffic repeater...")
    for p in processes:
        try:
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()

    log.info("stopping monitor...")
    monitor.on_message({"type": "eof", "data": {}})
    monitor.on_message({"type": "eof", "data": {}})
    monitor.on_message({"type": "eof", "data": {}})
    sys.exit(0)


def parse_options(interface_config):
    res = ""

    if not "options" in interface_config:
        return res

    for option in interface_config["options"]:
        res += f":{option}"

    return res


def aggregator(config, interfaces):
    p = subprocess.Popen(
        [
            config["biflow_aggregator"],
            "-c",
            config["biflow_config"],
            "-n",
            config["biflow_id"],
            "-a",
            str(config["biflow_active"]),
            "-p",
            str(config["biflow_passive"]),
            "-s",
            "20",
            "-i",
            ",".join(interfaces),
            "-e",
        ]
    )

    return p


def ipfixprobe(config, pcap, plugins, interfaces):
    p = subprocess.Popen(
        [
            config["ipfixprobe"],
            "-r",
            pcap,
            "-p",
            ",".join(plugins),
            "-i",
            ",".join(interfaces),
        ]
    )

    return p


def traffic_repeater(interfaces):
    p = subprocess.Popen(["traffic_repeater", "-i", ",".join(interfaces)])
    return p


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config", help="config file path")
    parser.add_argument("dir", help="trap path")
    parser.add_argument("prefix", help="trap prefix")

    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    plugins = [x["type"] for x in config["interfaces"]]

    interfaces = [
        x["interface"] if x["type"] != "pstats" else x["interface"] + "_pre"
        for x in config["interfaces"]
    ]

    interfaces = []
    pstats_pre = None
    pstats_post = None

    for x in config["interfaces"]:
        if x["type"] == "pstats":
            pstats_pre = x["interface"] + "_pre"
            pstats_post = x["interface"]
            interfaces.append(pstats_pre + ":buffer=off")
        else:
            interfaces.append(x["interface"] + ":buffer=off")

    prefix = args.prefix

    log.info(f"analyzing {prefix}")

    # Nemea setup
    log.info("starting traffic_repeater 1")
    p_tr_1 = traffic_repeater(
        [f"f:{args.dir}/{prefix}-bstats.trapcap", f"u:collector_basic"]
    )

    log.info("starting traffic_repeater 2")
    p_tr_2 = traffic_repeater(
        [f"f:{args.dir}/{prefix}-idpcontent.trapcap", f"u:collector_idpcontent"]
    )

    log.info("starting traffic_repeater 3")
    p_tr_3 = traffic_repeater([f"f:{args.dir}/{prefix}-pstats.trapcap", pstats_pre])

    log.info("starting aggregator...")
    p_agg = aggregator(config["nemea"], [pstats_pre, pstats_post])

    # BOTA setup
    log.info("starting BOTA...")
    monitor = Monitor(config)
    collector = Collector(config["interfaces"], monitor.on_message)
    collector.start()

    # signal handling
    signal.signal(
        signal.SIGINT,
        partial(signal_handler, monitor, [p_agg, p_tr_1, p_tr_2, p_tr_3]),
    )

    # main loop
    agg_rc = None
    tr_1_rc = None
    tr_2_rc = None
    tr_3_rc = None

    while agg_rc == None or tr_1_rc == None or tr_2_rc == None or tr_3_rc == None:
        time.sleep(0.25)
        agg_rc = p_agg.poll()
        tr_1_rc = p_tr_1.poll()
        tr_2_rc = p_tr_2.poll()
        tr_3_rc = p_tr_3.poll()

    time.sleep(1)


if __name__ == "__main__":
    main()
