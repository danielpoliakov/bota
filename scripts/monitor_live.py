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


def signal_handler(monitor, p_agg, p_probe, sig, frame):
    log.info("captured SIGINT, ending")
    time.sleep(1)

    log.info("stopping ipfixprobe and aggregator...")
    try:
        p_probe.send_signal(signal.SIGTERM)
        p_probe.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p_probe.kill()

    try:
        p_agg.send_signal(signal.SIGTERM)
        p_agg.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p_agg.kill()

    log.info("stopping monitor...")
    monitor.on_message({"type": "eof", "data": {}})
    monitor.on_message({"type": "eof", "data": {}})
    monitor.on_message({"type": "eof", "data": {}})

    while not monitor.end:
        time.sleep(0.25)

    sys.exit(0)


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


def ipfixprobe(config, network_interface, plugins, interfaces):
    p = subprocess.Popen(
        [
            config["ipfixprobe"],
            "-I",
            network_interface,
            "-p",
            ",".join(plugins),
            "-i",
            ",".join(interfaces),
            "-t",
            "300.0:30.0",
        ]
    )

    return p


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config", help="config file path")
    parser.add_argument("interface", help="network interface")

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

    # Nemea setup
    log.info("starting aggregator...")
    p_agg = aggregator(config["nemea"], [pstats_pre, pstats_post])

    log.info("starting ipfixprobe...")
    p_probe = ipfixprobe(config["nemea"], args.interface, plugins, interfaces)

    # BOTA setup
    log.info("starting BOTA...")
    monitor = Monitor(config)
    collector = Collector(config["interfaces"], monitor.on_message)
    collector.start()

    # signal handling
    signal.signal(signal.SIGINT, partial(signal_handler, monitor, p_agg, p_probe))

    # main loop
    agg_rc = None
    probe_rc = None

    while agg_rc == None or probe_rc == None:
        time.sleep(0.25)
        agg_rc = p_agg.poll()
        probe_rc = p_probe.poll()

    while not monitor.end:
        time.sleep(0.25)


    time.sleep(1)


if __name__ == "__main__":
    main()
