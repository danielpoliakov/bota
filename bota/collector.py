"""
    UniRec collector.
"""

import threading

import pytrap


class Collector:
    """Collector for processing multiple interfaces.

    Args:
        interfaces (list): UniRec interfaces in BOTA config format.
        callback (function): Callback function for sending collector messages.
    """

    def __init__(self, interfaces, callback):
        unirec_init = ["-i", ",".join(x["interface"] for x in interfaces)]

        self.interfaces = interfaces
        self.callback = callback
        self.threads = []
        self.lock = threading.Lock()

        self.trap = pytrap.TrapCtx()
        self.trap.init(unirec_init, len(interfaces), 0)

        for i in range(len(interfaces)):
            self.trap.setRequiredFmt(
                i, pytrap.FMT_UNIREC, "ipaddr SRC_IP,ipaddr DST_IP"
            )

    def __del__(self):
        self.trap.finalize()

    def start(self):
        """Start the collector.

        Set ups a thread for each of the monitored UniRec interfaces.
        """
        for i, x in enumerate(self.interfaces):
            t = threading.Thread(target=self.interface_loop, args=(i, x), daemon=True)
            t.start()
            self.threads.append(t)

    def interface_loop(self, index, interface):
        """Consuming loop for a single interface.

        Args:
            index (int): Unique interface index.
            interface ([type]): Interface specification in BOTA config format.
        """
        _, format_spec = self.trap.getDataFmt(index)
        ur = pytrap.UnirecTemplate(format_spec)

        while True:
            try:
                data = self.trap.recv(index)
            except pytrap.FormatChanged as e:
                _, format_spec = self.trap.getDataFmt(index)
                ur = pytrap.UnirecTemplate(format_spec)
                data = e.data

            # EOF
            if len(data) <= 1:
                message = {"type": "eof", "data": {}}
                with self.lock:
                    self.callback(message)
                break

            ur.setData(data)

            data = {}

            for k in ur.getFieldsDict():
                v = getattr(ur, k)

                # mapping
                if isinstance(v, (pytrap.UnirecIPAddr, pytrap.UnirecMACAddr)):
                    v = str(v)

                if isinstance(v, pytrap.UnirecTime):
                    v = v.format("%Y-%m-%dT%H:%M:%S.%f")

                if isinstance(v, bytearray):
                    v = v.hex()

                if k == "PPI_PKT_TIMES":
                    v = [x.format("%Y-%m-%dT%H:%M:%S.%f") for x in v]

                if isinstance(v, list) and not isinstance(v, str):
                    v = "[" + "|".join(map(str, v)) + "]"

                data[k.lower()] = v

            message = {"type": interface["type"], "data": data}

            with self.lock:
                self.callback(message)
