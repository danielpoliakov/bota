=============
Configuration
=============

Example BOTA configuration:

.. code:: json

    {
      "filter": {
        "type": "ip_range",
        "value": "10.0.0.0/8"
      },
      "interfaces": [
        {
          "interface": "u:collector_basic",
          "type": "basic"
        },
        {
          "interface": "u:collector_idpcontent",
          "type": "idpcontent"
        },
        {
          "interface": "u:collector_pstats",
          "type": "pstats"
        }
      ],
      "model": {
        "cnc": "/home/daniel/bota/data/rf.pickle",
        "tor": "/home/daniel/bota/data/tor.list",
        "anomaly": {
          "dst_ip": 50,
          "dst_port": 50,
          "packets": 1000,
          "bytes": 1000000
        }
      },
      "output": {
        "idea": "/home/daniel/bota/data/idea.json",
        "detail": "/home/daniel/bota/data/detail.json"
      },
      "nemea": {
        "ipfixprobe": "/usr/local/bin/ipfixprobe",
        "biflow_aggregator": "/usr/bin/nemea/biflow_aggregator",
        "biflow_config": "/home/daniel/bota/config/biflow.xml",
        "biflow_id": "main",
        "biflow_active": 300,
        "biflow_passive": 240
      }
    }
