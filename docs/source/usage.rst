=====
Usage
=====


On the host
***********

In case you have Nemea system installed, you can use following scripts.

Set up
------

Directory `data` contains pre-fitted model for C&C classificator and it can be
replaced with your model.

If you want to update list of Tor relays, use following script:

.. code::

   $ python scripts/update_tor_relays.py <destination>

Monitoring pcap
---------------

.. code::

   $ python3 scripts/monitor_pcap.py <bota_config> <pcap>

Monitoring live interface
-------------------------

.. code:: text

   # python3 scripts/monitor_live.py <bota_config> <interface>
   

In the docker
*************

Said scripts are also available in the docker enviroment. 

For configuration and output transfer, use docker volumes as such:


Set up
------

Update config if `data/bota-docker.json` if needed (e.g. changing filtering).

To update list of Tor relays used referenced in `data/bota-docker.json` run:

.. code:: text

   # docker run -v $PWD/data:/data:rw --rm bota python scripts/update_tor_relays.py /data/tor.list


Monitoring pcap
---------------

Place your pcap into the `data` directory. 

.. code:: text

   # docker run -v $PWD/data:/data:rw --rm bota python scripts/monitor_pcap.py /data/bota-docker.json <pcap>

Monitoring live interface
-------------------------

.. code:: text

   # docker run -v $PWD/data:/data:rw --rm --net=host --cap-add NET_ADMIN bota python scripts/monitor_live.py /data/bota-docker.json <interface>
