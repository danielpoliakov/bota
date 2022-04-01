============
Installation
============

Nemea requirements
******************

BOTA can be used as part of the `Nemea <https://github.com/CESNET/Nemea>`_ framework and it depends on two of Nemea binaries:

* `ipfixprobe <https://github.com/CESNET/ipfixprobe>`_
* `biflow_aggregator <https://github.com/CESNET/Nemea-Modules/tree/master/biflow_aggregator>`_


Python requirements
*******************

* nemea-pytrap
* imblearn
* scikit-learn
* pyahocorasick
* requests
* pandas


Manual installation
*******************

Assuming the requirements are installed, you can manually install BOTA python package.

.. code::
   
   $ git clone https://github.com/danieluhricek/BOTA
   $ cd BOTA
   $ python3 setup.py install


Tests and coverage
******************

To run tests and generate coverage, two packages are required:

* pytest
* coverage

Running tests:

.. code::
   
   $ pytest -v tests/


Generating coverage:

.. code::
   
   $ coverage run --source=bota -m pytest -v tests/

Showing report:

.. code::

   $ coverage report
 
   Name                 Stmts   Miss  Cover
   ----------------------------------------
   bota/__init__.py         0      0   100%
   bota/anomaly.py         38      0   100%
   bota/classifier.py     154      0   100%
   bota/collector.py       53      0   100%
   bota/endpoint.py        60      0   100%
   bota/filter.py          46      0   100%
   bota/monitor.py        109      0   100%
   ----------------------------------------
   TOTAL                  460      0   100%

Docker preparation
******************

The same without the need of having Nemea system installed can be prepared as docker environment.

Build docker image:

.. code:: text

   # docker build -t bota . -f docker/Dockerfile


Running tests:

.. code:: text

   # docker run --rm bota pytest -v tests/

