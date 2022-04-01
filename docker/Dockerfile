FROM python:3.6

WORKDIR /root

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    libxml2-utils \
    gawk \
    bc \
    libidn11-dev \
    bison \
    flex

RUN git clone --recursive https://github.com/CESNET/nemea \
    && cd nemea/modules \
    && git fetch origin bi-aggr-sorted_merge_dir \
    && git checkout bi-aggr-sorted_merge_dir \
    && cd .. \
    && ./bootstrap.sh \
    && ./configure --prefix=/usr --bindir=/usr/local/bin --sysconfdir=/etc/nemea --libdir=/usr/lib \
    && make -j$(nproc) \
    && make install

WORKDIR /root

RUN git clone https://github.com/CESNET/ipfixprobe \
    && cd ipfixprobe \
    && git checkout d016fe3cf5e6a960c4b7386f9f299b813ca801f1\
    && autoreconf -i \
    && ./configure --with-nemea \
    && make -j$(nproc) \
    && make install

COPY . /root/bota

WORKDIR /root/bota/

RUN pip install -r requirements.txt \
    && pip install .
