FROM debian:buster-slim

ENV DEBIAN_FRONTEND="noninteractive" \
    LANG="C.UTF-8"

RUN apt-get update \
    && apt-get -qq -y install \
    cmake \
    git \
    python-atomicwrites \
    python-attr \
    python-future \
    python-h2 \
    python-jsonschema \
    python-logbook \
    python-openssl \
    python-peewee \
    python-pip \
    python-pygments \
    python-typing \
    python-unpaddedbase64 \
    python-webcolors \
    python-wheel \
    weechat \
    weechat-python \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && pip install h11 \
    && rm -rf /root/.cache

WORKDIR /root
RUN git clone https://git.matrix.org/git/olm.git \
    && cd olm \
    && cmake . \
    && make install \
    && ldconfig
RUN pip install 'git+https://github.com/poljar/python-olm.git@master#egg=python-olm-0'
RUN git clone https://github.com/poljar/matrix-nio \
    && cd matrix-nio \
    && DESTDIR=/ make install
RUN git clone https://github.com/poljar/weechat-matrix \
    && cd weechat-matrix \
    && make install
