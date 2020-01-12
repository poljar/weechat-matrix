FROM debian:testing-slim

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN apt-get update -y; apt-get install -q -y \
  git \
  libolm-dev \
  python3 \
  python3-pip \
  weechat-curses \
  weechat-python \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && rm -fr /root/.cache

# add chat user
RUN useradd -ms /bin/bash chat && mkdir /var/build

# get and build source code
WORKDIR /var/build
RUN git clone https://github.com/poljar/weechat-matrix.git
WORKDIR /var/build/weechat-matrix
RUN pip3 install -r requirements.txt

# Install and setup autoloading
USER chat
RUN make install
WORKDIR /home/chat
RUN mkdir -p .weechat/python/autoload && ln -s /home/chat/.weechat/python/matrix.py /home/chat/.weechat/python/autoload/
