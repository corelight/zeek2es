FROM ubuntu:jammy

RUN apt-get -q update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      curl \
      fswatch \
      geoipupdate \
      git \
      iproute2 \
      jq \
      less \
      netcat \
      net-tools \
      parallel \
      python3 \
      python3-dev \
      python3-pip \
      python3-setuptools \
      python3-wheel \
      swig \
      tcpdump \
      tcpreplay \
      termshark \
      tshark \
      vim \
      wget \
      zeek-aux && \
    pip3 install --no-cache-dir pre-commit requests && \
    curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.2.0-amd64.deb && \
    dpkg -i filebeat-8.2.0-amd64.deb && \
    rm filebeat-8.2.0-amd64.deb && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && rm -rf ~/.cache/pip

# Install zeek2es
RUN cd / && git clone https://github.com/corelight/zeek2es.git

#COPY entrypoint.sh /entrypoint.sh
#RUN chmod 755 /entrypoint.sh