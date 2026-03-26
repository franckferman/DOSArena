FROM python:3.12-slim

LABEL description="DOSArena attacker node — all tools pre-installed"

# System deps + toolchains for Floodles native backends
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc build-essential \
    libpcap-dev \
    tcpdump \
    iproute2 \
    iputils-ping \
    nmap \
    curl wget \
    ncat \
    net-tools \
    dnsutils \
    snmp \
    ntpsec-ntpdate \
    iperf3 \
    hping3 \
    git \
    vim \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Rust (needed for Floodles native/rust backend)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# Python tools
RUN pip install --no-cache-dir \
    scapy \
    aiohttp \
    click \
    rich \
    pyyaml \
    requests

# Floodles — build all native backends (C, Rust, Go) then install
RUN git clone --depth=1 --branch stable https://github.com/franckferman/Floodles.git /tmp/floodles \
    && cd /tmp/floodles \
    && make all \
    && pip install --no-cache-dir . \
    && cp -r native /usr/local/lib/python3.12/site-packages/floodles/ \
    && rm -rf /tmp/floodles

WORKDIR /opt

# Convenience aliases
RUN echo 'alias ll="ls -la"' >> /root/.bashrc && \
    echo 'alias targets="cat /opt/scenarios/targets.txt"' >> /root/.bashrc && \
    echo 'alias scenarios="ls /opt/scenarios/"' >> /root/.bashrc && \
    echo 'alias submit="python3 /opt/ui/cli.py submit"' >> /root/.bashrc

COPY motd.txt /etc/motd
RUN echo 'cat /etc/motd' >> /root/.bashrc

CMD ["/bin/bash"]
