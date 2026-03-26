FROM debian:bullseye-slim
LABEL description="Stateful firewall — conntrack enabled, drops ACK/XMAS, limited conntrack table"

RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    iputils-ping \
    nginx-light \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY nginx.conf /etc/nginx/nginx.conf
RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
