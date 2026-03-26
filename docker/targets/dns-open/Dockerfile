FROM internetsystemsconsortium/bind9:9.18

LABEL description="BIND9 open resolver — responds to ANY from any source (DNS amp vulnerable)"

RUN apk add --no-cache dns-root-hints && \
    mkdir -p /usr/share/dns && \
    ln -s /usr/share/dns-root-hints/named.root /usr/share/dns/root.hints
RUN mkdir -p /var/log/named /var/log/bind && chown bind:bind /var/log/named /var/log/bind

COPY named.conf /etc/bind/named.conf
COPY named.conf.options /etc/bind/named.conf.options
COPY db.dosarena.local /etc/bind/db.dosarena.local

EXPOSE 53/udp 53/tcp
CMD ["-f", "-g", "-c", "/etc/bind/named.conf"]
