FROM httpd:2.4

LABEL description="Apache 2.4 — hardened: mod_reqtimeout, SYN cookies, rate limiting"

RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY www/ /usr/local/apache2/htdocs/

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
