FROM httpd:2.4

LABEL description="Apache 2.4 — intentionally vulnerable: no timeouts, SYN cookies disabled"

# Minimal config — no protection at all
COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY vhost.conf /usr/local/apache2/conf/extra/vhost.conf
COPY www/ /usr/local/apache2/htdocs/

EXPOSE 80

CMD ["httpd", "-D", "FOREGROUND"]
