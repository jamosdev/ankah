FROM haproxy:3.2.23-alpine
USER root
RUN apk add --no-cache openssl
COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
COPY start.sh /start.sh
RUN chmod +x /start.sh
ENTRYPOINT ["/start.sh"]
