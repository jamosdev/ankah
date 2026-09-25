# go-dots database for the demo: the upstream schema at the pinned commit,
# with the MySQLNotification UDF and the triggers that call it removed.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS schema
ARG GO_DOTS_COMMIT=4e631d1257fd6a5d1f7201c2d06d63c7ace88940
ARG TEMPLATE_SHA256=85e18d65e607de9f3dbe8fd867decc69d4cd648674ba59ea0fb418c7642b2e54
RUN apk add --no-cache curl
RUN curl -fsSL -o /template.sql \
      "https://raw.githubusercontent.com/nttdots/go-dots/${GO_DOTS_COMMIT}/dots_server/db_models/template.sql" \
 && echo "${TEMPLATE_SHA256}  /template.sql" | sha256sum -c -
COPY strip-udf.awk /strip-udf.awk
RUN awk -f /strip-udf.awk /template.sql > /01-schema.sql \
 && ! grep -q MySQLNotification /01-schema.sql

FROM mysql:5.7.44@sha256:4bc6bc963e6d8443453676cae56536f4b8156d78bae03c0145cbe47c2aad73bb
COPY --from=schema /01-schema.sql /docker-entrypoint-initdb.d/01-schema.sql
COPY 02-seed.sql /docker-entrypoint-initdb.d/02-seed.sql
