FROM golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS build
WORKDIR /src
COPY third_party/fetch-go-dots.sh third_party/fetch-go-dots.sh
COPY third_party/patches third_party/patches
RUN sh third_party/fetch-go-dots.sh
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV GOFLAGS=-tags=dots_nocoap
RUN go vet ./... && go test -race -count=1 ./...
RUN CGO_ENABLED=0 go build -trimpath -o /out/edge ./cmd/edge

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/edge /usr/local/bin/edge
COPY dots_server.yaml /etc/edge/dots_server.yaml
COPY start.sh /start.sh
ENTRYPOINT ["/start.sh"]
