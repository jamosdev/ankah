# Builds both load generators. The Compose services pick which one to run
# with `command: attacker` or `command: legit-probe`; both binaries are on
# PATH in the final image.
FROM golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go vet ./... && go test -race -count=1 ./...
RUN CGO_ENABLED=0 go build -trimpath -o /out/attacker ./cmd/attacker \
 && CGO_ENABLED=0 go build -trimpath -o /out/legit-probe ./cmd/legit-probe

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/attacker /usr/local/bin/attacker
COPY --from=build /out/legit-probe /usr/local/bin/legit-probe
