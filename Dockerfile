FROM --platform=$BUILDPLATFORM golang:1.26.4-alpine AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN mkdir -p web
COPY web/index.html ./web/index.html
RUN test "$TARGETOS" = "linux" && test "$TARGETARCH" = "amd64" \
    && mkdir -p /out \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -trimpath -ldflags="-s -w" -o /out/mcp-ssh-go .

FROM alpine:3.22

COPY --from=build /out/mcp-ssh-go /usr/local/bin/mcp-ssh-go
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

WORKDIR /app
VOLUME ["/app"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
