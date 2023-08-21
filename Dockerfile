ARG GOVERSION=1.20.7

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/cs-aws-waf-bouncer

RUN apk add --update --no-cache make git
COPY . .

RUN make build

FROM alpine:latest
COPY --from=build /go/src/cs-aws-waf-bouncer/crowdsec-aws-waf-bouncer /crowdsec-aws-waf-bouncer
COPY docker/docker_start.sh /

ENTRYPOINT ["/bin/sh", "/docker_start.sh"]
