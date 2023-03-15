ARG GOVERSION=1.20.1

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/cs-aws-waf-bouncer

COPY . .

RUN apk update && apk add make
RUN make

FROM alpine:latest

COPY --from=build /go/src/cs-aws-waf-bouncer/crowdsec-aws-waf-bouncer /crowdsec-aws-waf-bouncer
COPY docker/docker_start.sh /

ENTRYPOINT ["/bin/sh", "/docker_start.sh"]
