FROM golang:alpine AS builder
ENV GOBIN=/tmp
ENV CGO_ENABLED=0
RUN go install github.com/sivel/amanda@latest

FROM scratch
WORKDIR /root/
COPY --from=builder /tmp/amanda /amanda
VOLUME /artifacts
ENV GIN_MODE=release
ENTRYPOINT ["/amanda", "-artifacts=/artifacts"]
