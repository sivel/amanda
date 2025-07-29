FROM scratch
ARG TARGETARCH
COPY build/amanda_linux_${TARGETARCH} /amanda
VOLUME /artifacts
ENV GIN_MODE=release
ENTRYPOINT ["/amanda", "-artifacts=/artifacts"]
