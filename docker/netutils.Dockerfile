# Network tooling for the range: tcpdump (capture sensor) and tshark/capinfos
# (evidence and pcap checks). Runs tools inside Docker so nothing is installed on the host.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      tcpdump tshark iputils-ping ca-certificates libcap2-bin \
 && rm -rf /var/lib/apt/lists/*
# The sensor never runs as root: tcpdump gets only the raw-socket file capability and
# runs as the host user (compose `user:`), so pcaps on the host belong to that user.
RUN setcap cap_net_raw=eip "$(command -v tcpdump)"
WORKDIR /work
