FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 strace gdb libc6 && rm -rf /var/lib/apt/lists/*
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["/usr/bin/python3"]
