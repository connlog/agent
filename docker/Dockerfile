# The ConnLog agent as a container image (docs/topology/PLAN.md, T13.1):
# the released, signed static binary and nothing else. No shell, no package
# manager, no libc: the binary is linked against musl and carries its own
# TLS roots.
#
# Built from a context `context.sh` prepares (the binaries by architecture,
# the directories the agent writes), never from a build inside the image:
# what runs is byte for byte the binary the release signed.
#
# Run it with the host's network (its addresses, neighbours, connections and
# listening ports are the host's) and the host's root read-only at /host (its
# disks and machine id); `compose.yaml` beside this file is the reference.
FROM scratch

ARG TARGETARCH
ARG VERSION=dev

LABEL org.opencontainers.image.title="ConnLog agent" \
      org.opencontainers.image.description="The ConnLog monitoring agent: host metrics and, where allowed, the network it is on" \
      org.opencontainers.image.source="https://github.com/connlog/agent" \
      org.opencontainers.image.url="https://connlog.com" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

COPY --chmod=0755 bin/${TARGETARCH}/connlog-agent /usr/local/bin/connlog-agent
COPY LICENSE THIRD-PARTY-LICENSES.md /usr/share/doc/connlog-agent/
# The state and integrations directories, owned by the agent's user.
COPY --chown=10001:10001 rootfs/ /

# Settings are environment variables, the same names agent.conf holds on a
# systemd install (CONNLOG_TOKEN, CONNLOG_DISCOVERY, CONNLOG_CHECKS,
# CONNLOG_COLLECTOR, ...). These three say where the agent runs.
ENV CONNLOG_PACKAGING=docker \
    CONNLOG_HOST_ROOT=/host \
    CONNLOG_STATE_DIR=/var/lib/connlog

# Unprivileged and without capabilities, as the systemd unit runs it: the
# probes and sweeps use the kernel's ping socket, not a raw one.
USER 10001:10001
VOLUME ["/var/lib/connlog", "/etc/connlog/integrations.d"]
ENTRYPOINT ["/usr/local/bin/connlog-agent"]
