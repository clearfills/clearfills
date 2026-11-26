# ClearFills Isolated Execution Worker (Separate-User Docker Kit)
# Runs clearfills-desk (`clearfills watch`) as non-root user clearfills:clearfills (UID 10001)
# with 0600 file creation permissions inside a dedicated state volume inaccessible to host coding agents.

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CLEARFILLS_DESK_STATE=/var/lib/clearfills/state \
    CLEARFILLS_DESK_CONFIG=/etc/clearfills/clearfills.yaml \
    CLEARFILLS_REQUIRE_PASSKEY_COSIGN=1 \
    CLEARFILLS_REQUIRE_PASSKEY_UV=1

# Dedicated non-root user (UID/GID 10001) isolated from host developer UIDs (501/1000)
RUN groupadd --gid 10001 clearfills \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/clearfills --create-home --shell /usr/sbin/nologin clearfills

WORKDIR /opt/clearfills

# Copy open-core repository and install clearfills + clearfills-desk + ib-async
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY packages ./packages

RUN pip install --no-cache-dir '.[ibkr]'

# Prepare state and config directories with strict ownership & permissions
RUN mkdir -p /var/lib/clearfills/state /etc/clearfills \
    && chown -R 10001:10001 /var/lib/clearfills /etc/clearfills \
    && chmod 0700 /var/lib/clearfills /var/lib/clearfills/state \
    && chmod 0750 /etc/clearfills

# Entrypoint enforces umask 0077 (0600 files, 0700 dirs) and tightens existing state files
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'umask 0077' \
    'if [ -d "${CLEARFILLS_DESK_STATE:-/var/lib/clearfills/state}" ]; then' \
    '  find "${CLEARFILLS_DESK_STATE:-/var/lib/clearfills/state}" -maxdepth 2 -type f -exec chmod 0600 {} + 2>/dev/null || true' \
    'fi' \
    'exec "$@"' \
    > /usr/local/bin/clearfills-entrypoint.sh \
    && chmod 0755 /usr/local/bin/clearfills-entrypoint.sh

USER 10001:10001
WORKDIR /var/lib/clearfills

VOLUME ["/var/lib/clearfills/state"]

ENTRYPOINT ["/usr/local/bin/clearfills-entrypoint.sh"]
CMD ["clearfills", "watch", "--config", "/etc/clearfills/clearfills.yaml", "--state-dir", "/var/lib/clearfills/state"]
