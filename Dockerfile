# One image for every role. The dependencies go into a virtualenv built with Debian's own
# Python, which is the Python the distroless runtime image ships, so the venv runs there as is.
FROM docker.io/library/debian:13-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /venv
COPY requirements.txt /tmp/requirements.txt
# Hashes pinned in requirements.txt; wheels only, so nothing is compiled.
RUN /venv/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
 && /venv/bin/pip uninstall -y pip
COPY rhcl_probe /app/rhcl_probe
# Byte-compile now: the root filesystem is read-only at run time.
RUN /venv/bin/python -m compileall -q /app/rhcl_probe

# distroless: no shell, no package manager, CA certificates included. Runs as any UID, which
# is what OpenShift's restricted-v2 SCC assigns.
FROM gcr.io/distroless/python3-debian13:nonroot
ARG VERSION=dev
COPY --from=build /venv /venv
COPY --from=build /app /app
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RHCL_PROBE_VERSION=$VERSION
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/venv/bin/python3", "-m", "rhcl_probe"]
