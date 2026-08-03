FROM docker.io/library/python@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ARG OWP_SOURCE_REVISION
LABEL org.opencontainers.image.title="OpenWorkProof Rich execution/test candidate" \
      org.opencontainers.image.description="Offline Python 3.12 pytest runtime for the fixed Rich 15 source test" \
      org.opencontainers.image.source="https://github.com/dengyier/OpenWorkProof" \
      org.opencontainers.image.revision=$OWP_SOURCE_REVISION \
      org.openworkproof.image.role=execution-test \
      org.openworkproof.base.digest=sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ENV HOME=/nonexistent \
    LC_ALL=C.UTF-8 \
    PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
    TZ=UTC

COPY requirements.lock /tmp/requirements.lock
COPY wheels/ /tmp/wheels/
RUN cd /tmp/wheels/ \
    && sha256sum -c SHA256SUMS \
    && python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install \
        --disable-pip-version-check \
        --no-cache-dir \
        --no-index \
        --require-hashes \
        --find-links=/tmp/wheels \
        --only-binary=:all: \
        --no-deps \
        --requirement /tmp/requirements.lock \
    && /opt/venv/bin/python -m pip check \
    && rm -rf /tmp/requirements.lock /tmp/wheels

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/bin/env", "--"]
CMD ["/opt/venv/bin/python", "-I", "-m", "pytest"]
