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

COPY Dockerfile requirements.lock run_tests_runner.py verifier_test.py SHA256SUMS /tmp/context/
RUN cd /tmp/context/ \
    && sha256sum -c SHA256SUMS \
    && rm -rf /tmp/context

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

COPY run_tests_runner.py /opt/openworkproof/run_tests_runner.py
COPY verifier_test.py /tmp/verifier_test.py

RUN install -d -o 0 -g 0 -m 0555 /fixed-tests \
    && install -o 0 -g 0 -m 0444 /tmp/verifier_test.py /fixed-tests/verifier_test.py \
    && rm /tmp/verifier_test.py

RUN install -d -o 65532 -g 65532 -m 0755 /workspace /output

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/opt/venv/bin/python", "-I", "/opt/openworkproof/run_tests_runner.py"]
CMD ["execute"]
