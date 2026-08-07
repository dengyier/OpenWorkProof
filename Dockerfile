FROM python:3.12-slim

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml requirements-lock.txt ./
COPY src/ ./src/
COPY README.md README_en.md ./
COPY supply-chain/ ./supply-chain/

# Install dependencies and package
RUN pip install --no-cache-dir -r requirements-lock.txt && \
    pip install --no-cache-dir -e .

# Create non-root user
RUN useradd -m -u 1000 owp && chown -R owp:owp /app
USER owp

# Default command: show help
CMD ["owp", "--help"]
