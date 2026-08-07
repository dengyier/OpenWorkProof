# Contributing to OpenWorkProof

Thanks for your interest in OpenWorkProof! This document will help you get started.

## Project Overview

OpenWorkProof is a protocol for agent work contracts and verifiable execution. It is implemented in Python 3.12 and uses Ed25519 signatures + SQLite for its authoritative ledger.

## Ways to Contribute

### Reporting Issues
- Use the GitHub Issues page to report bugs
- Include a minimal reproducible example
- Specify your environment: OS, Python version, OpenWorkProof version

### Proposing Features
- Start a Discussion first before opening a feature request PR
- Explain the use case and why it matters for multi-agent systems
- Consider the protocol's design principles: Fail Closed, No-Cloning Authority, Offline Verifiability

### Code Contributions

1. **Fork the repository**
2. **Create a branch**: `git checkout -b feature/your-feature`
3. **Run tests**: `python -m pytest -q` （expect 2283+ passed）
4. **Write tests** for your changes
5. **Follow the code style**: the existing codebase follows PEP 8
6. **Open a Pull Request** with a clear description

### Protocol Contributions

OpenWorkProof is a protocol project. Changes to the protocol schema （in `specs/v0.1/`） require:

1. A written rationale explaining the design decision
2. Forward/backward compatibility analysis
3. Updates to the JSON Schema registry
4. Corresponding test coverage

### Good First Issues

Look for issues labeled `good-first-issue` or `help-wanted`. Current areas open for contribution:

- Tool call handler closures
- MCP/A2A framework adapters
- Real-world issue task encapsulation
- Security and compliance reviews
- Documentation improvements

## Development Setup

```bash
python3.12 -m venv .venv
./.venv/bin/python -m pip install -r requirements-lock.txt
./.venv/bin/python -m pip install -e .
./.venv/bin/python -m pytest -q
```

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
