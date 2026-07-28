from importlib.metadata import version

import openworkproof


def test_package_version_is_protocol_version() -> None:
    assert openworkproof.__version__ == "0.1.0"
    assert version("openworkproof") == "0.1.0"
