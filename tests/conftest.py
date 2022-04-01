import os

import pytest


@pytest.fixture(scope="session")
def test_directory():
    return os.path.dirname(__file__)
