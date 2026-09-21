"""Pytest fixtures wrapping the shared Phase 1 factories
(see tests/support/factories.py)."""

from __future__ import annotations

import pytest

from tests.support.factories import (
    make_claim as _make_claim,
)
from tests.support.factories import (
    make_claims as _make_claims,
)
from tests.support.factories import (
    make_deal as _make_deal,
)
from tests.support.factories import (
    make_input as _make_input,
)
from tests.support.factories import (
    make_proposal as _make_proposal,
)
from tests.support.factories import (
    make_record as _make_record,
)
from tests.support.factories import (
    new_ulid as _new_ulid,
)


@pytest.fixture
def ulid():
    return _new_ulid


@pytest.fixture
def make_record():
    return _make_record


@pytest.fixture
def make_claim():
    return _make_claim


@pytest.fixture
def make_claims():
    return _make_claims


@pytest.fixture
def make_deal():
    return _make_deal


@pytest.fixture
def make_proposal():
    return _make_proposal


@pytest.fixture
def make_input():
    return _make_input
