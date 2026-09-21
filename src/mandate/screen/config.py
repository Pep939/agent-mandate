"""Choose a content screen from the environment (ADR-0016) — an I/O module.

`MANDATE_CONTENT_SCREEN` picks the backend:

| value | backend |
|---|---|
| unset / `off` / `none` | no screen — content still holds for a person |
| `fixture` | the deterministic keyword screen (demos, pilot, CI) |
| `typesafe` | the vendor adapter; needs `TYPESAFE_API_KEY` |

`MANDATE_CONTENT_SCREEN_MODEL` overrides the pinned model id for `typesafe`
(still refused if it is a floating alias). The API key is read here and
handed to the adapter; it is never logged, rendered, or stored on a claim
(invariant 12).

Swapping in a local, on-prem backend is one more branch in this function —
that is the whole point of the interface.
"""

from __future__ import annotations

import os

from mandate.screen.fixture import FixtureScreen
from mandate.screen.protocol import ContentScreen
from mandate.screen.typesafe import DEFAULT_MODEL, TypeSafeScreen

__all__ = ["ScreenConfigError", "screen_from_env"]

_OFF = frozenset({"", "off", "none", "disabled", "0"})


class ScreenConfigError(ValueError):
    """The environment names a screen that cannot be built."""


def screen_from_env(env: dict[str, str] | None = None) -> ContentScreen | None:
    """Build the configured screen, or `None` when screening is off."""
    source = os.environ if env is None else env
    choice = (source.get("MANDATE_CONTENT_SCREEN") or "").strip().lower()
    if choice in _OFF:
        return None
    if choice == "fixture":
        return FixtureScreen()
    if choice == "typesafe":
        api_key = (source.get("TYPESAFE_API_KEY") or "").strip()
        if not api_key:
            msg = "MANDATE_CONTENT_SCREEN=typesafe requires TYPESAFE_API_KEY"
            raise ScreenConfigError(msg)
        model = (source.get("MANDATE_CONTENT_SCREEN_MODEL") or DEFAULT_MODEL).strip()
        try:
            return TypeSafeScreen(api_key, model=model)
        except ValueError as exc:
            raise ScreenConfigError(str(exc)) from exc
    msg = f"unknown MANDATE_CONTENT_SCREEN {choice!r} (expected fixture, typesafe, or off)"
    raise ScreenConfigError(msg)
