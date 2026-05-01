"""govclaw plugin shim.

The actual governance runtime lives in the top-level ``govclaw`` package
(importable for tests and CLI without booting the plugin loader). This
shim exists only so the Hermes plugin discoverer at
``hermes_cli/plugins.py`` finds and loads us via the standard
``plugins/<name>/`` convention.

See ``govclaw.plugin.register`` for the actual hook wiring.
"""

from __future__ import annotations

from govclaw.plugin import register  # noqa: F401 — re-exported for the loader

__all__ = ["register"]
