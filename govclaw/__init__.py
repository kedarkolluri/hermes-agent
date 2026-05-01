"""GovClaw — stakeholder governance runtime for Hermes persona agents.

Library entry point. The plugin shim at ``plugins/govclaw/`` wires
:func:`govclaw.plugin.register` into the Hermes plugin system; everything
governance-related lives here so it's importable for tests and CLI without
loading the plugin loader.

See ``plugins/govclaw/README.md`` for the user-facing overview and
``/root/.claude/plans/govclaw-stakeholder-governance-parallel-pumpkin.md``
for the design rationale.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
