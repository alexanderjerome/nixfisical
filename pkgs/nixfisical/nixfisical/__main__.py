"""Allow ``python -m nixfisical`` as an alias for the console script.

Useful inside a Nix build sandbox or a bare checkout where the entry-point
wrapper has not been installed onto ``PATH``.
"""

from __future__ import annotations

from nixfisical.cli import cli

if __name__ == "__main__":  # pragma: no cover - trivial delegation
    cli()
