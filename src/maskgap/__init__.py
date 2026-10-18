"""maskgap — find the gaps in your CI secret masking.

The package is intentionally dependency-free (Python standard library only) and
makes no network requests of any kind. See ``docs/design.md`` for the
architecture and ``docs/github-masking.md`` for how the GitHub Actions runner
masking coverage that maskgap models was established.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
