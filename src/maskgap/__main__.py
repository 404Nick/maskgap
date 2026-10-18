"""Allow ``python -m maskgap`` as an alternative to the ``maskgap`` script."""

from __future__ import annotations

import sys

from maskgap.cli import main

if __name__ == "__main__":
    sys.exit(main())
