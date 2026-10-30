"""Entry point for ``python -m zoog_cn_bypass`` and ``python <package dir>``."""

import os
import sys

if __package__ in (None, ""):
    # Started as ``python path\to\zoog_cn_bypass``: make the package importable.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zoog_cn_bypass.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
