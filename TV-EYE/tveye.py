#!/usr/bin/env python3
"""TV-EYE launcher script - run `python tveye.py` to start the console.

Author : Mr_TV
Telegram : @Mr_TV_ir
GitHub : https://github.com/TV-CENTER
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tveye.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
