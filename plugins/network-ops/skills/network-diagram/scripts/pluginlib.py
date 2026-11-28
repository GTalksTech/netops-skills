# ============================================================
# Script:       pluginlib.py
# Purpose:      Put the network-ops shared library (plugins/network-ops/lib, see its
#               README.md) on the import path. Import this before any shared package:
#                   import pluginlib  # noqa: F401
#                   import devicefacts
# Author:       G Talks Tech
# ============================================================
import sys
from pathlib import Path

LIB = Path(__file__).resolve().parents[3] / "lib"
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
