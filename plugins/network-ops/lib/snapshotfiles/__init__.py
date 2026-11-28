# ============================================================
# Package:      snapshotfiles
# Purpose:      How network-snapshot names the files it saves: one file per show command, named
#               from the command. network-snapshot writes them under this name and any skill
#               that reads a snapshot (network-vuln-scan's coverage gaps) finds them by it.
# Usage:        from snapshotfiles import slug
#               slug("show running-config")    # "show-running-config.txt"
# Author:       G Talks Tech
# Notes:        See lib/README.md. Pure function, no I/O.
# ============================================================
import re


def slug(cmd):
    """The file a command's output is saved to: lower case, every run of other characters as
    one '-', trimmed, plus '.txt'."""
    return re.sub(r"[^a-z0-9]+", "-", cmd.lower()).strip("-") + ".txt"
