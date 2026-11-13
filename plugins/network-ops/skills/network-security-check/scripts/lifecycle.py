# ============================================================
# Script:       lifecycle.py
# Purpose:      Software end-of-support check (CISA BOD 26-02). Maps each device's running
#               version to its release train and looks the train up in settings/lifecycle.yaml:
#               LIFECYCLE-EOS when the train is past its last security fix date,
#               LIFECYCLE-SOON when that date is within 12 months.
# Author:       G Talks Tech
# Notes:        Read-only, works from the version network-snapshot saved. Dates only come from
#               vendor pages (research/sources.md). Hardware end of life is out of scope.
# ============================================================
import datetime as dt
import re
from pathlib import Path

import yaml

from common import fails, result

SETTINGS = Path(__file__).resolve().parent.parent / "settings"
CHECKS = ("LIFECYCLE-EOS", "LIFECYCLE-SOON")
SOON_DAYS = 365        # BOD 26-02: inventory edge devices reaching EOS within the next 12 months
STALE_TABLE_DAYS = 180  # a vendor table older than this gets a "re-read the page" note


def load(path=None):
    return yaml.safe_load(Path(path or SETTINGS / "lifecycle.yaml").read_text(encoding="utf-8")) or {}


def _date(v):
    return v if isinstance(v, dt.date) else dt.date.fromisoformat(str(v))


def train(version):
    """First two numbers of a version: 17.09.04a -> '17.9', v7.4.2 -> '7.4', 21.4R3-S5 -> '21.4'.
    Junos special trains (15.1X49) return None: they are not in the table by train."""
    v = str(version or "").strip()
    if re.search(r"^\D*\d+\.\d+X\d", v, re.I):
        return None
    nums = re.findall(r"\d+", v)
    return f"{int(nums[0])}.{int(nums[1])}" if len(nums) >= 2 else None


def evaluate(dev, table, today=None):
    """LIFECYCLE-EOS and LIFECYCLE-SOON results for one device (device_facts output)."""
    today = today or dt.date.today()
    plat = table.get(dev.get("platform"))
    if not plat:
        why = f"no lifecycle table for platform '{dev.get('platform')}'"
        return [result(c, "n/a", why) for c in CHECKS]
    if not dev.get("version"):
        return [result(c, "not-visible", "software version not found in the snapshot") for c in CHECKS]
    tr = train(dev["version"])
    row = (plat.get("trains") or {}).get(tr)
    if not row:
        why = f"lifecycle unknown for {plat['name']} train {tr or dev['version']}, check vendor page " \
              f"{plat['vendor_page']}"
        return [result(c, "n/a", why) for c in CHECKS]
    field = next((f for f in plat["security_end"] if row.get(f)), None)
    end = _date(row[field])
    labels = plat.get("labels", {})
    page = row.get("url") or plat["vendor_page"]
    dates = "; ".join(f"{labels.get(k, k)} {_date(v).isoformat()}" for k, v in row.items()
                      if k in labels)
    src = f"{dates}. Source: {page}" + (f" ({row['note']})" if row.get("note") else "")
    head = f"{plat['name']} {dev['version']} (train {tr})"
    days = (end - today).days
    if days < 0:
        eos = result("LIFECYCLE-EOS", "fail", f"{head} is past its {labels.get(field, field)} "
                     f"({end.isoformat()}, {-days} days ago): no more security fixes. {src}",
                     [f"version {dev['version']}"], exposed=dev.get("internet_facing"))
        soon = result("LIFECYCLE-SOON", "n/a", "already past end of security fixes (LIFECYCLE-EOS)")
    else:
        eos = result("LIFECYCLE-EOS", "pass", f"{head} gets security fixes until {end.isoformat()}. {src}")
        if days <= SOON_DAYS:
            # A planning item: never scored above the lowest band (SCORING.md house rule).
            soon = result("LIFECYCLE-SOON", "fail", f"{head} reaches its {labels.get(field, field)} on "
                          f"{end.isoformat()}, in {days} days: plan the upgrade. {src}",
                          [f"version {dev['version']}"], exposed=False)
        else:
            soon = result("LIFECYCLE-SOON", "pass", f"{head}: more than 12 months of security fixes left "
                          f"(until {end.isoformat()})")
    return [eos, soon]


def stale_notes(table, today=None):
    today = today or dt.date.today()
    out = []
    for p, plat in table.items():
        age = (today - _date(plat["as_of"])).days
        if age > STALE_TABLE_DAYS:
            out.append(f"lifecycle dates for {plat.get('name', p)} were read {age} days ago ({plat['as_of']}): "
                       f"re-read {plat['vendor_page']} and update settings/lifecycle.yaml")
    return out


def apply(facts, notes, today=None, table=None):
    """Add lifecycle results to every checked device and their fails to its findings."""
    table = load() if table is None else table
    for d in facts:
        if "kind" not in d:      # platform with no security settings: nothing else ran either
            continue
        res = evaluate(d, table, today)
        d["results"] = d.get("results", []) + res
        d["findings"] = d.get("findings", []) + fails(res)
        rc = d.setdefault("result_counts", {})
        for r in res:
            rc[r["status"]] = rc.get(r["status"], 0) + 1
    notes += stale_notes(table, today)
    if any(r["status"] == "fail" for d in facts for r in d.get("results", []) if r["check"] in CHECKS):
        notes.append("lifecycle checks cover software trains only: hardware end of life is not checked")


def validate(table, source_keys):
    """check-settings: schema problems in lifecycle.yaml, as strings."""
    bad = []
    for p, plat in (table or {}).items():
        for k in ("name", "vendor_page", "as_of", "security_end", "trains"):
            if k not in plat:
                bad.append(f"lifecycle {p}: missing {k}")
        try:
            _date(plat.get("as_of"))
        except (TypeError, ValueError):
            bad.append(f"lifecycle {p}: as_of '{plat.get('as_of')}' is not YYYY-MM-DD")
        for t, row in (plat.get("trains") or {}).items():
            if not any(row.get(f) for f in plat.get("security_end", [])):
                bad.append(f"lifecycle {p} {t}: none of {plat.get('security_end')} is set")
            if row.get("source") not in source_keys:
                bad.append(f"lifecycle {p} {t}: source '{row.get('source')}' not in research/sources.md")
            for k, v in row.items():
                if k in plat.get("labels", {}):
                    try:
                        _date(v)
                    except (TypeError, ValueError):
                        bad.append(f"lifecycle {p} {t}: {k} '{v}' is not YYYY-MM-DD")
    return bad
