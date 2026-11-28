#!/usr/bin/env python3
# ============================================================
# Script:       diagram.py
# Purpose:      Draw an editable network diagram from show output network-snapshot already
#               saved, and/or a spreadsheet of links. One draw.io file with a page per layer
#               (Physical L1, Subnets L3, VLANs L2), a Markdown report with a Mermaid preview,
#               a JSON report, an editable links CSV, and PDF / SVG copies when draw.io Desktop
#               is installed. Written into <repo>/diagrams and committed with the snapshots.
# Usage:        python diagram.py run [--repo ~/network-snapshots] [--links links.csv ...]
#                                     [--site S] [--no-subnet] [--out DIR] [--no-export]
#                                     [--no-commit] [--title T]
#               python diagram.py run --links links.csv --out DIR      (spreadsheet only)
#               python diagram.py tag --device D --role R [--repo DIR] [--write]
# Dependencies: Python 3.9+, pyyaml (already a network-snapshot dependency). draw.io Desktop
#               is optional (PDF and SVG copies).
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/netops-skills (plugins/network-ops)
# Notes:        Never logs in to a device: reads files on disk only. The tag command writes the
#               inventory only with --write, after the user approved that exact change.
# ============================================================
import argparse
import csv
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import yaml

import pluginlib  # noqa: F401
import devicetags
import topology
from topology import short_intf

import drawio

BASENAME = "network-diagram"


def load_inventory(repo):
    f = repo / "inventory.yaml"
    if not f.exists():
        return None
    return yaml.safe_load(f.read_text(encoding="utf-8")) or {}


def build(args):
    repo = Path(args.repo).expanduser()
    topo = topology.new()
    if repo.exists():
        topo = topology.read_snapshot(repo, load_inventory(repo), args.site)
    elif not args.links:
        sys.exit(f"diagram.py: no snapshot repo at {repo} and no --links: run network-snapshot first, "
                 "or give a spreadsheet of links")
    topology.build_links(topo, subnets=not args.no_subnet)
    rows = sum(topology.read_csv(topo, Path(p).expanduser()) for p in args.links)
    for l in topo["links"]:
        l["kind"] = topology.link_kind(l)
    return repo, topo, rows


# ---------- report ----------
def mermaid(topo):
    ids = {n: f"n{i}" for i, n in enumerate(sorted(topo["devices"]))}
    arrow = {topology.NEIGHBOR: "---", topology.SPREADSHEET: "---", topology.SUBNET: "-.-", topology.TUNNEL: "-.-"}
    lines = ["graph TD"]
    by_site = {}
    for n, d in topo["devices"].items():
        by_site.setdefault(d["site"] or "not in inventory", []).append(n)
    for i, (site, names) in enumerate(sorted(by_site.items())):
        lines.append(f'  subgraph s{i}["{site}"]')
        lines += [f'    {ids[n]}["{n}"]' for n in sorted(names)]
        lines.append("  end")
    for l in sorted(topo["links"], key=lambda l: (l["a"], l["a_intf"])):
        label = f"{short_intf(l['a_intf'])} - {short_intf(l['b_intf'])}".strip(" -")
        if l["kind"] in (topology.SUBNET, topology.TUNNEL):
            label += f" ({l['kind']})"
        lines.append(f"  {ids[l['a']]} {arrow[l['kind']]}|\"{label}\"| {ids[l['b']]}" if label
                     else f"  {ids[l['a']]} {arrow[l['kind']]} {ids[l['b']]}")
    return "\n".join(lines)


def summary(topo, rows, files, exported, pages):
    devs = topo["devices"]
    return {
        "generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "devices": len(devs),
        "links": len(topo["links"]),
        "links_by_kind": dict(Counter(l["kind"] for l in topo["links"])),
        "spreadsheet_rows": rows,
        "pages": pages,
        "subnet_links": [f"{l['a']} {short_intf(l['a_intf'])} - {l['b']} {short_intf(l['b_intf'])} ({l['note']}, {l['kind']})"
                         for l in topo["links"] if l["kind"] in (topology.SUBNET, topology.TUNNEL)],
        "port_channels": [f"{l['a']} {short_intf(l['a_intf'])} - {l['b']} {short_intf(l['b_intf'])}: "
                          + ", ".join(f"{short_intf(x)}-{short_intf(y)}" for x, y in l["members"])
                          for l in topo["links"] if l["members"]],
        "roles": {n: {"role": d["role"], "source": d["role_source"]} for n, d in sorted(devs.items())},
        "roles_to_confirm": sorted(n for n, d in devs.items() if d["role"] and d["role_source"] != "inventory"
                                   and (d["in_inventory"] or d["seen_files"])),
        "roles_missing": sorted(n for n, d in devs.items() if not d["role"]),
        "unlinked_devices": topology.unlinked(topo),
        "unknown_neighbors": sorted(topo["unknown_neighbors"]),
        "coverage_gaps": topo["gaps"],
        "files": files,
        "exports": exported,
    }


def write_report(path, topo, rep):
    k = rep["links_by_kind"]
    out = [f"# Network diagram: {rep['devices']} devices, {rep['links']} links", "",
           f"Generated {rep['generated']}. Open `{Path(rep['files']['drawio']).name}` in draw.io "
           "(app.diagrams.net: File > Open from > Device); its pages are: " + ", ".join(rep["pages"]) + ".", "",
           "| Link kind | Count | How it was found |", "|---|---|---|",
           f"| Neighbor link | {k.get('neighbor', 0)} | The device reported it (CDP or LLDP) |",
           f"| Subnet link | {k.get('subnet', 0)} | Two interfaces share a /30 or /31 subnet; no neighbor protocol saw it |",
           f"| Tunnel | {k.get('tunnel', 0)} | Two tunnel interfaces share a subnet |",
           f"| Spreadsheet | {k.get('spreadsheet', 0)} | Your CSV |", ""]
    if rep["subnet_links"]:
        out += ["## Links neighbor discovery can't see", "",
                "Drawn dashed. Firewalls and tunnels often don't speak CDP or LLDP; these were matched by address:", ""]
        out += [f"- {s}" for s in rep["subnet_links"]] + [""]
    if rep["port_channels"]:
        out += ["## Port-channels", ""] + [f"- {s}" for s in rep["port_channels"]] + [""]
    if rep["roles_to_confirm"] or rep["roles_missing"]:
        out += ["## Device roles to confirm", "",
                "The layout uses each device's role (provider, edge, firewall, core, distribution, access). "
                "These were guessed or are missing; confirm with the tag command (it writes the inventory "
                "only with --write, after you approve):", ""]
        for n in rep["roles_to_confirm"]:
            r = rep["roles"][n]
            out.append(f"- {n}: **{r['role']}** ({r['source']}): `diagram.py tag --device {n} --role {r['role']}`")
        for n in rep["roles_missing"]:
            out.append(f"- {n}: no role: `diagram.py tag --device {n} --role <provider|edge|firewall|core|distribution|access>`")
        out.append("")
    if rep["unknown_neighbors"]:
        out += ["## Unknown neighbors", "", "Seen by CDP/LLDP but not in the inventory (drawn grey):", ""]
        out += [f"- {n}" for n in rep["unknown_neighbors"]] + [""]
    if rep["unlinked_devices"]:
        out += ["## Unlinked devices", "", "In the inventory, but no link was found (drawn, never dropped):", ""]
        out += [f"- {n}" for n in rep["unlinked_devices"]] + [""]
    if rep["coverage_gaps"]:
        out += ["## Coverage gaps", ""] + [f"- {g['device']}: {g['gap']} ({g['fix']})" for g in rep["coverage_gaps"]] + [""]
    if not rep["exports"].get("done"):
        out += ["## PDF and SVG copies", "", rep["exports"].get("why", ""), ""]
    out += ["## Preview (physical links)", "", "```mermaid", mermaid(topo), "```", ""]
    path.write_text("\n".join(out), encoding="utf-8")


def write_links_csv(path, topo):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["device_a", "port_a", "port_b", "device_b", "found_by", "description"])
        for l in sorted(topo["links"], key=lambda l: (l["a"], l["a_intf"])):
            w.writerow([l["a"], short_intf(l["a_intf"]), short_intf(l["b_intf"]), l["b"],
                        "+".join(sorted(l["sources"])), l["note"]])


# ---------- draw.io Desktop exports ----------
def find_drawio():
    for name in ("drawio", "draw.io"):
        if shutil.which(name):
            return shutil.which(name)
    for p in (Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "draw.io" / "draw.io.exe",
              Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "draw.io" / "draw.io.exe",
              Path("/Applications/draw.io.app/Contents/MacOS/draw.io")):
        if p.exists():
            return str(p)
    return None


def export(drawio_file, out):
    exe = find_drawio()
    if not exe:
        return {"done": False, "why": "draw.io Desktop isn't installed, so no PDF or SVG copy was made. The .drawio "
                                      "file opens in app.diagrams.net with nothing installed."}
    made, errors = [], []
    jobs = [(["-x", "-f", "pdf", "-a", "-o", str(out / f"{BASENAME}.pdf")], f"{BASENAME}.pdf"),
            (["-x", "-f", "svg", "--embed-diagram", "-p", "0", "-o", str(out / f"{BASENAME}.drawio.svg")],
             f"{BASENAME}.drawio.svg")]
    for args, name in jobs:
        try:
            r = subprocess.run([exe, *args, str(drawio_file)], capture_output=True, text=True, timeout=120)
            (made if r.returncode == 0 and (out / name).exists() else errors).append(name)
        except (OSError, subprocess.TimeoutExpired) as e:
            errors.append(f"{name} ({type(e).__name__})")
    return {"done": bool(made), "made": made, "failed": errors,
            "why": "" if made else f"draw.io Desktop ({exe}) could not export: {', '.join(errors)}"}


def commit(repo, out):
    if not (repo / ".git").exists() or repo not in out.parents:
        return "not committed (output is not inside a git snapshot repo)"
    rel = out.relative_to(repo)
    subprocess.run(["git", "-C", str(repo), "add", str(rel)], capture_output=True, text=True)
    r = subprocess.run(["git", "-C", str(repo), "commit", "-m", f"network-diagram: {dt.date.today()}", "--", str(rel)],
                       capture_output=True, text=True)
    if r.returncode == 0:
        return "committed"
    return "nothing changed since the last diagram" if "nothing" in (r.stdout + r.stderr) else \
        f"not committed: {(r.stderr or r.stdout).strip().splitlines()[-1:]}"


def run(args):
    repo, topo, rows = build(args)
    out = Path(args.out).expanduser() if args.out else repo / "diagrams"
    out.mkdir(parents=True, exist_ok=True)
    files = {"drawio": str(out / f"{BASENAME}.drawio"), "report": str(out / "report.md"),
             "json": str(out / "report.json"), "links_csv": str(out / "links.csv")}
    pages = drawio.write(Path(files["drawio"]), topo, args.title)
    exported = {"done": False, "why": "exports skipped (--no-export)"} if args.no_export else export(Path(files["drawio"]), out)
    write_links_csv(Path(files["links_csv"]), topo)
    rep = summary(topo, rows, files, exported, pages)
    write_report(Path(files["report"]), topo, rep)
    Path(files["json"]).write_text(json.dumps(rep, indent=1), encoding="utf-8")
    rep["git"] = "not committed (--no-commit)" if args.no_commit else commit(repo, out)
    print(json.dumps(rep, indent=1))


def tag(args, ap):
    if not args.device or not args.role:
        ap.error("tag needs --device NAME and --role ROLE")
    inv = Path(args.repo).expanduser() / "inventory.yaml"
    try:
        out = devicetags.apply(inv, args.device, {"role": args.role}, args.write,
                               allowed={"role": devicetags.ROLES})
    except (devicetags.TagError, OSError, yaml.YAMLError) as e:
        ap.exit(2, f"diagram.py tag: {e}\n")
    print(json.dumps(out, indent=1))


def main():
    ap = argparse.ArgumentParser(description="Network diagram (draw.io) from saved show output and/or a CSV of links.")
    ap.add_argument("action", choices=["run", "tag"])
    ap.add_argument("--repo", default="~/network-snapshots", help="network-snapshot repo (default ~/network-snapshots)")
    ap.add_argument("--links", action="append", default=[], help="run: CSV of links (device, port, port, device), repeatable")
    ap.add_argument("--site", help="run: draw one site only")
    ap.add_argument("--no-subnet", action="store_true", help="run: neighbor and spreadsheet links only")
    ap.add_argument("--out", help="run: output folder (default <repo>/diagrams)")
    ap.add_argument("--no-export", action="store_true", help="run: skip the PDF / SVG copies")
    ap.add_argument("--no-commit", action="store_true", help="run: don't commit the diagram to the snapshot repo")
    ap.add_argument("--title", default="Network", help="run: diagram title")
    ap.add_argument("--device", help="tag: device name")
    ap.add_argument("--role", help="tag: " + " | ".join(devicetags.ROLES))
    ap.add_argument("--write", action="store_true", help="tag: write the change (only after the user approved it)")
    args = ap.parse_args()
    return run(args) if args.action == "run" else tag(args, ap)


if __name__ == "__main__":
    sys.exit(main())
