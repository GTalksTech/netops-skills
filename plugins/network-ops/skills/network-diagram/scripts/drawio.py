# ============================================================
# Script:       drawio.py
# Purpose:      Write a topology (lib/topology) as one editable draw.io file with a page per
#               layer: Physical (L1) links with interface names, Subnets (L3) with each subnet as
#               a node, and VLANs (L2) with trunks and the VLANs on each switch. The file is
#               draw.io's XML (mxfile): app.diagrams.net opens it with no install.
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/netops-skills (plugins/network-ops)
# ============================================================
import html
import ipaddress
import xml.etree.ElementTree as ET
from collections import defaultdict, deque

import pluginlib  # noqa: F401
import topology
from topology import short_intf

TIER = {"provider": 0, "edge": 1, "firewall": 2, "core": 3, "distribution": 4, "access": 5}
UNPLACED = 6
W, H, GAP_X, GAP_Y, SITE_GAP, MARGIN = 60, 60, 190, 160, 90, 40

SHAPE = {"provider": "shape=cloud;", "edge": "shape=mxgraph.cisco19.rect;prIcon=router;",
         "firewall": "shape=mxgraph.cisco19.rect;prIcon=firewall;",
         "core": "shape=mxgraph.cisco19.rect;prIcon=l3_switch;",
         "distribution": "shape=mxgraph.cisco19.rect;prIcon=l3_switch;",
         "access": "shape=mxgraph.cisco19.rect;prIcon=l2_switch;",
         None: "shape=mxgraph.cisco19.rect;prIcon=router;"}
LINE = {topology.NEIGHBOR: "strokeColor=#005073;strokeWidth=2;",
        topology.SPREADSHEET: "strokeColor=#1E8449;strokeWidth=2;",
        topology.SUBNET: "strokeColor=#C0392B;strokeWidth=2;dashed=1;",
        topology.TUNNEL: "strokeColor=#8E44AD;strokeWidth=2;dashed=1;dashPattern=8 4;"}
LEGEND = [(topology.NEIGHBOR, "Neighbor link (CDP / LLDP)"),
          (topology.SUBNET, "Subnet link (shared /30 or /31, no CDP/LLDP)"),
          (topology.TUNNEL, "Tunnel (shared tunnel subnet)"),
          (topology.SPREADSHEET, "From your spreadsheet")]


# ---------- layout: one column block per site, device roles top to bottom ----------
def tiers(topo):
    """Each device's row: its role's tier; a device without a role sits one row below the
    nearest device that has one (then it is listed in the report as unplaced)."""
    tier = {n: TIER[d["role"]] for n, d in topo["devices"].items() if d["role"] in TIER}
    adj = defaultdict(set)
    for l in topo["links"]:
        adj[l["a"]].add(l["b"])
        adj[l["b"]].add(l["a"])
    q = deque(sorted(tier))
    while q:
        n = q.popleft()
        for m in sorted(adj[n]):
            if m not in tier:
                tier[m] = min(tier[n] + 1, UNPLACED)
                q.append(m)
    for n in topo["devices"]:
        tier.setdefault(n, UNPLACED)
    return tier


def layout(topo):
    """{device: (x, y)} and site boxes [(site, x, y, w, h)]. A site holding only provider
    devices is a band across the top, so its links fan down to every site."""
    tier = tiers(topo)
    sites = defaultdict(list)
    for n, d in topo["devices"].items():
        sites[d["site"] or "not in inventory"].append(n)
    top = [s for s in sites if len(sites) > 1 and all(tier[n] == 0 for n in sites[s])]
    pos, boxes, x0 = {}, [], MARGIN
    order = sorted((s for s in sites if s not in top), key=lambda s: (min(tier[n] for n in sites[s]), -len(sites[s]), s))
    for site in order:
        rows = defaultdict(list)
        for n in sorted(sites[site]):
            rows[tier[n]].append(n)
        width = max(len(r) for r in rows.values()) * GAP_X
        for t, members in rows.items():
            start = x0 + (width - len(members) * GAP_X) / 2
            for i, n in enumerate(members):
                pos[n] = (start + i * GAP_X + (GAP_X - W) / 2, MARGIN + 60 + t * GAP_Y)
        lo, hi = min(rows), max(rows)
        boxes.append((site, x0 - 10, MARGIN + 20 + lo * GAP_Y, width + 20, (hi - lo + 1) * GAP_Y + 20))
        x0 += width + SITE_GAP
    if top:
        names = sorted(n for s in top for n in sites[s])
        width = len(names) * GAP_X
        start = max(MARGIN, (x0 - SITE_GAP + MARGIN - width) / 2)
        for i, n in enumerate(names):
            pos[n] = (start + i * GAP_X + (GAP_X - W) / 2, MARGIN + 60)
        boxes.append((" / ".join(sorted(top)), start - 10, MARGIN + 20, width + 20, GAP_Y - 20))
    return pos, boxes


# ---------- XML helpers ----------
class Page:
    def __init__(self, mxfile, pid, name):
        model = ET.SubElement(ET.SubElement(mxfile, "diagram", id=pid, name=name), "mxGraphModel",
                              grid="1", gridSize="10", guides="1", tooltips="1", page="1",
                              pageWidth="1654", pageHeight="1169")
        self.root = ET.SubElement(model, "root")
        ET.SubElement(self.root, "mxCell", id=f"{pid}-0")
        ET.SubElement(self.root, "mxCell", id=f"{pid}-1", parent=f"{pid}-0")
        self.pid, self.n = pid, 0

    def id(self, prefix):
        self.n += 1
        return f"{self.pid}-{prefix}{self.n}"

    def vertex(self, value, style, x, y, w, h, tooltip=None, parent=None, cid=None):
        cid = cid or self.id("v")
        if tooltip:
            obj = ET.SubElement(self.root, "object", id=cid, label=value, tooltip=tooltip)
            c = ET.SubElement(obj, "mxCell", style=style, vertex="1", parent=parent or f"{self.pid}-1")
        else:
            c = ET.SubElement(self.root, "mxCell", id=cid, value=value, style=style, vertex="1",
                              parent=parent or f"{self.pid}-1")
        ET.SubElement(c, "mxGeometry", x=str(round(x)), y=str(round(y)), width=str(w), height=str(h),
                      **{"as": "geometry"})
        return cid

    def edge(self, src, dst, style, value="", tooltip=None):
        cid = self.id("e")
        if tooltip:
            obj = ET.SubElement(self.root, "object", id=cid, label=value, tooltip=tooltip)
            c = ET.SubElement(obj, "mxCell", style=style, edge="1", parent=f"{self.pid}-1", source=src, target=dst)
        else:
            c = ET.SubElement(self.root, "mxCell", id=cid, value=value, style=style, edge="1",
                              parent=f"{self.pid}-1", source=src, target=dst)
        ET.SubElement(c, "mxGeometry", relative="1", **{"as": "geometry"})
        return cid

    def edge_label(self, edge_id, text, frac):
        c = ET.SubElement(self.root, "mxCell", id=self.id("l"), value=text,
                          style="edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;fontSize=10;"
                                "labelBackgroundColor=#FFFFFF;",
                          vertex="1", connectable="0", parent=edge_id)
        ET.SubElement(c, "mxGeometry", x=str(frac), relative="1", **{"as": "geometry"})

    def legend(self, x, y, items):
        for i, (style, text) in enumerate(items):
            c = ET.SubElement(self.root, "mxCell", id=self.id("g"), value="", style=f"endArrow=none;html=1;{style}",
                              edge="1", parent=f"{self.pid}-1")
            g = ET.SubElement(c, "mxGeometry", relative="1", **{"as": "geometry"})
            ET.SubElement(g, "mxPoint", x=str(x), y=str(y + i * 24), **{"as": "sourcePoint"})
            ET.SubElement(g, "mxPoint", x=str(x + 40), y=str(y + i * 24), **{"as": "targetPoint"})
            self.vertex(html.escape(text), "text;html=1;align=left;verticalAlign=middle;fontSize=11;",
                        x + 48, y + i * 24 - 10, 320, 20)


def _device_cells(page, topo, pos, boxes, label=lambda d: html.escape(d["name"]), tip=None):
    for site, x, y, w, h in boxes:
        page.vertex(html.escape(site), "rounded=1;dashed=1;fillColor=none;strokeColor=#999999;verticalAlign=top;"
                    "align=left;spacingLeft=8;fontStyle=1;html=1;", x, y, w, h)
    ids = {}
    for n, d in sorted(topo["devices"].items()):
        x, y = pos[n]
        known = d["in_inventory"] or bool(d["seen_files"])
        shape = SHAPE[d["role"]] if d["role"] in SHAPE else (SHAPE["access"] if d["vlans"] else SHAPE[None])
        style = (shape +"verticalLabelPosition=bottom;verticalAlign=top;html=1;"
                 "aspect=fixed;align=center;labelBackgroundColor=#FFFFFF;fontStyle=1;fontSize=11;"
                 f"fillColor={'#FAFAFA' if known else '#EEEEEE'};strokeColor={'#005073' if known else '#999999'};"
                 + ("" if known else "dashed=1;"))
        ids[n] = page.vertex(label(d), style, x, y, W, H, tooltip=tip(d) if tip else None)
    return ids


def _role_tip(d):
    lines = [d["name"], f"site: {d['site'] or '-'}", f"role: {d['role'] or 'not set'}"
             + (f" ({d['role_source']})" if d["role"] and d["role_source"] != "inventory" else "")]
    if not d["in_inventory"] and not d["seen_files"]:
        lines.append("not in the inventory: seen only as a neighbor or in your spreadsheet")
    return "\n".join(lines)


def _desc(topo, dev, intf):
    return ((topo["devices"].get(dev, {}).get("descriptions") or {}).get(intf) or {}).get("description", "")


def _ip(topo, dev, intf):
    addrs = (topo["devices"].get(dev, {}).get("ips") or {}).get(intf) or []
    return str(addrs[0][0]) if addrs else ""


# ---------- pages ----------
def page_l1(mx, topo, pos, boxes, legend_y):
    page = Page(mx, "l1", "Physical (L1)")
    ids = _device_cells(page, topo, pos, boxes, tip=_role_tip)
    for l in sorted(topo["links"], key=lambda l: (l["a"], l["a_intf"])):
        kind = l["kind"]
        tip = [f"{l['a']} {l['a_intf']}  <->  {l['b']} {l['b_intf']}", f"found by: {', '.join(sorted(l['sources']))}"]
        for side in ("a", "b"):
            d = _desc(topo, l[side], l[f"{side}_intf"])
            if d:
                tip.append(f"{l[side]} {short_intf(l[side + '_intf'])}: {d}")
        if l["members"]:
            tip.append("members: " + ", ".join(f"{short_intf(x)}-{short_intf(y)}" for x, y in l["members"]))
        if l["note"]:
            tip.append(l["note"])
        value = html.escape(l["note"]) if kind in (topology.SUBNET, topology.TUNNEL) else ""
        width = "strokeWidth=4;" if l["members"] else ""
        eid = page.edge(ids[l["a"]], ids[l["b"]], f"endArrow=none;html=1;rounded=0;fontSize=10;"
                        f"labelBackgroundColor=#FFFFFF;{LINE[kind]}{width}", value, "\n".join(tip))
        for side, frac in (("a", -0.6), ("b", 0.6)):
            name = short_intf(l[f"{side}_intf"])
            if l["members"]:
                name += f" ({len(l['members'])} links)"
            if name:
                page.edge_label(eid, html.escape(name), frac)
    page.legend(MARGIN, legend_y, [(LINE[k], t) for k, t in LEGEND])


def _subnets(topo, skip_vrfs=topology.SKIP_VRFS):
    """{network: [(device, intf, ip)]} for every non-management IPv4 subnet on a device."""
    nets = defaultdict(list)
    for n, d in topo["devices"].items():
        for intf, addrs in (d.get("ips") or {}).items():
            for ipi, vrf in addrs:
                if vrf in skip_vrfs or intf.startswith("Loopback") or ipi.network.prefixlen == 32:
                    continue
                nets[ipi.network].append((n, intf, ipi))
    return nets


def page_l3(mx, topo, pos, boxes, legend_y):
    page = Page(mx, "l3", "Subnets (L3)")
    ids = _device_cells(page, topo, pos, boxes, tip=_role_tip)
    below = defaultdict(int)
    taken = [(x - 15, y - 5, W + 30, H + 35) for x, y in pos.values()]      # device icon + name
    def free(x, y):
        """The nearest spot to (x, y) that covers no device or subnet: tried above and below in turn."""
        steps = [0] + [sign * k * 30 for k in range(1, 10) for sign in (-1, 1)]
        for dx, dy in [(dx, dy) for dy in steps for dx in (0, 135, -135)]:
            if not any(x + dx < tx + tw and x + dx + 120 > tx and y + dy < ty + th and y + dy + 26 > ty
                       for tx, ty, tw, th in taken):
                x, y = x + dx, y + dy
                break
        else:
            y += 30 * len(taken)       # nowhere free nearby: below everything, still readable
        taken.append((x, y, 120, 26))
        return x, y
    for net, members in sorted(_subnets(topo).items(), key=lambda kv: (kv[0].version, kv[0])):
        xs = [pos[m[0]][0] for m in members]
        ys = [pos[m[0]][1] for m in members]
        if len({m[0] for m in members}) > 1:
            x, y = free(sum(xs) / len(xs) + W / 2 - 60, sum(ys) / len(ys) + H / 2 - 13)
        else:     # a subnet only one device has (a LAN): beside that device
            dev = members[0][0]
            below[dev] += 1
            x, y = free(pos[dev][0] + W + 12, pos[dev][1] - 20 + below[dev] * 30)
        tunnel = any(m[1].startswith("Tunnel") for m in members)
        public = not ipaddress.ip_network(net).is_private
        fill = "#F3E5F5" if tunnel else ("#FDEDEC" if public else "#EAF2F8")
        sid = page.vertex(html.escape(str(net)), f"rounded=1;arcSize=50;whiteSpace=wrap;html=1;fontSize=10;"
                          f"fillColor={fill};strokeColor=#5D6D7E;", x, y, 120, 26,
                          tooltip="\n".join(f"{m[0]} {m[1]} {m[2]}" for m in members))
        for dev, intf, ipi in members:
            eid = page.edge(ids[dev], sid, "endArrow=none;html=1;strokeColor=#5D6D7E;", "")
            page.edge_label(eid, html.escape(f"{short_intf(intf)} .{str(ipi.ip).split('.')[-1]}"), -0.4)
    page.legend(MARGIN, legend_y, [("strokeColor=#5D6D7E;", "Interface in a subnet (label: interface and host address)")])


def _vlan_label(d):
    if not d["vlans"]:
        return html.escape(d["name"])
    shown = [html.escape(f"{v} {d['vlans'][v]['name']}") for v in sorted(d["vlans"]) if v != 1]
    return f"<b>{html.escape(d['name'])}</b><br><font style='font-size:9px'>{'<br>'.join(shown) or 'VLAN 1 only'}</font>"


def page_l2(mx, topo, pos, boxes, legend_y):
    page = Page(mx, "l2", "VLANs (L2)")
    ids = _device_cells(page, topo, pos, boxes, label=_vlan_label, tip=_vlan_tip)
    for l in sorted(topo["links"], key=lambda l: (l["a"], l["a_intf"])):
        ta = (topo["devices"][l["a"]].get("trunks") or {}).get(l["a_intf"])
        tb = (topo["devices"][l["b"]].get("trunks") or {}).get(l["b_intf"])
        t = ta or tb
        if t:
            native = t.get("native")
            label = f"trunk {t['allowed']}" + (f" (native {native})" if native and native != "1" else "")
            page.edge(ids[l["a"]], ids[l["b"]], "endArrow=none;html=1;strokeColor=#1F618D;strokeWidth=3;"
                      "fontSize=10;labelBackgroundColor=#FFFFFF;", html.escape(label))
        else:
            page.edge(ids[l["a"]], ids[l["b"]], "endArrow=none;html=1;strokeColor=#BBBBBB;dashed=1;", "")
    page.legend(MARGIN, legend_y, [("strokeColor=#1F618D;strokeWidth=3;", "Trunk (allowed VLANs)"),
                                   ("strokeColor=#BBBBBB;dashed=1;", "Routed or access link (no trunk)")])


def _vlan_tip(d):
    lines = [d["name"]]
    for v in sorted(d["vlans"]):
        info = d["vlans"][v]
        ports = ", ".join(short_intf(x) for x in info["ports"])
        lines.append(f"VLAN {v} {info['name']}" + (f": {ports}" if ports else ""))
    if not d["vlans"]:
        lines.append("no VLAN output saved (router, firewall, or a platform not read yet)")
    return "\n".join(lines)


def _links_under_devices(root):
    """Order a page's cells so site boxes are at the back, then links and their labels, then
    devices on top: a link never hides a device's name."""
    def rank(el):
        cell = el if el.tag == "mxCell" else el.find("mxCell")
        if cell.get("edge") == "1":
            return 2
        if cell.get("vertex") != "1":
            return 0
        if "dashed=1;fillColor=none" in (cell.get("style") or ""):
            return 1
        return 3 if cell.get("connectable") == "0" else 4
    kids = list(root)
    for k in kids:
        root.remove(k)
    for k in sorted(kids, key=rank):      # sorted() is stable: same-rank cells keep their order
        root.append(k)


def has_l2(topo):
    return any(d["vlans"] or d["trunks"] for d in topo["devices"].values())


def write(path, topo, title="Network"):
    pos, boxes = layout(topo)
    legend_y = max((b[2] + b[4] for b in boxes), default=400) + 40
    mx = ET.Element("mxfile", host="netops-skills network-diagram", type="device")
    page_l1(mx, topo, pos, boxes, legend_y)
    page_l3(mx, topo, pos, boxes, legend_y + GAP_Y)
    if has_l2(topo):
        page_l2(mx, topo, pos, boxes, legend_y)
    for d in mx.iter("diagram"):
        d.set("name", f"{title}: {d.get('name')}")
    for root in mx.iter("root"):
        _links_under_devices(root)
    ET.indent(mx)
    path.write_text(ET.tostring(mx, encoding="unicode"), encoding="utf-8")
    return [d.get("name") for d in mx.iter("diagram")]
