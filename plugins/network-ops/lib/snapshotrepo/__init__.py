# ============================================================
# Package:      snapshotrepo
# Purpose:      Find the snapshot repo (the git repo network-snapshot keeps for one network)
#               the same way in every network-ops skill, and save where it is. One snapshot
#               repo per network, kept outside project folders; its location is asked once,
#               on first use, and remembered in a user settings file (docs/adr/0003).
# Usage:        loc = snapshotrepo.resolve(repo=args.repo, network=args.network)
#                   -> {"path", "network", "source", "note"}; raises RepoError
#               print(snapshotrepo.banner(loc), file=sys.stderr)
#               snapshotrepo.set_repo(path, network=None, replace=False) -> what was saved
# Order:        1. --repo PATH or --network NAME
#               2. NETOPS_REPO (a path)
#               3. .netops.yaml, the first one found walking up from the current folder
#                  (holds only `network: NAME`, safe to commit)
#               4. the settings file's `default:` network (or its only network)
#               5. back-compat: no settings yet but ~/network-snapshots/inventory.yaml exists:
#                  adopt that path, save it as the default, and say so once (`note`)
#               6. nothing: RepoError code no_snapshot_repo. Never prompts, guesses or
#                  creates a repo; the agent asks the user and runs --set-repo.
# Settings:     NETOPS_CONFIG if set, else %APPDATA%\netops\config.yaml on Windows, else
#               $XDG_CONFIG_HOME/netops/config.yaml (default ~/.config/netops/config.yaml).
#               networks: {NAME: PATH}, default: NAME
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/netops-skills (plugins/network-ops)
# ============================================================
import json
import os
import sys
from pathlib import Path

import yaml

POINTER = ".netops.yaml"
LEGACY = "~/network-snapshots"     # the default every skill used before 0.4.0
FIRST_NAME = "main"                # the name a network gets when the user never picks one
EXIT_CODE = 3                      # exit status when no repo can be found (argparse uses 2)
HEADER = ("# network-ops settings: where each network's snapshot repo lives.\n"
          "# Written by `snapshot.py --set-repo PATH [--network NAME]`; editing by hand is fine.\n")


class RepoError(Exception):
    """No usable snapshot repo. `code` is machine-readable: no_snapshot_repo, unknown_network,
    bad_settings, network_exists, path_in_use."""

    def __init__(self, code, message, **extra):
        super().__init__(message)
        self.code, self.message, self.extra = code, message, extra

    def as_dict(self):
        return {"error": self.code, "message": self.message, "settings": str(settings_path()), **self.extra}


def settings_path(env=None):
    env = os.environ if env is None else env
    if env.get("NETOPS_CONFIG"):
        return Path(env["NETOPS_CONFIG"]).expanduser()
    if os.name == "nt" and env.get("APPDATA"):
        return Path(env["APPDATA"]) / "netops" / "config.yaml"
    base = env.get("XDG_CONFIG_HOME") or "~/.config"
    return Path(base).expanduser() / "netops" / "config.yaml"


def _norm(path):
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _same(a, b):
    return os.path.normcase(str(_norm(a))) == os.path.normcase(str(_norm(b)))


def load_settings(path=None):
    """{"networks": {name: path}, "default": name or None}; empty when there is no file."""
    path = Path(path) if path else settings_path()
    if not path.exists():
        return {"networks": {}, "default": None}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise RepoError("bad_settings", f"{path}: {e}")
    nets = (data.get("networks") or {}) if isinstance(data, dict) else None
    if not isinstance(nets, dict):
        raise RepoError("bad_settings", f"{path}: expected `networks: {{NAME: PATH}}` and `default: NAME`")
    return {"networks": {str(k): str(v) for k, v in nets.items()}, "default": data.get("default")}


def save_settings(settings, path=None):
    path = Path(path) if path else settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {"networks": settings["networks"], "default": settings.get("default")}
    path.write_text(HEADER + yaml.safe_dump(body, sort_keys=False), encoding="utf-8")
    return path


def find_pointer(cwd=None):
    """The nearest .netops.yaml at or above `cwd`, or None."""
    here = _norm(cwd or os.getcwd())
    for d in (here, *here.parents):
        if (d / POINTER).is_file():
            return d / POINTER
    return None


def _named(settings, name, why):
    path = settings["networks"].get(name)
    if path is None:
        known = ", ".join(sorted(settings["networks"])) or "none yet"
        raise RepoError("unknown_network", f"network '{name}' ({why}) is not in {settings_path()} "
                        f"(known: {known}); add it with snapshot.py --set-repo PATH --network {name}")
    return path


def _name_of(settings, path):
    for name, p in settings["networks"].items():
        if _same(p, path):
            return name
    return None


def _loc(path, network, source, note=None):
    return {"path": _norm(path), "network": network, "source": source, "note": note}


def resolve(repo=None, network=None, cwd=None, env=None):
    """Where this run's snapshot repo is, following the order in the header."""
    env = os.environ if env is None else env
    spath = settings_path(env)
    settings = load_settings(spath)
    if repo:
        return _loc(repo, _name_of(settings, repo), "--repo")
    if network:
        return _loc(_named(settings, network, "--network"), network, "--network")
    if env.get("NETOPS_REPO"):
        return _loc(env["NETOPS_REPO"], _name_of(settings, env["NETOPS_REPO"]), "NETOPS_REPO")
    pointer = find_pointer(cwd)
    if pointer:
        try:
            name = (yaml.safe_load(pointer.read_text(encoding="utf-8")) or {}).get("network")
        except (OSError, yaml.YAMLError, AttributeError) as e:
            raise RepoError("bad_settings", f"{pointer}: {e}")
        if not name:
            raise RepoError("bad_settings", f"{pointer}: expected one line, `network: NAME`")
        return _loc(_named(settings, str(name), str(pointer)), str(name), str(pointer))
    nets, default = settings["networks"], settings.get("default")
    if default:
        return _loc(_named(settings, str(default), f"default in {spath}"), str(default), "default")
    if len(nets) == 1:
        (name, path), = nets.items()
        return _loc(path, name, "default")
    if not nets:
        legacy = _norm(LEGACY)
        if (legacy / "inventory.yaml").is_file():
            save_settings({"networks": {FIRST_NAME: str(legacy)}, "default": FIRST_NAME}, spath)
            note = (f"Found snapshots in {legacy} (the old default location) and saved it as your "
                    f"snapshot repo in {spath}. Change it with snapshot.py --set-repo PATH --replace.")
            return _loc(legacy, FIRST_NAME, "adopted", note)
        raise RepoError("no_snapshot_repo", "no snapshot repo is set up yet: choose a folder and run "
                        "snapshot.py --set-repo PATH (or pass --repo PATH)")
    raise RepoError("no_snapshot_repo", f"several networks in {spath} and no default: pass --network NAME "
                    f"(one of {', '.join(sorted(nets))}) or put `network: NAME` in a {POINTER}",
                    networks=sorted(nets))


def set_repo(path, network=None, replace=False, env=None):
    """Save PATH as a network's snapshot repo and create the folder. Never changes another
    network's entry: a name that already points elsewhere needs replace=True, and a path
    another network already uses is refused."""
    spath = settings_path(env)
    settings = load_settings(spath)
    nets = settings["networks"]
    name = network or settings.get("default") or (next(iter(nets)) if len(nets) == 1 else FIRST_NAME)
    path = _norm(path)
    other = _name_of(settings, path)
    if other and other != name:
        raise RepoError("path_in_use", f"{path} is already the snapshot repo of network '{other}'; "
                        f"use --network {other}")
    old = nets.get(name)
    replaced = None
    if old is not None and not _same(old, path):
        if not replace:
            raise RepoError("network_exists", f"network '{name}' already points to {old}; "
                            f"add --replace to move it to {path} (the old folder is left as it is)",
                            network=name, current=old)
        replaced = old
    created = not path.exists()
    path.mkdir(parents=True, exist_ok=True)
    nets[name] = str(path)
    if not settings.get("default"):
        settings["default"] = name
    save_settings(settings, spath)
    return {"settings": str(spath), "network": name, "path": str(path), "default": settings["default"],
            "created": created, "replaced": replaced}


def banner(loc):
    """The one line every run prints."""
    return f"Snapshot repo: {loc['path']} (network: {loc['network'] or 'unnamed'})"


def report_fields(loc):
    """The fields every skill's JSON report carries about the repo."""
    out = {"repo": str(loc["path"]), "network": loc["network"]}
    if loc.get("note"):
        out["repo_note"] = loc["note"]
    return out


def announce(loc, stream=None):
    """Print the banner (and the one-time adoption note) to stderr, so stdout stays pure JSON."""
    stream = stream or sys.stderr
    if loc.get("note"):
        print(loc["note"], file=stream)
    print(banner(loc), file=stream)


def fail(err, stream=None):
    """Print a RepoError as one JSON line on stderr and exit with EXIT_CODE."""
    print(json.dumps(err.as_dict()), file=stream or sys.stderr)
    sys.exit(EXIT_CODE)
