# ============================================================
# Package:      credentials
# Purpose:      The one place a network-ops skill gets a device password. For a credential
#               name (a username, or an inventory 'credential' name) it tries, in order:
#               the environment variable NETOPS_SECRET_<NAME>, a command the user configured
#               (any vault or password manager CLI that prints the secret), then the OS
#               credential store (keyring, service 'netops-skills').
# Usage:        import credentials
#               creds = credentials.Credentials(inventory.get("credentials"))
#               pw = creds.get("svc-netops-ro")     # raises CredentialError if none found
#               credentials.store(name, secret)     # --set-credential: into the OS store
# Author:       G Talks Tech
# Notes:        See lib/README.md. Never prints, logs or writes a secret: errors name the
#               methods tried and why each failed, never anything a command printed.
#               Secrets are held in memory for one run, one lookup per credential name.
# ============================================================
import os
import re
import shlex
import shutil
import signal
import subprocess

import keyring

SERVICE = "netops-skills"
ENV_PREFIX = "NETOPS_SECRET_"
SETTINGS = {"command", "timeout"}
DEFAULT_TIMEOUT = 30


class CredentialError(Exception):
    """No method found the secret, or the settings are wrong. Never carries a secret."""


def env_name(name):
    """'svc-netops-ro' -> 'NETOPS_SECRET_SVC_NETOPS_RO'."""
    return ENV_PREFIX + re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")


def store(name, secret):
    """Save a secret in the OS credential store under `name` (what --set-credential does)."""
    keyring.set_password(SERVICE, name, secret)


def _settings(settings):
    """(argv list, timeout) from the inventory's `credentials:` block, or CredentialError."""
    settings = {} if settings is None else settings
    if not isinstance(settings, dict):
        raise CredentialError("'credentials:' must be a mapping with 'command' and/or 'timeout'")
    unknown = set(settings) - SETTINGS
    if unknown:
        raise CredentialError(f"unknown credentials setting(s) {sorted(unknown)}; known: {sorted(SETTINGS)}")
    cmd = settings.get("command") or []
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    if not (isinstance(cmd, list) and all(isinstance(a, str) for a in cmd)):
        raise CredentialError("credentials 'command' must be one line or a list of words")
    timeout = settings.get("timeout", DEFAULT_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise CredentialError("credentials 'timeout' must be a number of seconds above 0")
    return cmd, timeout


def _kill_tree(proc):
    """Stop the command and anything it started (bw.cmd runs node under cmd.exe), so a
    grandchild holding the output pipes cannot keep the run waiting."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()


class Credentials:
    """One run's credential lookups. `settings` is the inventory's `credentials:` block:
    command  (optional) argv list, or one line split like a shell would; '{name}' in it
             becomes the credential name. Runs with no shell and no stdin.
    timeout  (optional) seconds the command may take, default 30.
    """

    def __init__(self, settings=None):
        self._command, self._timeout = _settings(settings)
        self._found = {}  # name -> (secret, None) or (None, error message)

    def __repr__(self):
        return f"<Credentials command={bool(self._command)} looked_up={sorted(self._found)}>"

    def get(self, name):
        """The secret for `name`. Raises CredentialError, naming each method tried."""
        if name not in self._found:
            self._found[name] = self._lookup(name)
        secret, error = self._found[name]
        if secret is None:
            raise CredentialError(error)
        return secret

    def _lookup(self, name):
        tried = []
        var = env_name(name)
        if os.environ.get(var):
            return os.environ[var], None
        tried.append(f"environment variable {var} (not set)")
        if self._command:
            secret, why = self._run(name)
            if secret:
                return secret, None
            tried.append(f"command {self._command[0]} ({why})")
        try:
            secret = keyring.get_password(SERVICE, name)
        except Exception as e:  # no usable backend, locked keychain
            secret, why = None, f"unavailable: {type(e).__name__}"
        else:
            why = "no entry"
        if secret:
            return secret, None
        tried.append(f"OS credential store, service '{SERVICE}' ({why})")
        return None, (f"no password found for '{name}': tried " + "; ".join(tried)
                      + f". Set {var}, configure a credentials command, or run --set-credential {name}")

    def _run(self, name):
        """(secret, None) or (None, why). The why never includes anything the command printed:
        a CLI may echo a secret, token or session key to stdout or stderr."""
        argv = [a.replace("{name}", name) for a in self._command]
        exe = shutil.which(argv[0])  # finds bw.cmd and the like on Windows, with no shell
        if not exe:
            return None, "not found on PATH"
        try:
            proc = subprocess.Popen([exe, *argv[1:]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, start_new_session=os.name != "nt")
        except OSError as e:
            return None, f"could not run: {type(e).__name__}"
        try:
            out, _ = proc.communicate(timeout=self._timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            try:
                proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            return None, f"timed out after {self._timeout}s"
        if proc.returncode != 0:
            return None, f"exit {proc.returncode}"
        try:
            secret = out.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError:
            return None, "printed something that is not UTF-8 text"
        if not secret:
            return None, "printed nothing"
        return secret, None
