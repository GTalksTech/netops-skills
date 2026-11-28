# ============================================================
# Script:       fortigate_guard.py
# Purpose:      A read-only SSH connection to a FortiGate. Netmiko's Fortinet driver
#               (checked in 4.8.0, netmiko/fortinet/fortinet_ssh.py) turns paging off by
#               writing config ('config system console' / 'set output standard' / 'end'),
#               writes 'set output more' back at logout, and enters 'config global' on a
#               VDOM box just to read the console mode. This connection does none of that:
#               it reads the console mode with 'get system console' and refuses the device,
#               with the one-line fix, when the mode is not 'standard' or cannot be read.
# Usage:        conn = fortigate_guard.connect(**netmiko_params)   # raises ReadOnlyRefused
# Author:       G Talks Tech
# Notes:        VDOM-mode FortiGates are refused: their console mode cannot be read without
#               'config global'. Whether to support them is an open decision.
#               tests/test_fortigate_guard.py checks the installed driver still has the
#               methods overridden here.
# ============================================================
import re

FIX = ("set the console to standard output yourself, once, from an admin session: "
       "'config system console', 'set output standard', 'end'. The snapshot never changes "
       "device config, so it will not do this for you.")


class ReadOnlyRefused(Exception):
    """The device cannot be read without changing its config; the message says what to do."""


def output_mode(text):
    """'standard' or 'more' from `get system console`, else None."""
    m = re.search(r"^\s*output\s*:\s*(\S+)\s*$", text or "", re.M)
    return m.group(1) if m and m.group(1) in ("standard", "more") else None


def vdoms_enabled(text):
    """True when `get system status` shows VDOMs on (multiple or split-task)."""
    return bool(re.search(r"Virtual domain configuration:\s*(multiple|enable|split-task)", text or ""))


class ReadOnlyFortinetMixin:
    """Put before netmiko's FortinetSSH in the class bases."""

    def session_preparation(self):
        data = self._test_channel_read(pattern=f"to accept|{self.prompt_pattern}")
        if "to accept" in data:  # post-login banner: same key press the driver sends
            self.write_channel("a\r")
            self._test_channel_read(pattern=self.prompt_pattern)
        self.set_base_prompt()
        self._vdoms = False
        status = self._send_command_str("get system status", expect_string=self.prompt_pattern)
        if vdoms_enabled(status):
            raise ReadOnlyRefused(
                "VDOMs are on: reading this FortiGate's console mode needs 'config global', "
                "which the snapshot never enters. VDOM support is not built yet.")
        mode = output_mode(self._send_command_str("get system console", expect_string=self.prompt_pattern))
        if mode != "standard":
            seen = f"is '{mode}'" if mode else "could not be read"
            raise ReadOnlyRefused(f"console output mode {seen}, so output would page: {FIX}")
        self._original_output_mode = self._output_mode = "standard"

    def disable_paging(self, *args, **kwargs):
        return ""  # checked in session_preparation; never written

    def _config_global(self):
        raise ReadOnlyRefused("refusing 'config global': the snapshot is read-only")

    def cleanup(self, command="exit"):
        # FortinetSSH.cleanup writes 'set output more' only when the mode it recorded at login
        # was 'more'. Record 'standard' so the driver's logout is only the plain 'exit'.
        self._original_output_mode = "standard"
        return super().cleanup(command=command)


def connection_class():
    from netmiko.fortinet.fortinet_ssh import FortinetSSH
    return type("ReadOnlyFortinetSSH", (ReadOnlyFortinetMixin, FortinetSSH), {})


def connect(**params):
    params = dict(params)
    params.pop("device_type", None)
    return connection_class()(device_type="fortinet", **params)
