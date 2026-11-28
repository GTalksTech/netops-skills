"""Shared credential lookup: environment variable, then a configured command, then the OS store."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import credentials  # noqa: E402

SECRET = "s3cr3t-Pa55"


@pytest.fixture
def store(monkeypatch):
    """The OS credential store, as a dict: {(service, name): secret}."""
    saved = {}
    monkeypatch.setattr(credentials.keyring, "get_password", lambda s, u: saved.get((s, u)))
    monkeypatch.setattr(credentials.keyring, "set_password", lambda s, u, p: saved.__setitem__((s, u), p))
    return saved


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("NETOPS_SECRET_"):
            monkeypatch.delenv(k)


def py(code):
    """A command (argv list) that runs a line of Python, standing in for a vault CLI."""
    return [sys.executable, "-c", code]


def test_environment_variable_named_after_the_credential(monkeypatch, store):
    monkeypatch.setenv("NETOPS_SECRET_SVC_NETOPS_RO", SECRET)
    creds = credentials.Credentials()
    assert creds.get("svc-netops-ro") == SECRET


def test_configured_command_prints_the_secret_for_the_named_credential(store):
    # the vault CLI gets the credential name in place of {name}; its trailing newline is dropped
    cmd = py("import sys; print({'svc-netops-ro': '" + SECRET + "'}[sys.argv[1]])") + ["{name}"]
    creds = credentials.Credentials({"command": cmd})
    assert creds.get("svc-netops-ro") == SECRET


def test_command_given_as_one_line(store, tmp_path):
    script = tmp_path / "vault.py"
    script.write_text("import sys; sys.stdout.write('pw-for-' + sys.argv[1] + '\\r\\n')", encoding="utf-8")
    line = f'"{Path(sys.executable).as_posix()}" "{script.as_posix()}" {{name}}'
    assert credentials.Credentials({"command": line}).get("claude-ro") == "pw-for-claude-ro"


def test_os_credential_store_under_the_shared_service(store):
    store[("netops-skills", "claude-ro")] = SECRET
    creds = credentials.Credentials()
    assert creds.get("claude-ro") == SECRET


def test_methods_are_tried_in_order(monkeypatch, store):
    cmd = py("print('from-command')")
    store[("netops-skills", "a")] = "from-store"
    store[("netops-skills", "b")] = "from-store"
    store[("netops-skills", "c")] = "from-store"
    monkeypatch.setenv("NETOPS_SECRET_A", "from-env")
    creds = credentials.Credentials({"command": cmd})
    assert creds.get("a") == "from-env"
    assert creds.get("b") == "from-command"
    assert credentials.Credentials().get("c") == "from-store"


def test_a_failing_command_falls_through_to_the_store(store):
    # a vault that has no item by this name exits non-zero; the OS store may still hold it
    store[("netops-skills", "claude-ro")] = SECRET
    creds = credentials.Credentials({"command": py("import sys; sys.exit('Not found.')")})
    assert creds.get("claude-ro") == SECRET


def test_empty_command_output_is_not_a_password(store):
    store[("netops-skills", "claude-ro")] = SECRET
    assert credentials.Credentials({"command": py("print()")}).get("claude-ro") == SECRET


def test_nothing_found_names_every_method_tried_and_no_secret(store):
    leaky = py(f"import sys; print('{SECRET}'); print('{SECRET} locked', file=sys.stderr); sys.exit(3)")
    creds = credentials.Credentials({"command": leaky})
    with pytest.raises(credentials.CredentialError) as e:
        creds.get("claude-ro")
    msg = str(e.value)
    assert "NETOPS_SECRET_CLAUDE_RO" in msg
    assert "exit 3" in msg
    assert "OS credential store" in msg
    assert "--set-credential claude-ro" in msg
    assert SECRET not in msg


def test_missing_command_program_is_reported(store):
    creds = credentials.Credentials({"command": ["no-such-vault-cli-xyz", "get", "{name}"]})
    with pytest.raises(credentials.CredentialError, match="no-such-vault-cli-xyz"):
        creds.get("claude-ro")


def test_slow_command_times_out(store):
    creds = credentials.Credentials({"command": py("import time; time.sleep(5)"), "timeout": 1})
    with pytest.raises(credentials.CredentialError, match="timed out"):
        creds.get("claude-ro")


def test_each_credential_is_looked_up_once_per_run(store, tmp_path):
    count = tmp_path / "count.txt"
    cmd = py(f"open(r'{count}', 'a').write('x'); print('pw')")
    creds = credentials.Credentials({"command": cmd})
    for _ in range(3):
        creds.get("claude-ro")
    assert count.read_text() == "x"


def test_secret_is_not_in_repr(monkeypatch, store):
    monkeypatch.setenv("NETOPS_SECRET_CLAUDE_RO", SECRET)
    creds = credentials.Credentials()
    creds.get("claude-ro")
    assert SECRET not in repr(creds)


def test_store_saves_to_the_os_credential_store(store):
    credentials.store("claude-ro", SECRET)
    assert store[("netops-skills", "claude-ro")] == SECRET


def test_settings_are_checked(store):
    with pytest.raises(credentials.CredentialError, match="unknown"):
        credentials.Credentials({"comand": "bw get password {name}"})


def test_command_error_text_never_reaches_the_message(store):
    # a CLI may echo a token or session key on stderr with nothing on stdout
    creds = credentials.Credentials({"command": py(f"import sys; sys.exit('token {SECRET}')")})
    with pytest.raises(credentials.CredentialError) as e:
        creds.get("claude-ro")
    assert "exit 1" in str(e.value) and SECRET not in str(e.value)


def test_non_ascii_password_from_a_command_is_read_as_utf8(store):
    pw = "pässé-€"
    cmd = py(f"import sys; sys.stdout.buffer.write({pw!r}.encode('utf-8') + b'\\n')")
    assert credentials.Credentials({"command": cmd}).get("claude-ro") == pw


@pytest.mark.parametrize("settings", ["bw get password {name}", {"timeout": "30"}, {"timeout": 0},
                                      {"command": {"bw": "get"}}])
def test_bad_settings_are_refused_up_front(settings):
    with pytest.raises(credentials.CredentialError):
        credentials.Credentials(settings)
