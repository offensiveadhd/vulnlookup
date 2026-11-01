"""The optional NVD API key, kept where the operating system keeps secrets.

Order of lookup:
1. ``NVD_API_KEY`` in the environment (CI, containers, one-off runs).
2. The OS credential store: Windows Credential Manager (``CredReadW`` through ctypes), the macOS
   Keychain (``security find-generic-password``), the freedesktop Secret Service on Linux
   (``secret-tool``) when it is installed.
3. A file under the user config directory with mode 0600, only when no store is available, and
   the tool says so every time it writes one.

The key is sent in the ``apiKey`` header to ``services.nvd.nist.gov`` only. It is never written
to the cache, never echoed, never logged; ``status`` prints its last four characters at most.
Subprocesses are called with argument lists, never a shell.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import paths

SERVICE = "vulnlookup"
ACCOUNT = "nvd-api-key"
TARGET = "vulnlookup/nvd-api-key"  # Windows credential target name
FILE_NAME = "nvd_api_key"


@dataclass
class Status:
    present: bool
    where: str  # env | credential-manager | keychain | secret-service | file | none
    hint: str = ""  # last 4 characters, or ""

    def as_dict(self) -> dict[str, object]:
        return {"present": self.present, "where": self.where, "hint": self.hint}


def _valid(key: str) -> bool:
    key = key.strip()
    return 20 <= len(key) <= 128 and all(c.isalnum() or c in "-_" for c in key)


# ---------------------------------------------------------------------- Windows


class _CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TargetName", ctypes.c_wchar_p),
        ("Comment", ctypes.c_wchar_p),
        ("LastWritten", ctypes.c_uint64),
        ("CredentialBlobSize", ctypes.c_uint32),
        ("CredentialBlob", ctypes.c_void_p),
        ("Persist", ctypes.c_uint32),
        ("AttributeCount", ctypes.c_uint32),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.c_wchar_p),
        ("UserName", ctypes.c_wchar_p),
    ]


_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2


def _win_read() -> str | None:
    adv = ctypes.windll.advapi32  # type: ignore[attr-defined]
    p = ctypes.POINTER(_CREDENTIAL)()
    if not adv.CredReadW(TARGET, _CRED_TYPE_GENERIC, 0, ctypes.byref(p)):
        return None
    try:
        c = p.contents
        if not c.CredentialBlobSize:
            return None
        raw = ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize)
        return raw.decode("utf-16-le", "ignore").strip() or None
    finally:
        adv.CredFree(p)


def _win_write(key: str) -> None:
    adv = ctypes.windll.advapi32  # type: ignore[attr-defined]
    blob = key.encode("utf-16-le")
    buf = ctypes.create_string_buffer(blob, len(blob))
    c = _CREDENTIAL()
    c.Type = _CRED_TYPE_GENERIC
    c.TargetName = TARGET
    c.Comment = "NVD API key for vulnlookup"
    c.CredentialBlobSize = len(blob)
    c.CredentialBlob = ctypes.cast(buf, ctypes.c_void_p)
    c.Persist = _CRED_PERSIST_LOCAL_MACHINE
    c.UserName = ACCOUNT
    if not adv.CredWriteW(ctypes.byref(c), 0):
        raise OSError(ctypes.get_last_error() or ctypes.GetLastError(), "CredWriteW failed")  # type: ignore[attr-defined]


def _win_delete() -> bool:
    adv = ctypes.windll.advapi32  # type: ignore[attr-defined]
    return bool(adv.CredDeleteW(TARGET, _CRED_TYPE_GENERIC, 0))


# ---------------------------------------------------------------------- macOS / Linux


def _run(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, input=stdin, capture_output=True, text=True, check=False)  # noqa: S603


def _mac_read() -> str | None:
    r = _run(["security", "find-generic-password", "-a", ACCOUNT, "-s", SERVICE, "-w"])
    return r.stdout.strip() or None if r.returncode == 0 else None


def _mac_write(key: str) -> None:
    # -U updates in place. The key is an argument to `security`, briefly visible in the process
    # list to other local users; the Keychain has no stdin path for add-generic-password.
    r = _run(["security", "add-generic-password", "-U", "-a", ACCOUNT, "-s", SERVICE, "-w", key])
    if r.returncode != 0:
        raise OSError(r.returncode, r.stderr.strip() or "security add-generic-password failed")


def _mac_delete() -> bool:
    return _run(["security", "delete-generic-password", "-a", ACCOUNT, "-s", SERVICE]).returncode == 0


def _secret_tool() -> str | None:
    return shutil.which("secret-tool")


def _linux_read() -> str | None:
    r = _run(["secret-tool", "lookup", "service", SERVICE, "account", ACCOUNT])
    return r.stdout.strip() or None if r.returncode == 0 else None


def _linux_write(key: str) -> None:
    r = _run(["secret-tool", "store", "--label=vulnlookup NVD API key", "service", SERVICE, "account", ACCOUNT], stdin=key)
    if r.returncode != 0:
        raise OSError(r.returncode, r.stderr.strip() or "secret-tool store failed")


def _linux_delete() -> bool:
    return _run(["secret-tool", "clear", "service", SERVICE, "account", ACCOUNT]).returncode == 0


# ---------------------------------------------------------------------- file fallback


def _file() -> Path:
    return paths.config_dir() / FILE_NAME


def _file_read() -> str | None:
    try:
        return _file().read_text("utf-8").strip() or None
    except OSError:
        return None


def _file_write(key: str) -> None:
    p = _file()
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(key + "\n")
    with contextlib.suppress(OSError):  # Windows has no POSIX mode bits; the open() mode did what it could
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)


def _file_delete() -> bool:
    try:
        _file().unlink()
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------- the store


def store_kind(force_file: bool = False) -> str:
    if force_file:
        return "file"
    if sys.platform == "win32":
        return "credential-manager"
    if sys.platform == "darwin" and shutil.which("security"):
        return "keychain"
    if _secret_tool():
        return "secret-service"
    return "file"


def get_key() -> tuple[str | None, str]:
    """(key, where). The environment wins; then the store; then the file."""
    env = os.environ.get("NVD_API_KEY", "").strip()
    if env:
        return env, "env"
    kind = store_kind()
    try:
        if kind == "credential-manager":
            k = _win_read()
        elif kind == "keychain":
            k = _mac_read()
        elif kind == "secret-service":
            k = _linux_read()
        else:
            k = None
    except Exception:
        k = None
    if k:
        return k, kind
    k = _file_read()
    return (k, "file") if k else (None, "none")


def set_key(key: str, force_file: bool = False) -> str:
    key = key.strip()
    if not _valid(key):
        raise ValueError("that does not look like an NVD API key (20-128 characters, letters, digits, - and _)")
    kind = store_kind(force_file)
    if kind == "credential-manager":
        _win_write(key)
    elif kind == "keychain":
        _mac_write(key)
    elif kind == "secret-service":
        _linux_write(key)
    else:
        _file_write(key)
        print(
            f"warning: no OS credential store available; the key is in {_file()} with mode 0600. "
            "Anyone who can read your files can read it.",
            file=sys.stderr,
        )
    return kind


def clear_key() -> list[str]:
    cleared = []
    kind = store_kind()
    try:
        if (
            kind == "credential-manager"
            and _win_delete()
            or kind == "keychain"
            and _mac_delete()
            or kind == "secret-service"
            and _linux_delete()
        ):
            cleared.append(kind)
    except Exception as e:  # a store that is installed but refuses (locked keychain, no D-Bus): say so, go on
        print(f"warning: could not clear the {kind}: {e}", file=sys.stderr)
    if _file_delete():
        cleared.append("file")
    return cleared


def status() -> Status:
    key, where = get_key()
    if not key:
        return Status(False, "none")
    return Status(True, where, key[-4:])
