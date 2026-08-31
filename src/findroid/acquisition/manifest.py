"""APK manifest reader for real-mode plumbing.

A thin androguard wrapper that returns exactly the manifest fields the import
discovery and acquisition stages need, so the pipeline keeps a single source of
truth for what a real APK actually declares. No dynamic analysis.
"""

from __future__ import annotations

import logging
from pathlib import Path

try:  # androguard logs via loguru even when stdlib logging is disabled
    from loguru import logger as _loguru

    _loguru.disable("androguard")
except Exception:  # noqa: BLE001
    pass
logging.disable(logging.CRITICAL)

from ..models import sha256_bytes  # noqa: E402


class ApkReadError(RuntimeError):
    """Raised when a file cannot be parsed as an Android APK."""


def read_apk_manifest(path: str | Path) -> dict:
    """Return manifest facts for a genuine APK file.

    Fields: ``package_name``, ``app_name``, ``version_code``, ``version_name``,
    ``min_sdk``, ``target_sdk``, ``size_bytes``, ``sha256``, ``dex_count``.
    """
    try:
        from androguard.core.apk import APK
    except Exception as exc:  # noqa: BLE001
        raise ApkReadError(f"androguard unavailable: {exc}") from exc

    path = Path(path)
    if not path.is_file():
        raise ApkReadError(f"not a file: {path}")
    data = path.read_bytes()
    try:
        apk = APK(str(path))
    except Exception as exc:  # noqa: BLE001
        raise ApkReadError(f"unparseable APK {path.name}: {exc}") from exc

    min_sdk = apk.get_min_sdk_version()
    target_sdk = apk.get_target_sdk_version()
    return {
        "package_name": str(apk.get_package() or ""),
        "app_name": str(apk.get_app_name() or ""),
        "version_code": _intish(apk.get_androidversion_code()),
        "version_name": str(apk.get_androidversion_name() or ""),
        "min_sdk": _intish(min_sdk),
        "target_sdk": _intish(target_sdk),
        "size_bytes": len(data),
        "sha256": sha256_bytes(data),
        "dex_count": len(list(apk.get_all_dex())),
    }


def _intish(value) -> int:
    if value in (None, "", "N/A"):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


__all__ = ["ApkReadError", "read_apk_manifest"]
