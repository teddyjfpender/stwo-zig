"""Per-child resource accounting for Linux and macOS qualification runs."""

import platform


def peak_rss_bytes(usage, system=None):
    """Normalize wait4's high-water RSS; this is a measurement, not a cap.

    Darwin reports bytes, whereas Linux reports KiB. Refuse other platforms
    rather than quietly publishing an incorrectly scaled memory measurement.
    """
    system = platform.system() if system is None else system
    if system not in ("Darwin", "Linux"):
        raise ValueError(f"unsupported wait4 RSS units on {system}")
    return usage.ru_maxrss * (1 if system == "Darwin" else 1024)
