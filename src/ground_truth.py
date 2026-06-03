"""
Ground truth labeling for the APT3 empire dataset.

The dataset covers a single Empire APT3 emulation run on 2019-05-14.
We identify malicious process creation events by known attack-tool patterns
observed in the dataset. Everything else (svchost, explorer, MicrosoftEdge, etc.)
is benign background activity.

This labeling is conservative and auditable: we only mark an event malicious
if it exhibits a clear attack indicator. Ambiguous events are treated as benign,
which may inflate FN counts but keeps FP analysis honest.
"""

import re


def is_malicious_process_creation(image: str, command_line: str) -> bool:
    """Return True if a process creation event is a known-malicious APT3 technique."""
    if not image and not command_line:
        return False

    img = (image or "").lower()
    cmd = (command_line or "").lower()

    # T1059.001 — PowerShell encoded/obfuscated execution
    if "powershell.exe" in img:
        if any(flag in cmd for flag in [" -enc ", " -encodedcommand ", "-w 1", "-nop "]):
            return True

    # T1033 — Whoami reconnaissance
    if "whoami.exe" in img:
        if any(flag in cmd for flag in ["/all", "/groups", "/priv"]):
            return True

    # T1016 — Network configuration discovery
    if "ipconfig.exe" in img and "/all" in cmd:
        return True

    # T1059.005 — VBScript execution via cmd or wscript
    if ("cmd.exe" in img or "wscript.exe" in img) and ".vbs" in cmd:
        return True

    # T1021.002 — Remote service creation for lateral movement
    if "sc.exe" in img and " create " in cmd and "binpath=" in cmd:
        return True

    # T1069.002 / T1087.002 — Domain group/user enumeration
    if "net.exe" in img:
        if any(kw in cmd for kw in [" group ", " localgroup ", " user "]):
            if "/domain" in cmd:
                return True

    return False


# Known benign process images (Windows background activity in this dataset)
KNOWN_BENIGN_IMAGES = frozenset([
    "svchost.exe",
    "explorer.exe",
    "microsoftedgecp.exe",
    "microsoftedge.exe",
    "backgroundtaskhost.exe",
    "taskhostw.exe",
    "dllhost.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "windows.warp.jitservice.exe",
    "runtimebroker.exe",
    "shellexperiencehost.exe",
    "applicationframehost.exe",
    "wuauclt.exe",
    "mscorsvw.exe",
    "vssvc.exe",
    "msiexec.exe",
])


def label_event(event: dict) -> str | None:
    """
    Return 'malicious', 'benign', or None (skip — not a process creation event).
    Only Sysmon EID 1 (process creation) events are scored.
    """
    if event.get("log_name", "") != "Microsoft-Windows-Sysmon/Operational":
        return None
    if event.get("event_id") != 1:
        return None

    ed = event.get("event_data", {})
    image = ed.get("Image", "")
    command_line = ed.get("CommandLine", "")

    if is_malicious_process_creation(image, command_line):
        return "malicious"

    img_base = image.split("\\")[-1].lower() if image else ""
    if img_base in KNOWN_BENIGN_IMAGES:
        return "benign"

    # Events not clearly malicious or benign are excluded from scoring
    # (honest: we can't claim FN/TN on ambiguous events)
    return None
