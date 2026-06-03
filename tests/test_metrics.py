"""Tests for metrics math and ground truth labeling."""

import pytest

from src.ground_truth import is_malicious_process_creation, label_event
from src.metrics import score_detection


# --- Ground truth labeling ---

@pytest.mark.parametrize("image,cmd,expected", [
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "powershell.exe -noP -sta -w 1 -enc SQBFAFgA", True),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "powershell.exe -encodedCommand SQBFAFgA", True),
    (r"C:\Windows\system32\whoami.exe",
     "whoami.exe /all /fo list", True),
    (r"C:\Windows\system32\whoami.exe",
     "whoami.exe /groups", True),
    (r"C:\Windows\system32\ipconfig.exe",
     "ipconfig.exe /all", True),
    (r"C:\Windows\system32\cmd.exe",
     r"cmd.exe /c C:\windows\system32\autoupdate.vbs", True),
    (r"C:\Windows\System32\WScript.exe",
     r'"C:\Windows\System32\WScript.exe" "C:\Users\user\Downloads\payload.vbs"', True),
    (r"C:\WINDOWS\system32\sc.exe",
     r'sc.exe \\HFDC01 create AdobeUpdater binPath= "cmd.exe /c payload.exe"', True),
    (r"C:\Windows\system32\net.exe",
     'net.exe group "Domain Admins" /domain', True),
    # Benign cases
    (r"C:\Windows\system32\svchost.exe",
     "svchost.exe -k netsvcs", False),
    (r"C:\Windows\system32\whoami.exe",
     "whoami.exe", False),  # no enum flags
    (r"C:\Windows\system32\net.exe",
     "net.exe start", False),  # no /domain or group enum
    (r"C:\Windows\system32\ipconfig.exe",
     "ipconfig.exe", False),  # no /all
])
def test_is_malicious_process_creation(image, cmd, expected):
    assert is_malicious_process_creation(image, cmd) == expected


def test_label_event_skips_non_sysmon():
    event = {"log_name": "Security", "event_id": 4688, "event_data": {}}
    assert label_event(event) is None


def test_label_event_skips_non_eid1():
    event = {
        "log_name": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 3,
        "event_data": {},
    }
    assert label_event(event) is None


def test_label_event_malicious():
    event = {
        "log_name": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 1,
        "event_data": {
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -noP -sta -w 1 -enc SQBFAFgA",
        },
    }
    assert label_event(event) == "malicious"


def test_label_event_benign():
    event = {
        "log_name": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 1,
        "event_data": {
            "Image": r"C:\Windows\system32\svchost.exe",
            "CommandLine": "svchost.exe -k netsvcs",
        },
    }
    assert label_event(event) == "benign"


# --- Metrics math ---

def test_score_detection_perfect():
    malicious = {"t1|img1", "t2|img2"}
    benign = {"t3|img3", "t4|img4"}
    matches = [
        {"timestamp": "t1", "image": "img1"},
        {"timestamp": "t2", "image": "img2"},
    ]
    result = score_detection(matches, malicious, benign)
    assert result["tp"] == 2
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["fp_rate"] == 0.0


def test_score_detection_with_fp():
    malicious = {"t1|img1"}
    benign = {"t2|img2", "t3|img3"}
    matches = [
        {"timestamp": "t1", "image": "img1"},
        {"timestamp": "t2", "image": "img2"},  # FP
    ]
    result = score_detection(matches, malicious, benign)
    assert result["tp"] == 1
    assert result["fp"] == 1
    assert result["precision"] == 0.5
    assert result["fp_rate"] == 0.5


def test_score_detection_with_fn():
    malicious = {"t1|img1", "t2|img2"}
    benign = {"t3|img3"}
    matches = [{"timestamp": "t1", "image": "img1"}]
    result = score_detection(matches, malicious, benign)
    assert result["fn"] == 1
    assert result["recall"] == 0.5


def test_score_detection_empty_matches():
    malicious = {"t1|img1"}
    benign = {"t2|img2"}
    result = score_detection([], malicious, benign)
    assert result["tp"] == 0
    assert result["precision"] == 0.0
    assert result["recall"] == 0.0
