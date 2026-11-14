from pathlib import Path
from types import SimpleNamespace

import pytest

from netops import ai
from netops.cli import main
from netops.parsers import normalize_ifname, parse_capture
from netops.report import to_markdown
from netops.rules import analyze, health_score

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture(scope="module")
def branch():
    return parse_capture((SAMPLES / "branch-sw01.txt").read_text())


@pytest.fixture(scope="module")
def healthy():
    return parse_capture((SAMPLES / "healthy-r1.txt").read_text())


def ids(findings):
    return {f.id for f in findings}


# ------------------------------------------------------------------ parsing
def test_hostname_and_sections(branch):
    assert branch.hostname == "BRANCH-SW01"
    assert len(branch.commands) == 4


def test_interfaces_parsed(branch):
    gi2 = branch.interface("Gi1/0/2")
    assert gi2.crc == 47902 and gi2.packets_in == 8821930 and gi2.description == "PRINTER-2F"
    gi1 = branch.interface("GigabitEthernet1/0/1")
    assert gi1.duplex == "half" and gi1.late_collisions == 3398
    assert branch.interface("Gi1/0/24").output_drops == 88123
    assert not branch.interface("Gi1/0/10").is_up


def test_ospf_cpu_logs_parsed(branch):
    assert [n.state for n in branch.ospf_neighbors] == ["FULL", "EXSTART", "INIT"]
    assert branch.cpu == {"5s": 91, "1m": 87, "5m": 79}
    assert branch.cpu_top[0][0] == "IP Input"
    assert len(branch.logs) == 12
    assert branch.logs[0].code == "LINK-3-UPDOWN"


@pytest.mark.parametrize("raw,expected", [
    ("GigabitEthernet1/0/2", "gi1/0/2"), ("Gi1/0/2", "gi1/0/2"),
    ("TenGigabitEthernet1/1/1", "te1/1/1"), ("Vlan100", "vlan100"),
])
def test_interface_name_normalisation(raw, expected):
    assert normalize_ifname(raw) == expected


# ------------------------------------------------------------------ rules
def test_detects_all_problems(branch):
    assert ids(analyze(branch)) == {
        "DUPLEX_MISMATCH", "CRC_ERRORS", "LINK_FLAP", "OSPF_ADJACENCY",
        "HIGH_CPU", "MAC_FLAP", "CONGESTION", "CONFIG_CHANGE",
    }


def test_healthy_device_has_no_findings(healthy):
    findings = analyze(healthy)
    assert findings == []
    assert health_score(findings) == 100


def test_findings_sorted_by_severity(branch):
    sev = [f.severity for f in analyze(branch)]
    assert sev == sorted(sev, key=["critical", "warning", "info"].index)


def test_ospf_exstart_blames_mtu_with_log_evidence(branch):
    f = next(f for f in analyze(branch) if f.id == "OSPF_ADJACENCY" and "10.255.0.7" in f.target)
    assert "MTU" in f.likely_cause
    assert any("mismatched MTU" in e for e in f.evidence)


def test_crc_correlated_with_flaps(branch):
    f = next(f for f in analyze(branch) if f.id == "CRC_ERRORS")
    assert "PRINTER-2F" in f.target
    assert any("flapped 3 times" in e for e in f.evidence)


def test_full_ospf_neighbor_and_low_crc_are_ignored():
    text = """R1#show ip ospf neighbor
10.0.0.2          1   FULL/DR         00:00:35    10.1.1.2        Gi0/0
R1#show interfaces
Gi0/0 is up, line protocol is up
  Full-duplex, 1000Mb/s, media type is RJ45
     10000000 packets input, 1 bytes
     5 input errors, 5 CRC, 0 frame
"""
    assert analyze(parse_capture(text)) == []


# ------------------------------------------------------------------ AI layer
class FakeClient:
    def __init__(self):
        self.calls = []
        self.messages = self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(content=[SimpleNamespace(type="text", text="## Summary\nAI says hi")])


def test_ai_prompt_contains_only_grounded_data(branch):
    prompt = ai.build_prompt(branch, analyze(branch), lang="ar")
    assert "<findings>" in prompt and "BRANCH-SW01" in prompt
    assert "Arabic" in prompt


def test_ai_call_uses_system_prompt(branch):
    client = FakeClient()
    text = ai.explain_with_claude(branch, analyze(branch), client=client)
    assert text.startswith("## Summary")
    call = client.calls[0]
    assert "Never invent" in call["system"]
    assert call["messages"][0]["role"] == "user"


def test_offline_fallback_without_key(branch, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    text, mode = ai.explain(branch, analyze(branch))
    assert mode == "offline" and "Action plan" in text


def test_ai_failure_falls_back(branch, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    monkeypatch.setattr(ai, "explain_with_claude", lambda *a, **k: (_ for _ in ()).throw(TimeoutError()))
    text, mode = ai.explain(branch, analyze(branch))
    assert mode == "offline" and "TimeoutError" in text


# ------------------------------------------------------------------ report + CLI
def test_markdown_report(branch):
    md = to_markdown(branch, analyze(branch), "## Summary\nx", "offline")
    assert md.startswith("# NetOps report: BRANCH-SW01")
    assert "🔴 Duplex mismatch" in md


def test_cli_exit_codes(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert main([str(SAMPLES / "healthy-r1.txt")]) == 0
    assert main([str(SAMPLES / "branch-sw01.txt"), "--report", str(tmp_path / "r.md")]) == 1
    assert (tmp_path / "r.md").exists()
