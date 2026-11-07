from viruswall.behavior import ProcessInfo, ProcessMonitor
from viruswall.filesystem import DirectoryMonitor
from viruswall.heuristic import HeuristicAnalyzer
from viruswall.scanner import FileScanner
from viruswall.signatures import SignatureDatabase


def test_heuristic_and_scanner_integration(tmp_path):
    file = tmp_path / "invoice.pdf.exe"
    file.write_bytes(b"MZ" + b"powershell -enc AAAA")
    analyzer = HeuristicAnalyzer(sensitivity=80)
    findings = analyzer.analyze(file)
    assert {f.rule for f in findings} >= {"double_extension", "dangerous_construct"}
    result = FileScanner(SignatureDatabase(tmp_path / "db.json"), analyzers=[analyzer.analyze]).scan_file(file)
    assert result.status == "suspicious"
    assert result.findings


def test_heuristic_limits_false_positives(tmp_path):
    file = tmp_path / "normal.sh"
    file.write_text("echo hello")
    assert HeuristicAnalyzer().analyze(file) == []


def test_process_new_and_rule(tmp_path):
    parent = ProcessInfo(10, None, "winword.exe", "/app/word", 1.0, "now")
    child = ProcessInfo(11, 10, "powershell.exe", "/app/shell", 2.0, "now")
    snapshots = [[parent], [parent, child]]
    monitor = ProcessMonitor(lambda: snapshots.pop(0))
    assert monitor.new_processes() == []
    assert monitor.new_processes() == [child]
    assert monitor.analyze(child, [parent, child])[0].risk == "high"


def test_directory_monitor_events(tmp_path):
    events = []
    monitor = DirectoryMonitor(tmp_path, events.append)
    file = tmp_path / "sample.txt"
    file.write_text("a")
    assert [e.event_type for e in monitor.poll()] == ["created"]
    file.write_text("ab")
    assert [e.event_type for e in monitor.poll()] == ["modified"]
    file.unlink()
    assert [e.event_type for e in monitor.poll()] == ["deleted"]
    assert len(events) == 3
