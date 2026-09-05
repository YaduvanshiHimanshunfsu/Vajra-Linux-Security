"""Unit tests for the Causal Provenance Graph engine."""

from __future__ import annotations

import sys
from pathlib import Path

# Add service directory to sys.path
service_dir = Path(__file__).resolve().parents[1]
if str(service_dir) not in sys.path:
    sys.path.insert(0, str(service_dir))

from app.exporter import GraphExporter
from app.lineage import GraphEdge, GraphNode, ProvenanceGraph


def _make_process_exec_event(
    proc_id: str = "boot:1:101",
    executable: str = "/usr/sbin/nginx",
    parent_exe: str | None = "/usr/lib/systemd/systemd",
    object_value: str = "/usr/sbin/nginx",
    event_type: str = "PROCESS_EXEC",
) -> dict:
    event = {
        "event_type": event_type,
        "observed_at": "2026-09-01T00:00:00Z",
        "subject": {"process_id": proc_id, "executable": executable, "pid": 101, "uid": 33},
        "workload": {"workload_id": "nginx.service"},
        "object_value": object_value,
        "attributes": {},
    }
    if parent_exe:
        event["attributes"]["parent_executable"] = parent_exe
    return event


def test_ingest_creates_process_and_parent_nodes() -> None:
    graph = ProvenanceGraph()
    graph.ingest_event(_make_process_exec_event())
    assert len(graph.nodes) == 3  # parent node + process node + binary file node
    assert len(graph.edges) == 2  # SPAWNED + EXECUTED


def test_ingest_network_connect_creates_socket_node() -> None:
    graph = ProvenanceGraph()
    graph.ingest_event(
        _make_process_exec_event(
            event_type="NETWORK_CONNECT",
            object_value="198.51.100.4:4444",
            parent_exe=None,
        )
    )
    assert any(n.node_type == "socket" for n in graph.nodes.values())


def test_ingest_file_access_creates_file_node() -> None:
    graph = ProvenanceGraph()
    graph.ingest_event(
        _make_process_exec_event(
            event_type="FILE_ACCESS",
            object_value="/etc/shadow",
            parent_exe=None,
        )
    )
    assert any(n.node_type == "file" for n in graph.nodes.values())


def test_risk_upgrade_on_duplicate_node() -> None:
    graph = ProvenanceGraph()
    graph.ingest_event(_make_process_exec_event(), risk_score=0.1)
    graph.ingest_event(_make_process_exec_event(), risk_score=0.95)
    proc_node = graph.nodes.get("boot:1:101")
    assert proc_node is not None
    assert proc_node.risk_level == "critical"


def test_extract_causal_path() -> None:
    graph = ProvenanceGraph()
    graph.ingest_event(_make_process_exec_event(
        proc_id="child",
        parent_exe="/usr/sbin/nginx",
        executable="/tmp/nc",
        object_value="/tmp/nc",
    ))
    path = graph.extract_causal_path("child")
    assert len(path) >= 2
    assert path[-1] == "child"


def test_cytoscape_export_structure() -> None:
    graph = ProvenanceGraph()
    graph.ingest_event(_make_process_exec_event())
    result = GraphExporter.to_cytoscape_json(graph)
    assert "elements" in result
    assert result["node_count"] >= 2
    assert result["edge_count"] >= 1
    # Verify element structure
    for elem in result["elements"]:
        assert "data" in elem
        assert "id" in elem["data"]


def test_node_and_edge_bounding() -> None:
    graph = ProvenanceGraph(max_nodes=5, max_edges=10)
    for i in range(15):
        graph.ingest_event(_make_process_exec_event(
            proc_id=f"proc-{i}",
            executable=f"/usr/bin/proc_{i}",
            object_value=f"/usr/bin/proc_{i}",
        ))
    assert len(graph.nodes) <= 5
    assert len(graph.edges) <= 10
