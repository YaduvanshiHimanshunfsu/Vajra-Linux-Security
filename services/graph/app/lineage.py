"""Causal Provenance Graph Engine.

Reconstructs directed causal execution graphs from streaming kernel telemetry:
Process -> Process (spawn), Process -> File (access/write), Process -> Socket (connect).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class GraphNode:
    id: str
    label: str
    node_type: str  # "process", "file", "socket", "cgroup"
    risk_level: str = "normal"  # "normal", "medium", "high", "critical"
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str  # "SPAWNED", "ACCESSED", "CONNECTED_TO", "DROPPED"
    timestamp: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


class ProvenanceGraph:
    """Directed temporal provenance graph tracking execution ancestry."""

    def __init__(self, max_nodes: int = 500, max_edges: int = 2000) -> None:
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self._adjacency: dict[str, list[str]] = {}  # source -> targets
        self._reverse_adjacency: dict[str, list[str]] = {}  # target -> sources

    def add_node(self, node: GraphNode) -> None:
        if node.id not in self.nodes:
            if len(self.nodes) >= self.max_nodes:
                oldest_key = next(iter(self.nodes))
                del self.nodes[oldest_key]
            self.nodes[node.id] = node
        else:
            # Upgrade risk level if higher
            existing = self.nodes[node.id]
            if node.risk_level in ("critical", "high") and existing.risk_level != "critical":
                existing.risk_level = node.risk_level
            existing.attributes.update(node.attributes)

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)
        if len(self.edges) > self.max_edges:
            self.edges = self.edges[-self.max_edges:]
        self._adjacency.setdefault(edge.source, []).append(edge.target)
        self._reverse_adjacency.setdefault(edge.target, []).append(edge.source)

    def ingest_event(self, event_dict: dict[str, Any], risk_score: float = 0.0) -> None:
        """Ingest a normalized SecurityEvent into the provenance graph."""
        event_type = event_dict.get("event_type", "")
        subject = event_dict.get("subject", {})
        workload = event_dict.get("workload", {})
        object_value = event_dict.get("object_value", "")
        obs_at = event_dict.get("observed_at", datetime.now(timezone.utc).isoformat())

        proc_id = subject.get("process_id", "proc-unknown")
        proc_exe = subject.get("executable", "unknown")
        parent_exe = event_dict.get("attributes", {}).get("parent_executable")

        risk_level = (
            "critical" if risk_score >= 0.85 else "high" if risk_score >= 0.60 else "medium" if risk_score >= 0.30 else "normal"
        )

        # 1. Add Process Node
        self.add_node(
            GraphNode(
                id=proc_id,
                label=proc_exe.split("/")[-1] or proc_exe,
                node_type="process",
                risk_level=risk_level,
                attributes={
                    "executable": proc_exe,
                    "pid": subject.get("pid", 0),
                    "uid": subject.get("uid", 1000),
                    "workload": workload.get("workload_id", "default"),
                },
            )
        )

        # 2. Add Parent Node & Spawn Edge if parent exists
        if parent_exe:
            parent_id = f"parent:{parent_exe}"
            self.add_node(
                GraphNode(
                    id=parent_id,
                    label=parent_exe.split("/")[-1] or parent_exe,
                    node_type="process",
                    risk_level="normal",
                    attributes={"executable": parent_exe},
                )
            )
            self.add_edge(
                GraphEdge(
                    source=parent_id,
                    target=proc_id,
                    relation="SPAWNED",
                    timestamp=obs_at,
                )
            )

        # 3. Handle Object Specific Edges
        if event_type == "PROCESS_EXEC":
            file_node_id = f"bin:{object_value}"
            self.add_node(
                GraphNode(
                    id=file_node_id,
                    label=object_value.split("/")[-1] or object_value,
                    node_type="file",
                    risk_level=risk_level,
                    attributes={"path": object_value},
                )
            )
            self.add_edge(
                GraphEdge(
                    source=proc_id,
                    target=file_node_id,
                    relation="EXECUTED",
                    timestamp=obs_at,
                )
            )

        elif event_type == "NETWORK_CONNECT":
            socket_node_id = f"socket:{object_value}"
            self.add_node(
                GraphNode(
                    id=socket_node_id,
                    label=object_value,
                    node_type="socket",
                    risk_level=risk_level,
                    attributes={"destination": object_value},
                )
            )
            self.add_edge(
                GraphEdge(
                    source=proc_id,
                    target=socket_node_id,
                    relation="CONNECTED_TO",
                    timestamp=obs_at,
                )
            )

        elif event_type == "FILE_ACCESS":
            file_node_id = f"file:{object_value}"
            self.add_node(
                GraphNode(
                    id=file_node_id,
                    label=object_value.split("/")[-1] or object_value,
                    node_type="file",
                    risk_level=risk_level,
                    attributes={"path": object_value},
                )
            )
            self.add_edge(
                GraphEdge(
                    source=proc_id,
                    target=file_node_id,
                    relation="ACCESSED",
                    timestamp=obs_at,
                )
            )

    def extract_causal_path(self, target_node_id: str) -> list[str]:
        """Find the root ancestor path leading to a suspicious node."""
        path: list[str] = []
        visited = set()
        curr = target_node_id

        while curr and curr not in visited:
            visited.add(curr)
            path.append(curr)
            parents = self._reverse_adjacency.get(curr, [])
            curr = parents[0] if parents else None

        path.reverse()
        return path
