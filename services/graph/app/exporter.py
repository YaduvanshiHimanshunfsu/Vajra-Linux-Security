"""Graph serialization for UI and Cytoscape/D3 rendering."""

from __future__ import annotations

from typing import Any

from .lineage import ProvenanceGraph


class GraphExporter:
    @staticmethod
    def to_cytoscape_json(graph: ProvenanceGraph) -> dict[str, Any]:
        """Convert graph into standard Cytoscape elements structure."""
        elements: list[dict[str, Any]] = []

        # Export nodes
        for node in graph.nodes.values():
            elements.append(
                {
                    "data": {
                        "id": node.id,
                        "label": node.label,
                        "type": node.node_type,
                        "risk": node.risk_level,
                        **node.attributes,
                    }
                }
            )

        # Export edges
        for idx, edge in enumerate(graph.edges):
            elements.append(
                {
                    "data": {
                        "id": f"edge-{idx}",
                        "source": edge.source,
                        "target": edge.target,
                        "label": edge.relation,
                        "timestamp": edge.timestamp,
                    }
                }
            )

        return {"elements": elements, "node_count": len(graph.nodes), "edge_count": len(graph.edges)}
