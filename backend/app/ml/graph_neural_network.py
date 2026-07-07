from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from app.core.logger import logger
from dataclasses import dataclass, field


@dataclass
class GraphNode:
    id: str
    node_type: str
    features: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[np.ndarray] = None


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    edge_type: str
    weight: float = 1.0
    features: Dict[str, Any] = field(default_factory=dict)


class HeterogeneousGraph:
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.adjacency: Dict[str, Dict[str, List[GraphEdge]]] = {}

    def add_node(self, node_id: str, node_type: str, features: Dict[str, Any] = None):
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(id=node_id, node_type=node_type, features=features or {})
            self.adjacency[node_id] = {}

    def add_edge(self, source_id: str, target_id: str, edge_type: str, weight: float = 1.0, features: Dict[str, Any] = None):
        if source_id not in self.nodes:
            self.add_node(source_id, "unknown")
        if target_id not in self.nodes:
            self.add_node(target_id, "unknown")
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=weight,
            features=features or {}
        )
        self.edges.append(edge)
        if target_id not in self.adjacency[source_id]:
            self.adjacency[source_id][target_id] = []
        self.adjacency[source_id][target_id].append(edge)

    def get_neighbors(self, node_id: str, edge_type: Optional[str] = None) -> List[Tuple[str, GraphEdge]]:
        neighbors = []
        if node_id not in self.adjacency:
            return neighbors
        for target_id, edges in self.adjacency[node_id].items():
            for edge in edges:
                if edge_type is None or edge.edge_type == edge_type:
                    neighbors.append((target_id, edge))
        return neighbors

    def get_subgraph(self, node_ids: List[str]) -> "HeterogeneousGraph":
        subgraph = HeterogeneousGraph()
        node_set = set(node_ids)
        for nid in node_ids:
            if nid in self.nodes:
                subgraph.add_node(nid, self.nodes[nid].node_type, self.nodes[nid].features)
        for edge in self.edges:
            if edge.source_id in node_set and edge.target_id in node_set:
                subgraph.add_edge(edge.source_id, edge.target_id, edge.edge_type, edge.weight, edge.features)
        return subgraph

    def node_count(self) -> int:
        return len(self.nodes)

    def edge_count(self) -> int:
        return len(self.edges)


class GraphNeuralNetwork:
    def __init__(self, input_dim: int = 128, hidden_dim: int = 64, output_dim: int = 32):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        self.graph = HeterogeneousGraph()
        self.is_trained = False

        import numpy as np
        self._W1 = np.random.randn(input_dim, hidden_dim) * 0.01
        self._W2 = np.random.randn(hidden_dim, output_dim) * 0.01

    def build_from_events(self, events: List[Dict[str, Any]]):
        for event in events:
            source_id = event.get("source_ip") or event.get("user_id") or event.get("hostname")
            target_id = event.get("destination_ip") or event.get("target_host") or event.get("process_id")
            if not source_id or not target_id:
                continue
            self.graph.add_node(source_id, "entity", {"type": event.get("source_type", "unknown")})
            self.graph.add_node(target_id, "entity", {"type": event.get("target_type", "unknown")})
            self.graph.add_edge(
                source_id=source_id,
                target_id=target_id,
                edge_type=event.get("event_type", "related_to"),
                weight=event.get("severity_score", 1.0),
                features={"timestamp": event.get("timestamp"), "protocol": event.get("protocol")}
            )
        logger.info("Built graph with %d nodes and %d edges", self.graph.node_count(), self.graph.edge_count())

    def compute_embeddings(self) -> Dict[str, np.ndarray]:
        embeddings = {}
        for node_id, node in self.graph.nodes.items():
            raw_features = self._extract_features(node)
            h1 = np.tanh(raw_features @ self._W1)
            h2 = h1 @ self._W2
            embeddings[node_id] = h2 / (np.linalg.norm(h2) + 1e-8)
        return embeddings

    def _extract_features(self, node: GraphNode) -> np.ndarray:
        import numpy as np
        features = np.zeros(self.input_dim)
        for i, (key, value) in enumerate(node.features.items()):
            if i >= self.input_dim:
                break
            if isinstance(value, (int, float)):
                features[i] = float(value)
            elif isinstance(value, str):
                features[i] = float(hash(value) % 1000) / 1000.0
        return features

    def detect_anomalous_edges(self, threshold: float = 0.8) -> List[Dict[str, Any]]:
        anomalous = []
        embeddings = self.compute_embeddings()
        for edge in self.graph.edges:
            src_emb = embeddings.get(edge.source_id)
            tgt_emb = embeddings.get(edge.target_id)
            if src_emb is not None and tgt_emb is not None:
                similarity = float(np.dot(src_emb, tgt_emb) / (np.linalg.norm(src_emb) * np.linalg.norm(tgt_emb) + 1e-8))
                if similarity < threshold:
                    anomalous.append({
                        "source": edge.source_id,
                        "target": edge.target_id,
                        "type": edge.edge_type,
                        "similarity": similarity,
                        "weight": edge.weight
                    })
        return anomalous

    def find_attack_paths(self, start_node: str, max_depth: int = 5) -> List[List[str]]:
        paths = []

        def dfs(current: str, path: List[str], visited: set):
            if len(path) > max_depth:
                return
            if len(path) > 1:
                paths.append(path[:])
            for neighbor, _ in self.graph.get_neighbors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    dfs(neighbor, path + [neighbor], visited)
                    visited.remove(neighbor)

        visited = {start_node}
        dfs(start_node, [start_node], visited)
        paths.sort(key=len, reverse=True)
        return paths[:20]

    def save(self, path: str):
        import pickle
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, path: str):
        import pickle
        with open(path, "rb") as f:
            return pickle.load(f)
