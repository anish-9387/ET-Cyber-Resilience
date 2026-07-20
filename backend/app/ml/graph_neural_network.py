from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
import hashlib
import math
import pickle

import numpy as np

from app.core.logger import logger

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    nx = None
    NETWORKX_AVAILABLE = False


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
        self.reverse_adjacency: Dict[str, Dict[str, List[GraphEdge]]] = {}

    def add_node(self, node_id: str, node_type: str, features: Dict[str, Any] = None):
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(id=node_id, node_type=node_type, features=features or {})
            self.adjacency[node_id] = {}
            self.reverse_adjacency[node_id] = {}
        elif node_type != "unknown" and self.nodes[node_id].node_type == "unknown":
            self.nodes[node_id].node_type = node_type

    def add_edge(self, source_id: str, target_id: str, edge_type: str, weight: float = 1.0,
                 features: Dict[str, Any] = None):
        if source_id not in self.nodes:
            self.add_node(source_id, "unknown")
        if target_id not in self.nodes:
            self.add_node(target_id, "unknown")
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=weight,
            features=features or {},
        )
        self.edges.append(edge)
        self.adjacency[source_id].setdefault(target_id, []).append(edge)
        self.reverse_adjacency[target_id].setdefault(source_id, []).append(edge)

    def get_neighbors(self, node_id: str, edge_type: Optional[str] = None) -> List[Tuple[str, GraphEdge]]:
        neighbors = []
        for target_id, edges in self.adjacency.get(node_id, {}).items():
            for edge in edges:
                if edge_type is None or edge.edge_type == edge_type:
                    neighbors.append((target_id, edge))
        return neighbors

    def get_undirected_neighbors(self, node_id: str) -> List[str]:
        out = set(self.adjacency.get(node_id, {}).keys())
        out.update(self.reverse_adjacency.get(node_id, {}).keys())
        out.discard(node_id)
        return sorted(out)

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


def _bucket(value: str, buckets: int) -> int:
    digest = hashlib.blake2b(str(value).encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % buckets


class GraphStructuralEmbedder:
    """Deterministic structural node embeddings over a heterogeneous entity graph.

    No learned weights and no randomness: every dimension is a closed-form graph
    statistic, so the same graph always yields the same embedding.

    Layout (`embedding_dim` = 5 + 3 * type_buckets + edge_buckets):
      0    normalized out-degree
      1    normalized in-degree
      2    normalized total degree
      3    local clustering coefficient (undirected view)
      4    PageRank, scaled by node count
      5..  1-hop neighbour node-type histogram (hashed into `type_buckets`)
      ..   2-hop neighbour node-type histogram
      ..   own node-type one-hot (hashed)
      ..   incident edge-type histogram (hashed into `edge_buckets`)

    `fit()` records the mean/std of endpoint cosine similarity over the graph's
    edges, which turns `detect_anomalous_edges` into a z-score test against the
    observed baseline instead of a bare constant threshold.
    """

    def __init__(self, type_buckets: int = 8, edge_buckets: int = 8):
        self.type_buckets = type_buckets
        self.edge_buckets = edge_buckets
        self.embedding_dim = 5 + 3 * type_buckets + edge_buckets
        self.graph = HeterogeneousGraph()
        self._embeddings: Dict[str, np.ndarray] = {}
        self._pagerank: Dict[str, float] = {}
        self.baseline_mean: Optional[float] = None
        self.baseline_std: Optional[float] = None
        self.is_fitted: bool = False

    def build_from_events(self, events: List[Dict[str, Any]]):
        for event in events:
            source_id = event.get("source_ip") or event.get("user_id") or event.get("hostname")
            target_id = event.get("destination_ip") or event.get("target_host") or event.get("process_id")
            if not source_id or not target_id:
                continue
            self.graph.add_node(str(source_id), str(event.get("source_type", "unknown")))
            self.graph.add_node(str(target_id), str(event.get("target_type", "unknown")))
            self.graph.add_edge(
                source_id=str(source_id),
                target_id=str(target_id),
                edge_type=str(event.get("event_type", "related_to")),
                weight=float(event.get("severity_score", 1.0) or 1.0),
                features={"timestamp": event.get("timestamp"), "protocol": event.get("protocol")},
            )
        self._invalidate()
        logger.info(
            "Built structural graph",
            nodes=self.graph.node_count(),
            edges=self.graph.edge_count(),
        )

    def _invalidate(self):
        self._embeddings = {}
        self._pagerank = {}

    def _to_networkx(self):
        g = nx.DiGraph()
        for node_id, node in self.graph.nodes.items():
            g.add_node(node_id, node_type=node.node_type)
        for edge in self.graph.edges:
            if g.has_edge(edge.source_id, edge.target_id):
                g[edge.source_id][edge.target_id]["weight"] += edge.weight
            else:
                g.add_edge(edge.source_id, edge.target_id, weight=edge.weight)
        return g

    def _compute_pagerank(self) -> Dict[str, float]:
        n = self.graph.node_count()
        if n == 0:
            return {}
        if NETWORKX_AVAILABLE:
            try:
                return nx.pagerank(self._to_networkx(), alpha=0.85, weight="weight")
            except Exception as e:
                logger.warning("PageRank via networkx failed, using power iteration", error=str(e))
        return self._power_iteration_pagerank()

    def _power_iteration_pagerank(self, damping: float = 0.85, iterations: int = 50) -> Dict[str, float]:
        node_ids = sorted(self.graph.nodes.keys())
        n = len(node_ids)
        if n == 0:
            return {}
        rank = {nid: 1.0 / n for nid in node_ids}
        out_degree = {nid: len(self.graph.adjacency.get(nid, {})) for nid in node_ids}
        for _ in range(iterations):
            new_rank = {nid: (1.0 - damping) / n for nid in node_ids}
            dangling = sum(rank[nid] for nid in node_ids if out_degree[nid] == 0)
            for nid in node_ids:
                new_rank[nid] += damping * dangling / n
            for nid in node_ids:
                if out_degree[nid] == 0:
                    continue
                share = damping * rank[nid] / out_degree[nid]
                for target in self.graph.adjacency.get(nid, {}):
                    new_rank[target] = new_rank.get(target, 0.0) + share
            rank = new_rank
        return rank

    def _clustering_coefficient(self, node_id: str) -> float:
        neighbors = self.graph.get_undirected_neighbors(node_id)
        k = len(neighbors)
        if k < 2:
            return 0.0
        neighbor_set = set(neighbors)
        links = 0
        for nb in neighbors:
            links += len(neighbor_set.intersection(self.graph.get_undirected_neighbors(nb)))
        return links / (k * (k - 1))

    def _k_hop_type_histogram(self, node_id: str, hops: int) -> np.ndarray:
        histogram = np.zeros(self.type_buckets, dtype=np.float64)
        frontier = {node_id}
        seen = {node_id}
        for _ in range(hops):
            next_frontier = set()
            for nid in frontier:
                for nb in self.graph.get_undirected_neighbors(nid):
                    if nb not in seen:
                        next_frontier.add(nb)
            frontier = next_frontier
            seen.update(frontier)
        for nid in frontier:
            node = self.graph.nodes.get(nid)
            if node is not None:
                histogram[_bucket(node.node_type, self.type_buckets)] += 1.0
        total = histogram.sum()
        return histogram / total if total > 0 else histogram

    def _edge_type_histogram(self, node_id: str) -> np.ndarray:
        histogram = np.zeros(self.edge_buckets, dtype=np.float64)
        for edges in self.graph.adjacency.get(node_id, {}).values():
            for edge in edges:
                histogram[_bucket(edge.edge_type, self.edge_buckets)] += 1.0
        for edges in self.graph.reverse_adjacency.get(node_id, {}).values():
            for edge in edges:
                histogram[_bucket(edge.edge_type, self.edge_buckets)] += 1.0
        total = histogram.sum()
        return histogram / total if total > 0 else histogram

    def compute_embeddings(self) -> Dict[str, np.ndarray]:
        if self._embeddings:
            return self._embeddings

        n = max(self.graph.node_count(), 1)
        self._pagerank = self._compute_pagerank()

        embeddings: Dict[str, np.ndarray] = {}
        for node_id, node in self.graph.nodes.items():
            out_deg = len(self.graph.adjacency.get(node_id, {}))
            in_deg = len(self.graph.reverse_adjacency.get(node_id, {}))
            total_deg = len(self.graph.get_undirected_neighbors(node_id))

            scalars = np.array([
                math.log1p(out_deg) / math.log1p(n),
                math.log1p(in_deg) / math.log1p(n),
                math.log1p(total_deg) / math.log1p(n),
                self._clustering_coefficient(node_id),
                min(self._pagerank.get(node_id, 0.0) * n, 5.0) / 5.0,
            ], dtype=np.float64)

            own_type = np.zeros(self.type_buckets, dtype=np.float64)
            own_type[_bucket(node.node_type, self.type_buckets)] = 1.0

            vector = np.concatenate([
                scalars,
                self._k_hop_type_histogram(node_id, 1),
                self._k_hop_type_histogram(node_id, 2),
                own_type,
                self._edge_type_histogram(node_id),
            ])

            norm = float(np.linalg.norm(vector))
            embeddings[node_id] = vector / norm if norm > 0 else vector
            node.embedding = embeddings[node_id]

        self._embeddings = embeddings
        return embeddings

    def fit(self) -> Dict[str, Any]:
        embeddings = self.compute_embeddings()
        similarities = []
        for edge in self.graph.edges:
            src = embeddings.get(edge.source_id)
            tgt = embeddings.get(edge.target_id)
            if src is None or tgt is None:
                continue
            similarities.append(self._cosine(src, tgt))

        if similarities:
            arr = np.array(similarities, dtype=np.float64)
            self.baseline_mean = float(arr.mean())
            self.baseline_std = float(arr.std()) or 1e-6
            self.is_fitted = True
        else:
            self.baseline_mean = None
            self.baseline_std = None
            self.is_fitted = False

        logger.info(
            "Structural embedder fitted",
            nodes=self.graph.node_count(),
            edges=self.graph.edge_count(),
            baseline_mean=self.baseline_mean,
            baseline_std=self.baseline_std,
        )
        return {
            "is_fitted": self.is_fitted,
            "nodes": self.graph.node_count(),
            "edges": self.graph.edge_count(),
            "baseline_mean": self.baseline_mean,
            "baseline_std": self.baseline_std,
            "embedding_dim": self.embedding_dim,
        }

    @staticmethod
    def _cosine(a: np.ndarray, b: np.ndarray) -> float:
        denom = float(np.linalg.norm(a) * np.linalg.norm(b))
        if denom <= 0:
            return 0.0
        return float(np.dot(a, b) / denom)

    def detect_anomalous_edges(self, threshold: float = 0.8, z_threshold: float = 1.5) -> List[Dict[str, Any]]:
        """Flag edges whose endpoints are structurally dissimilar.

        Once `fit()` has run the test is a z-score against the graph's own edge
        similarity distribution; otherwise it degrades to the absolute
        `threshold` comparison.
        """
        embeddings = self.compute_embeddings()
        anomalous = []
        for edge in self.graph.edges:
            src = embeddings.get(edge.source_id)
            tgt = embeddings.get(edge.target_id)
            if src is None or tgt is None:
                continue
            similarity = self._cosine(src, tgt)

            if self.is_fitted and self.baseline_std:
                z_score = (self.baseline_mean - similarity) / self.baseline_std
                flagged = z_score > z_threshold
                method = "z_score"
            else:
                z_score = 0.0
                flagged = similarity < threshold
                method = "absolute_threshold"

            if flagged:
                anomalous.append({
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "type": edge.edge_type,
                    "similarity": round(similarity, 6),
                    "z_score": round(z_score, 4),
                    "method": method,
                    "weight": edge.weight,
                })
        anomalous.sort(key=lambda x: x["similarity"])
        return anomalous

    def most_central_nodes(self, top_k: int = 10) -> List[Dict[str, Any]]:
        self.compute_embeddings()
        ranked = sorted(self._pagerank.items(), key=lambda kv: kv[1], reverse=True)
        return [
            {
                "node_id": nid,
                "node_type": self.graph.nodes[nid].node_type if nid in self.graph.nodes else "unknown",
                "pagerank": round(score, 6),
            }
            for nid, score in ranked[:top_k]
        ]

    def find_attack_paths(self, start_node: str, max_depth: int = 5) -> List[List[str]]:
        paths: List[List[str]] = []

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

        dfs(start_node, [start_node], {start_node})
        paths.sort(key=len, reverse=True)
        return paths[:20]

    def save(self, path: str):
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls, path: str):
        with open(path, "rb") as f:
            return pickle.load(f)
