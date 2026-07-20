"""Vector memory over knowledge-graph nodes.

Both sentence-transformers and Qdrant are optional. The module imports cleanly
without either installed or running; every entry point checks ``self.available``
first so a missing vector store degrades to "no semantic recall" rather than an
import-time crash.
"""

from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from app.core.database import qdrant_client
from app.core.config import settings
from app.core.logger import logger
import uuid

try:
    from sentence_transformers import SentenceTransformer

    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:  # pragma: no cover - optional heavy dependency
    SentenceTransformer = None
    SENTENCE_TRANSFORMERS_AVAILABLE = False

try:
    from qdrant_client.http.models import (
        PointStruct,
        VectorParams,
        Distance,
        Filter,
        FieldCondition,
        MatchValue,
        ScoredPoint,
    )

    QDRANT_MODELS_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    PointStruct = VectorParams = Distance = Filter = None
    FieldCondition = MatchValue = ScoredPoint = None
    QDRANT_MODELS_AVAILABLE = False


COLLECTION_NAME = "graph_node_embeddings"
EMBEDDING_DIMENSION = 384


class GraphEmbeddings:
    def __init__(self):
        self.model_name = settings.EMBEDDING_MODEL
        self.model: Optional[SentenceTransformer] = None
        self._loaded = False
        self.dimension = self._get_dimension()

    def _get_dimension(self) -> int:
        model_map = {
            "all-MiniLM-L6-v2": 384,
            "all-mpnet-base-v2": 768,
            "all-distilroberta-v1": 768,
            "multi-qa-MiniLM-L6-cos-v1": 384,
        }
        return model_map.get(self.model_name, EMBEDDING_DIMENSION)

    @property
    def available(self) -> bool:
        return (
            qdrant_client is not None
            and QDRANT_MODELS_AVAILABLE
            and SENTENCE_TRANSFORMERS_AVAILABLE
        )

    async def _load_model(self):
        if self._loaded:
            return
        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            logger.warning("embedding_model_unavailable", model=self.model_name)
            return
        self.model = SentenceTransformer(self.model_name)
        self._loaded = True
        logger.info("embedding_model_loaded", model=self.model_name)

    async def _ensure_collection(self):
        try:
            collections = qdrant_client.get_collections()
            exists = any(
                c.name == COLLECTION_NAME for c in collections.collections
            )
            if not exists:
                qdrant_client.create_collection(
                    collection_name=COLLECTION_NAME,
                    vectors_config=VectorParams(
                        size=self.dimension,
                        distance=Distance.COSINE,
                    ),
                )
                logger.info("Embedding collection created", collection=COLLECTION_NAME)
        except Exception as e:
            logger.error("Failed to ensure collection", error=str(e))
            raise

    async def create_embedding(self, text: str) -> List[float]:
        await self._load_model()
        embedding = self.model.encode(text, show_progress_bar=False)
        return embedding.tolist()

    async def create_node_embedding(
        self,
        node_type: str,
        node_id: str,
        properties: Dict[str, Any]
    ) -> str:
        embed_text = self._build_embedding_text(node_type, properties)
        vector = await self.create_embedding(embed_text)
        point_id = str(uuid.uuid4())

        await self._ensure_collection()

        qdrant_client.upsert(
            collection_name=COLLECTION_NAME,
            points=[
                PointStruct(
                    id=point_id,
                    vector=vector,
                    payload={
                        "node_id": node_id,
                        "node_type": node_type,
                        "text": embed_text,
                        **{k: str(v) for k, v in properties.items()},
                    },
                )
            ],
        )
        return point_id

    async def batch_create_embeddings(
        self,
        nodes: List[Tuple[str, str, Dict[str, Any]]]
    ) -> List[str]:
        await self._load_model()
        await self._ensure_collection()

        texts = [
            self._build_embedding_text(node_type, props)
            for node_type, _, props in nodes
        ]
        embeddings = self.model.encode(texts, show_progress_bar=True)
        point_ids = []

        points = []
        for i, (node_type, node_id, props) in enumerate(nodes):
            point_id = str(uuid.uuid4())
            point_ids.append(point_id)
            points.append(
                PointStruct(
                    id=point_id,
                    vector=embeddings[i].tolist(),
                    payload={
                        "node_id": node_id,
                        "node_type": node_type,
                        "text": texts[i],
                        **{k: str(v) for k, v in props.items()},
                    },
                )
            )

        qdrant_client.upsert(
            collection_name=COLLECTION_NAME,
            points=points,
        )
        return point_ids

    async def search_similar(
        self,
        query: str,
        node_type: Optional[str] = None,
        top_k: int = 10,
        threshold: float = 0.5,
    ) -> List[Dict[str, Any]]:
        query_vector = await self.create_embedding(query)

        query_filter = None
        if node_type:
            query_filter = Filter(
                must=[
                    FieldCondition(
                        key="node_type",
                        match=MatchValue(value=node_type),
                    )
                ]
            )

        results = qdrant_client.search(
            collection_name=COLLECTION_NAME,
            query_vector=query_vector,
            limit=top_k,
            score_threshold=threshold,
            query_filter=query_filter,
        )

        return [
            {
                "node_id": hit.payload.get("node_id"),
                "node_type": hit.payload.get("node_type"),
                "text": hit.payload.get("text"),
                "score": hit.score,
                "properties": {
                    k: v for k, v in hit.payload.items()
                    if k not in ("node_id", "node_type", "text")
                },
            }
            for hit in results
        ]

    async def search_by_node_type(
        self,
        node_type: str,
        top_k: int = 100,
    ) -> List[Dict[str, Any]]:
        query_filter = Filter(
            must=[
                FieldCondition(
                    key="node_type",
                    match=MatchValue(value=node_type),
                )
            ]
        )

        results = qdrant_client.scroll(
            collection_name=COLLECTION_NAME,
            limit=top_k,
            query_filter=query_filter,
        )
        return [
            {
                "node_id": hit.payload.get("node_id"),
                "node_type": hit.payload.get("node_type"),
                "text": hit.payload.get("text"),
                "properties": {
                    k: v for k, v in hit.payload.items()
                    if k not in ("node_id", "node_type", "text")
                },
            }
            for hit in results[0]
        ]

    async def delete_node_embedding(self, point_id: str):
        qdrant_client.delete(
            collection_name=COLLECTION_NAME,
            points_selector=[point_id],
        )

    async def delete_embeddings_by_node_id(self, node_id: str):
        scroll_result = qdrant_client.scroll(
            collection_name=COLLECTION_NAME,
            limit=100,
            query_filter=Filter(
                must=[
                    FieldCondition(
                        key="node_id",
                        match=MatchValue(value=node_id),
                    )
                ]
            ),
        )
        point_ids = [hit.id for hit in scroll_result[0]]
        if point_ids:
            qdrant_client.delete(
                collection_name=COLLECTION_NAME,
                points_selector=point_ids,
            )

    async def get_collection_stats(self) -> Dict[str, Any]:
        collection_info = qdrant_client.get_collection(COLLECTION_NAME)
        return {
            "name": COLLECTION_NAME,
            "status": collection_info.status,
            "vectors_count": collection_info.points_count,
            "dimension": self.dimension,
            "model": self.model_name,
        }

    def _build_embedding_text(self, node_type: str, properties: Dict[str, Any]) -> str:
        parts = [f"Node Type: {node_type}"]
        important_keys = [
            "name", "hostname", "description", "username", "email",
            "role", "category", "device_type", "department", "service",
            "cve_id", "technique_id", "policy_id",
        ]
        for key in important_keys:
            if key in properties:
                parts.append(f"{key}: {properties[key]}")

        label_keys = [
            "os", "os_version", "version", "firmware_version",
            "protocol", "vendor", "manufacturer", "location",
            "ip_address", "domain",
        ]
        for key in label_keys:
            if key in properties:
                parts.append(f"{key}: {properties[key]}")

        for key, value in properties.items():
            if key not in important_keys and key not in label_keys:
                if isinstance(value, (str, int, float, bool)):
                    parts.append(f"{key}: {value}")

        return " | ".join(parts)


graph_embeddings = GraphEmbeddings()
