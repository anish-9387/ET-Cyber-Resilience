"""Neo4j access layer.

Every method is a no-op returning an empty result when Neo4j is disabled or
unreachable, so the knowledge-graph enrichment is strictly additive: the
in-memory world model remains the source of truth for the demo path.
"""

from typing import Any, Dict, List, Optional

from app.core.database import neo4j_driver
from app.core.logger import logger


class GraphManager:
    def __init__(self):
        self.driver = neo4j_driver

    @property
    def available(self) -> bool:
        return self.driver is not None

    async def create_node(self, labels: List[str], properties: Dict[str, Any]) -> Optional[str]:
        if not self.available:
            return None
        try:
            async with self.driver.session() as session:
                label_str = ":".join(labels)
                result = await session.run(
                    f"CREATE (n:{label_str} $props) RETURN elementId(n) as id",
                    props=properties,
                )
                record = await result.single()
                return record["id"]
        except Exception as exc:
            logger.warning("graph_create_node_failed", error=str(exc))
            return None

    async def create_relationship(
        self, from_id: str, to_id: str, rel_type: str, properties: Dict[str, Any] = None
    ) -> bool:
        if not self.available:
            return False
        try:
            async with self.driver.session() as session:
                await session.run(
                    "MATCH (a) WHERE elementId(a) = $from_id "
                    "MATCH (b) WHERE elementId(b) = $to_id "
                    f"CREATE (a)-[r:{rel_type} $props]->(b) RETURN elementId(r)",
                    from_id=from_id,
                    to_id=to_id,
                    props=properties or {},
                )
            return True
        except Exception as exc:
            logger.warning("graph_create_relationship_failed", error=str(exc))
            return False

    async def find_paths(
        self, start_labels: List[str], end_labels: List[str], max_depth: int = 5
    ) -> List[Dict]:
        if not self.available:
            return []
        try:
            async with self.driver.session() as session:
                result = await session.run(
                    f"MATCH path = shortestPath("
                    f"(a:{':'.join(start_labels)})-[*..{max_depth}]-(b:{':'.join(end_labels)})) "
                    f"RETURN path, length(path) as distance"
                )
                return [
                    {"path": record["path"], "distance": record["distance"]}
                    async for record in result
                ]
        except Exception as exc:
            logger.warning("graph_find_paths_failed", error=str(exc))
            return []

    async def get_blast_radius(self, node_id: str, depth: int = 3) -> Dict[str, Any]:
        if not self.available:
            return {"blast_radius": [], "total_count": 0, "source": "unavailable"}
        try:
            async with self.driver.session() as session:
                result = await session.run(
                    f"MATCH (n) WHERE elementId(n) = $node_id "
                    f"MATCH (n)-[*..{depth}]-(connected) "
                    f"RETURN DISTINCT connected, labels(connected) as types",
                    node_id=node_id,
                )
                nodes = [
                    {"node": record["connected"], "type": record["types"]}
                    async for record in result
                ]
                return {"blast_radius": nodes, "total_count": len(nodes), "source": "neo4j"}
        except Exception as exc:
            logger.warning("graph_blast_radius_failed", error=str(exc))
            return {"blast_radius": [], "total_count": 0, "source": "error"}

    async def query(self, cypher: str, params: Dict = None) -> List[Dict]:
        if not self.available:
            return []
        try:
            async with self.driver.session() as session:
                result = await session.run(cypher, params or {})
                return [record.data() async for record in result]
        except Exception as exc:
            logger.warning("graph_query_failed", error=str(exc))
            return []

    async def close(self):
        if self.available:
            await self.driver.close()


graph_manager = GraphManager()
