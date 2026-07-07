from typing import Dict, Any, List, Optional, Tuple
from app.core.database import neo4j_driver
from app.core.logger import logger


class GraphManager:
    def __init__(self):
        self.driver = neo4j_driver

    async def create_node(self, labels: List[str], properties: Dict[str, Any]) -> str:
        async with self.driver.session() as session:
            label_str = ":".join(labels)
            result = await session.run(
                f"CREATE (n:{label_str} $props) RETURN elementId(n) as id",
                props=properties
            )
            record = await result.single()
            return record["id"]

    async def create_relationship(
        self, from_id: str, to_id: str, rel_type: str, properties: Dict[str, Any] = None
    ):
        async with self.driver.session() as session:
            await session.run(
                f"MATCH (a) WHERE elementId(a) = $from_id "
                f"MATCH (b) WHERE elementId(b) = $to_id "
                f"CREATE (a)-[r:{rel_type} $props]->(b) RETURN elementId(r)",
                from_id=from_id, to_id=to_id, props=properties or {}
            )

    async def find_paths(
        self, start_labels: List[str], end_labels: List[str], max_depth: int = 5
    ) -> List[Dict]:
        async with self.driver.session() as session:
            result = await session.run(
                f"MATCH path = shortestPath("
                f"(a:{':'.join(start_labels)})-[*..{max_depth}]-(b:{':'.join(end_labels)})) "
                f"RETURN path, length(path) as distance"
            )
            paths = []
            async for record in result:
                paths.append({"path": record["path"], "distance": record["distance"]})
            return paths

    async def get_blast_radius(self, node_id: str, depth: int = 3) -> Dict[str, Any]:
        async with self.driver.session() as session:
            result = await session.run(
                f"MATCH (n) WHERE elementId(n) = $node_id "
                f"MATCH (n)-[*..{depth}]-(connected) "
                f"RETURN DISTINCT connected, labels(connected) as types",
                node_id=node_id
            )
            nodes = []
            async for record in result:
                nodes.append({"node": record["connected"], "type": record["types"]})
            return {"blast_radius": nodes, "total_count": len(nodes)}

    async def query(self, cypher: str, params: Dict = None) -> List[Dict]:
        async with self.driver.session() as session:
            result = await session.run(cypher, params or {})
            return [record.data() async for record in result]

    async def close(self):
        await self.driver.close()


graph_manager = GraphManager()
