from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field
import math
import random
from app.core.logger import logger
from app.digital_twin.state_manager import state_manager, EntityStatus, EntityCategory
from app.knowledge_graph.graph_manager import graph_manager


class LayoutAlgorithm(str, Enum):
    HIERARCHICAL = "hierarchical"
    FORCE_DIRECTED = "force_directed"
    RADIAL = "radial"
    GRID = "grid"


class VisualStyle(str, Enum):
    DEFAULT = "default"
    ATTACK_SIMULATION = "attack_simulation"
    BLAST_RADIUS = "blast_radius"
    CROWN_JEWEL = "crown_jewel"
    DEPARTMENT = "department"


STATUS_COLORS = {
    EntityStatus.HEALTHY: {"bg": "#22c55e", "border": "#16a34a", "text": "#ffffff"},
    EntityStatus.DEGRADED: {"bg": "#eab308", "border": "#ca8a04", "text": "#000000"},
    EntityStatus.COMPROMISED: {"bg": "#ef4444", "border": "#dc2626", "text": "#ffffff"},
    EntityStatus.OFFLINE: {"bg": "#6b7280", "border": "#4b5563", "text": "#ffffff"},
    EntityStatus.UNDER_ATTACK: {"bg": "#f97316", "border": "#ea580c", "text": "#ffffff"},
    EntityStatus.ISOLATED: {"bg": "#8b5cf6", "border": "#7c3aed", "text": "#ffffff"},
    EntityStatus.RECOVERING: {"bg": "#06b6d4", "border": "#0891b2", "text": "#ffffff"},
    EntityStatus.UNKNOWN: {"bg": "#94a3b8", "border": "#64748b", "text": "#ffffff"},
}

CATEGORY_ICONS = {
    EntityCategory.SERVER: "server",
    EntityCategory.NETWORK_DEVICE: "network-wired",
    EntityCategory.IOT_DEVICE: "microchip",
    EntityCategory.OT_DEVICE: "industry",
    EntityCategory.APPLICATION: "window-restore",
    EntityCategory.DATABASE: "database",
    EntityCategory.IDENTITY: "id-card",
    EntityCategory.USER: "user",
    EntityCategory.CLOUD_SERVICE: "cloud",
    EntityCategory.CREDENTIAL: "key",
}

CATEGORY_SHAPES = {
    EntityCategory.SERVER: "rounded-rect",
    EntityCategory.NETWORK_DEVICE: "diamond",
    EntityCategory.IOT_DEVICE: "circle",
    EntityCategory.OT_DEVICE: "hexagon",
    EntityCategory.APPLICATION: "rounded-rect",
    EntityCategory.DATABASE: "cylinder",
    EntityCategory.IDENTITY: "pill",
    EntityCategory.USER: "circle",
    EntityCategory.CLOUD_SERVICE: "cloud",
    EntityCategory.CREDENTIAL: "pill",
}

CATEGORY_SIZES = {
    EntityCategory.SERVER: 12,
    EntityCategory.NETWORK_DEVICE: 10,
    EntityCategory.IOT_DEVICE: 8,
    EntityCategory.OT_DEVICE: 8,
    EntityCategory.APPLICATION: 10,
    EntityCategory.DATABASE: 11,
    EntityCategory.IDENTITY: 7,
    EntityCategory.USER: 9,
    EntityCategory.CLOUD_SERVICE: 9,
    EntityCategory.CREDENTIAL: 6,
}


@dataclass
class VisualNode:
    id: str
    label: str
    category: str
    status: str
    x: float
    y: float
    size: int
    color: str
    border_color: str
    text_color: str
    icon: str
    shape: str
    opacity: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    animation_state: Optional[str] = None
    pulse: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "category": self.category,
            "status": self.status,
            "position": {"x": self.x, "y": self.y},
            "size": self.size,
            "color": self.color,
            "borderColor": self.border_color,
            "textColor": self.text_color,
            "icon": self.icon,
            "shape": self.shape,
            "opacity": self.opacity,
            "properties": self.properties,
            "animationState": self.animation_state,
            "pulse": self.pulse,
        }


@dataclass
class VisualEdge:
    id: str
    source: str
    target: str
    label: str
    style: str = "solid"
    color: str = "#64748b"
    width: float = 1.0
    opacity: float = 0.6
    animated: bool = False
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "label": self.label,
            "style": self.style,
            "color": self.color,
            "width": self.width,
            "opacity": self.opacity,
            "animated": self.animated,
            "properties": self.properties,
        }


@dataclass
class VisualizationData:
    nodes: List[VisualNode] = field(default_factory=list)
    edges: List[VisualEdge] = field(default_factory=list)
    layout: str = "force_directed"
    viewport: Dict[str, float] = field(default_factory=lambda: {"x": 0, "y": 0, "zoom": 1})
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "layout": self.layout,
            "viewport": self.viewport,
            "metadata": self.metadata,
        }


class TwinVisualizer:
    def __init__(self):
        self._layout_cache: Dict[str, Dict[str, Tuple[float, float]]] = {}

    async def generate_visualization(
        self,
        style: VisualStyle = VisualStyle.DEFAULT,
        layout: LayoutAlgorithm = LayoutAlgorithm.FORCE_DIRECTED,
        filter_status: Optional[List[str]] = None,
        filter_category: Optional[List[str]] = None,
    ) -> VisualizationData:
        entities = state_manager.get_all_entities()
        if filter_status:
            entities = [e for e in entities if e.status.value in filter_status]
        if filter_category:
            entities = [e for e in entities if e.category.value in filter_category]

        positions = await self._compute_layout(entities, layout, style)
        nodes = await self._create_visual_nodes(entities, positions, style)
        edges = await self._create_visual_edges(entities, nodes, style)

        status_counts = state_manager.get_status_summary()
        entity_counts = state_manager.get_entity_count()

        return VisualizationData(
            nodes=nodes,
            edges=edges,
            layout=layout.value,
            metadata={
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "status_summary": status_counts,
                "entity_summary": entity_counts,
                "style": style.value,
                "generated_at": __import__("datetime").datetime.now().isoformat(),
            },
        )

    async def generate_attack_animation(
        self,
        compromised_entity_ids: List[str],
        animation_frames: int = 10,
    ) -> List[VisualizationData]:
        all_entities = state_manager.get_all_entities()
        base_positions = await self._compute_layout(
            all_entities, LayoutAlgorithm.FORCE_DIRECTED, VisualStyle.ATTACK_SIMULATION
        )

        frames = []
        for frame_idx in range(animation_frames):
            progress = frame_idx / max(animation_frames - 1, 1)
            visible_compromised = compromised_entity_ids[:int(len(compromised_entity_ids) * progress) + 1]

            entities_copy = []
            for entity in all_entities:
                import copy
                e_copy = copy.copy(entity)
                if entity.entity_id in visible_compromised:
                    e_copy = copy.copy(entity)
                    old_status = e_copy.status
                    e_copy.status = EntityStatus.COMPROMISED
                elif entity.entity_id in compromised_entity_ids:
                    pass
                entities_copy.append(e_copy)

            nodes = await self._create_visual_nodes(
                entities_copy, base_positions, VisualStyle.ATTACK_SIMULATION
            )
            edges = await self._create_visual_edges(entities_copy, nodes, VisualStyle.ATTACK_SIMULATION)

            for node in nodes:
                if node.id in visible_compromised:
                    node.pulse = True
                    node.animation_state = "compromised"

            frames.append(VisualizationData(
                nodes=nodes,
                edges=edges,
                layout="force_directed",
                metadata={"frame": frame_idx, "progress": progress, "total_frames": animation_frames},
            ))

        return frames

    async def generate_blast_radius_visualization(
        self,
        center_entity_id: str,
        depth: int = 2,
    ) -> VisualizationData:
        blast_data = await graph_manager.get_blast_radius(center_entity_id, depth)
        blast_ids = {center_entity_id}

        for item in blast_data["blast_radius"]:
            blast_ids.add(item["node"].element_id)

        all_entities = state_manager.get_all_entities()
        relevant = [e for e in all_entities if e.entity_id in blast_ids]

        positions = {}
        center_x, center_y = 400, 300
        positions[center_entity_id] = (center_x, center_y)

        ring = 0
        ring_items = []
        for item in blast_data["blast_radius"]:
            node_id = item["node"].element_id
            if node_id != center_entity_id:
                ring_items.append(node_id)
        ring_items = list(set(ring_items))

        ring_distance = 120
        for i, node_id in enumerate(ring_items):
            angle = (2 * math.pi * i) / max(len(ring_items), 1)
            positions[node_id] = (
                center_x + ring_distance * math.cos(angle),
                center_y + ring_distance * math.sin(angle),
            )

        nodes = await self._create_visual_nodes(relevant, positions, VisualStyle.BLAST_RADIUS)
        edges = await self._create_visual_edges(relevant, nodes, VisualStyle.BLAST_RADIUS)

        for node in nodes:
            if node.id == center_entity_id:
                node.pulse = True
                node.opacity = 1.0

        return VisualizationData(
            nodes=nodes,
            edges=edges,
            layout="radial",
            metadata={
                "center_entity_id": center_entity_id,
                "blast_radius_count": len(blast_ids) - 1,
                "depth": depth,
            },
        )

    async def _compute_layout(
        self,
        entities: List[EntityState],
        algorithm: LayoutAlgorithm,
        style: VisualStyle,
    ) -> Dict[str, Tuple[float, float]]:
        cache_key = f"{algorithm.value}_{style.value}_{len(entities)}"
        if cache_key in self._layout_cache:
            return self._layout_cache[cache_key]

        if algorithm == LayoutAlgorithm.FORCE_DIRECTED:
            positions = self._force_directed_layout(entities)
        elif algorithm == LayoutAlgorithm.HIERARCHICAL:
            positions = self._hierarchical_layout(entities)
        elif algorithm == LayoutAlgorithm.RADIAL:
            positions = self._radial_layout(entities)
        else:
            positions = self._grid_layout(entities)

        self._layout_cache[cache_key] = positions
        if len(self._layout_cache) > 50:
            self._layout_cache.clear()

        return positions

    def _force_directed_layout(self, entities: List[EntityState]) -> Dict[str, Tuple[float, float]]:
        import random
        positions = {
            e.entity_id: (
                random.uniform(50, 750),
                random.uniform(50, 550),
            )
            for e in entities
        }

        entity_ids = list(positions.keys())
        width, height = 800, 600
        center_x, center_y = width / 2, height / 2
        iterations = 50
        repulsion = 5000.0
        attraction = 0.01
        damping = 0.9

        for iteration in range(iterations):
            forces = {eid: [0.0, 0.0] for eid in entity_ids}

            for i, eid1 in enumerate(entity_ids):
                for eid2 in entity_ids[i + 1:]:
                    dx = positions[eid1][0] - positions[eid2][0]
                    dy = positions[eid1][1] - positions[eid2][1]
                    dist = max(math.sqrt(dx * dx + dy * dy), 1.0)
                    force = repulsion / (dist * dist)
                    fx = force * dx / dist
                    fy = force * dy / dist
                    forces[eid1][0] += fx
                    forces[eid1][1] += fy
                    forces[eid2][0] -= fx
                    forces[eid2][1] -= fy

            for eid in entity_ids:
                dx = center_x - positions[eid][0]
                dy = center_y - positions[eid][1]
                forces[eid][0] += dx * attraction
                forces[eid][1] += dy * attraction

            for eid in entity_ids:
                forces[eid][0] *= damping
                forces[eid][1] *= damping
                x, y = positions[eid]
                positions[eid] = (
                    max(30, min(width - 30, x + forces[eid][0])),
                    max(30, min(height - 30, y + forces[eid][1])),
                )

        return positions

    def _hierarchical_layout(self, entities: List[EntityState]) -> Dict[str, Tuple[float, float]]:
        levels = {
            EntityCategory.FIREWALL: 0,
            EntityCategory.SWITCH: 1,
            EntityCategory.NETWORK_DEVICE: 1,
            EntityCategory.SERVER: 2,
            EntityCategory.DATABASE: 2,
            EntityCategory.APPLICATION: 3,
            EntityCategory.IOT_DEVICE: 3,
            EntityCategory.OT_DEVICE: 3,
            EntityCategory.IDENTITY: 4,
            EntityCategory.USER: 4,
            EntityCategory.CLOUD_SERVICE: 4,
        }

        level_entities: Dict[int, List[EntityState]] = {}
        for entity in entities:
            level = levels.get(entity.category, 2)
            level_entities.setdefault(level, []).append(entity)

        positions = {}
        y_spacing = 100
        x_spacing = 120
        start_y = 50

        for level in sorted(level_entities.keys()):
            ents = level_entities[level]
            total_width = len(ents) * x_spacing
            start_x = (800 - total_width) / 2 + x_spacing / 2
            y = start_y + level * y_spacing

            for i, entity in enumerate(ents):
                positions[entity.entity_id] = (start_x + i * x_spacing, y)

        return positions

    def _radial_layout(self, entities: List[EntityState]) -> Dict[str, Tuple[float, float]]:
        center_x, center_y = 400, 300
        radius = 250

        category_order = sorted(set(e.category for e in entities),
                                key=lambda c: list(EntityCategory).index(c) if c in EntityCategory.__members__.values() else 999)

        angle_map = {}
        for i, cat in enumerate(category_order):
            cat_entities = [e for e in entities if e.category == cat]
            for j, entity in enumerate(cat_entities):
                angle = (2 * math.pi * (i + j / max(len(cat_entities), 1))) / max(len(category_order), 1)
                angle_map[entity.entity_id] = angle

        return {
            e.entity_id: (
                center_x + radius * math.cos(angle_map.get(e.entity_id, 0)),
                center_y + radius * math.sin(angle_map.get(e.entity_id, 0)),
            )
            for e in entities
        }

    def _grid_layout(self, entities: List[EntityState]) -> Dict[str, Tuple[float, float]]:
        cols = max(int(math.sqrt(len(entities))), 1)
        x_spacing = 100
        y_spacing = 80
        positions = {}

        for i, entity in enumerate(entities):
            col = i % cols
            row = i // cols
            positions[entity.entity_id] = (50 + col * x_spacing, 50 + row * y_spacing)

        return positions

    async def _create_visual_nodes(
        self,
        entities: List[EntityState],
        positions: Dict[str, Tuple[float, float]],
        style: VisualStyle,
    ) -> List[VisualNode]:
        nodes = []
        for entity in entities:
            pos = positions.get(entity.entity_id, (0, 0))
            colors = STATUS_COLORS.get(entity.status, STATUS_COLORS[EntityStatus.UNKNOWN])

            label = (
                entity.properties.get("name")
                or entity.properties.get("hostname")
                or entity.properties.get("username")
                or entity.entity_id[:12]
            )

            node = VisualNode(
                id=entity.entity_id,
                label=str(label),
                category=entity.category.value,
                status=entity.status.value,
                x=pos[0],
                y=pos[1],
                size=CATEGORY_SIZES.get(entity.category, 10) * (1.3 if entity.status == EntityStatus.COMPROMISED else 1.0),
                color=colors["bg"],
                border_color=colors["border"],
                text_color=colors["text"],
                icon=CATEGORY_ICONS.get(entity.category, "circle"),
                shape=CATEGORY_SHAPES.get(entity.category, "circle"),
                opacity=0.4 if entity.status == EntityStatus.OFFLINE else 1.0,
                properties={
                    "entity_id": entity.entity_id,
                    "category": entity.category.value,
                    "criticality": entity.properties.get("criticality", "unknown"),
                    "ip": entity.properties.get("ip_address", ""),
                    "department": entity.properties.get("department", ""),
                },
                pulse=(entity.status == EntityStatus.UNDER_ATTACK or entity.status == EntityStatus.COMPROMISED),
            )
            nodes.append(node)

        return nodes

    async def _create_visual_edges(
        self,
        entities: List[EntityState],
        nodes: List[VisualNode],
        style: VisualStyle,
    ) -> List[VisualEdge]:
        node_ids = {n.id for n in nodes}
        edges = []

        for entity in entities:
            for connected_id in entity.connected_entities:
                if connected_id in node_ids:
                    edge_id = f"{entity.entity_id}->{connected_id}"
                    edge = VisualEdge(
                        id=edge_id,
                        source=entity.entity_id,
                        target=connected_id,
                        label="",
                        style="solid",
                        color="#64748b",
                        width=1.0,
                        opacity=0.6,
                        animated=False,
                        properties={"relation": "connected"},
                    )

                    if style == VisualStyle.ATTACK_SIMULATION:
                        if entity.status == EntityStatus.COMPROMISED:
                            edge.color = "#ef4444"
                            edge.width = 2.0
                            edge.opacity = 0.9
                        elif entity.status == EntityStatus.DEGRADED:
                            edge.color = "#eab308"
                            edge.width = 1.5

                    edges.append(edge)

        return edges

    async def clear_cache(self):
        self._layout_cache.clear()
        logger.info("Visualizer layout cache cleared")


twin_visualizer = TwinVisualizer()
