"""Knowledge retrieval abstractions for agentic planning."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class RetrievalHit:
    """Single retrieval match returned to an agent."""

    source: str
    title: str
    snippet: str
    score: float


class KnowledgeRetriever:
    """Interface for local-first retrieval providers."""

    async def retrieve(self, query: str, *, limit: int = 5) -> list[RetrievalHit]:
        raise NotImplementedError


class NullKnowledgeRetriever(KnowledgeRetriever):
    """No-op retriever used when no corpus is configured."""

    async def retrieve(self, query: str, *, limit: int = 5) -> list[RetrievalHit]:
        return []


class CompositeKnowledgeRetriever(KnowledgeRetriever):
    """Chain multiple retrievers and deduplicate their hits."""

    def __init__(self, retrievers: Iterable[KnowledgeRetriever]) -> None:
        self.retrievers = list(retrievers)

    async def retrieve(self, query: str, *, limit: int = 5) -> list[RetrievalHit]:
        merged: list[RetrievalHit] = []
        for retriever in self.retrievers:
            merged.extend(await retriever.retrieve(query, limit=limit))

        deduped: dict[tuple[str, str], RetrievalHit] = {}
        for hit in merged:
            key = (hit.source, hit.title)
            current = deduped.get(key)
            if current is None or hit.score > current.score:
                deduped[key] = hit
        ranked = sorted(deduped.values(), key=lambda item: item.score, reverse=True)
        return ranked[:limit]


class GraphifyKnowledgeRetriever(KnowledgeRetriever):
    """Retrieve compact subgraph snippets from a persisted Graphify graph."""

    def __init__(self, graph_path: Path | None = None) -> None:
        repo_root = Path(__file__).resolve().parents[4]
        self.graph_path = graph_path or repo_root / "graphify-out" / "graph.json"
        self._graph: dict | None = None

    async def retrieve(self, query: str, *, limit: int = 5) -> list[RetrievalHit]:
        graph = self._load_graph()
        if graph is None:
            return []

        terms = [term.lower() for term in query.split() if len(term.strip()) >= 3]
        if not terms:
            return []

        nodes = graph.get("nodes", [])
        links = graph.get("links", [])
        node_by_id = {str(node.get("id")): node for node in nodes}
        adjacency: dict[str, list[dict]] = {}
        for link in links:
            source = str(link.get("source", ""))
            target = str(link.get("target", ""))
            adjacency.setdefault(source, []).append(link)
            adjacency.setdefault(target, []).append(link)

        scored: list[RetrievalHit] = []
        for node in nodes:
            label = str(node.get("label", ""))
            source_file = str(node.get("source_file", node.get("source", "")))
            searchable = " ".join(
                [
                    label,
                    str(node.get("norm_label", "")),
                    str(node.get("file_type", "")),
                    source_file,
                ]
            ).lower()
            matched = [term for term in terms if term in searchable]
            if not matched:
                continue

            score = float(sum(searchable.count(term) for term in matched))
            node_id = str(node.get("id", ""))
            local_edges = adjacency.get(node_id, [])[:4]
            snippets: list[str] = []
            for edge in local_edges:
                other_id = str(edge.get("target") if str(edge.get("source")) == node_id else edge.get("source"))
                other = node_by_id.get(other_id, {})
                other_label = str(other.get("label", other_id))
                relation = str(edge.get("label", "related_to"))
                snippets.append(f"{label} -[{relation}]-> {other_label}")
            snippet = " | ".join(snippets) if snippets else label
            title = label or node_id
            scored.append(
                RetrievalHit(
                    source=source_file or self.graph_path.name,
                    title=title,
                    snippet=snippet[:280],
                    score=score + (0.5 * len(local_edges)),
                )
            )
        scored.sort(key=lambda item: item.score, reverse=True)
        return scored[:limit]

    async def retrieve_attack_paths(self, query: str, *, limit: int = 5) -> list[dict[str, str | float]]:
        graph = self._load_graph()
        if graph is None:
            return []

        terms = [term.lower() for term in query.split() if len(term.strip()) >= 3]
        if not terms:
            return []

        nodes = graph.get("nodes", [])
        links = graph.get("links", [])
        hyperedges = graph.get("graph", {}).get("hyperedges", [])
        node_by_id = {str(node.get("id")): node for node in nodes}

        matched_ids: set[str] = set()
        for node in nodes:
            searchable = " ".join(
                [
                    str(node.get("label", "")),
                    str(node.get("norm_label", "")),
                    str(node.get("source_file", "")),
                ]
            ).lower()
            if any(term in searchable for term in terms):
                matched_ids.add(str(node.get("id", "")))

        paths: list[dict[str, str | float]] = []
        for hyperedge in hyperedges:
            label = str(hyperedge.get("label", ""))
            nodes_in_hyperedge = [str(item) for item in hyperedge.get("nodes", [])]
            if matched_ids.intersection(nodes_in_hyperedge) or any(term in label.lower() for term in terms):
                named_members = [str(node_by_id.get(node_id, {}).get("label", node_id)) for node_id in nodes_in_hyperedge[:5]]
                paths.append(
                    {
                        "name": label or "graphify_hyperedge",
                        "steps": " -> ".join(named_members),
                        "narrative": str(hyperedge.get("relation", "related concepts")),
                        "score": float(hyperedge.get("confidence_score", 0.5)),
                    }
                )

        for link in links:
            source = str(link.get("source", ""))
            target = str(link.get("target", ""))
            if source not in matched_ids and target not in matched_ids:
                continue
            source_label = str(node_by_id.get(source, {}).get("label", source))
            target_label = str(node_by_id.get(target, {}).get("label", target))
            relation = str(link.get("label", "related_to"))
            paths.append(
                {
                    "name": f"{source_label} to {target_label}",
                    "steps": f"{source_label} -> {target_label}",
                    "narrative": relation,
                    "score": float(0.4),
                }
            )

        unique: dict[tuple[str, str], dict[str, str | float]] = {}
        for item in paths:
            key = (str(item.get("name", "")), str(item.get("steps", "")))
            current = unique.get(key)
            if current is None or float(item.get("score", 0.0)) > float(current.get("score", 0.0)):
                unique[key] = item
        ranked = sorted(unique.values(), key=lambda row: float(row.get("score", 0.0)), reverse=True)
        return ranked[:limit]

    def _load_graph(self) -> dict | None:
        if self._graph is not None:
            return self._graph
        if not self.graph_path.exists():
            return None
        try:
            self._graph = json.loads(self.graph_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return self._graph


class FileSystemKnowledgeRetriever(KnowledgeRetriever):
    """A lightweight local retriever over markdown, yaml, json, and text files."""

    def __init__(self, roots: Iterable[Path] | None = None) -> None:
        repo_root = Path(__file__).resolve().parents[4]
        default_roots = [repo_root / "docs", repo_root / "data"]
        self.roots = [Path(root) for root in (roots or default_roots)]

    async def retrieve(self, query: str, *, limit: int = 5) -> list[RetrievalHit]:
        terms = [term.lower() for term in query.split() if len(term.strip()) >= 3]
        if not terms:
            return []

        hits: list[RetrievalHit] = []
        for path in self._iter_candidate_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lowered = text.lower()
            matched = [term for term in terms if term in lowered]
            if not matched:
                continue
            score = float(sum(lowered.count(term) for term in matched))
            snippet = self._extract_snippet(text, matched[0])
            hits.append(
                RetrievalHit(
                    source=str(path),
                    title=path.name,
                    snippet=snippet,
                    score=score,
                )
            )
        hits.sort(key=lambda item: item.score, reverse=True)
        return hits[:limit]

    def _iter_candidate_files(self) -> Iterable[Path]:
        patterns = ("*.md", "*.txt", "*.yaml", "*.yml", "*.json")
        for root in self.roots:
            if not root.exists():
                continue
            for pattern in patterns:
                yield from root.rglob(pattern)

    def _extract_snippet(self, text: str, term: str, *, radius: int = 160) -> str:
        lowered = text.lower()
        index = lowered.find(term)
        if index < 0:
            return text[:radius].strip()
        start = max(0, index - radius // 2)
        end = min(len(text), start + radius)
        return " ".join(text[start:end].split())


def default_retriever() -> KnowledgeRetriever:
    """Return the best available local-first retriever stack."""
    graphify = GraphifyKnowledgeRetriever()
    if graphify.graph_path.exists():
        return CompositeKnowledgeRetriever([graphify, FileSystemKnowledgeRetriever()])
    return FileSystemKnowledgeRetriever()
