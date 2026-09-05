"""Parent-first, dual-token scheduler for recursive pipeline DAGs."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
import heapq
from typing import Any, Callable

from scripts import recursive_pipeline_protocol as protocol


@dataclass
class SchedulerMetrics:
    peak_cpu_tokens: int = 0
    peak_rss_tokens: int = 0
    max_parallel_tasks: int = 0


class TokenScheduler:
    """Schedule ready nodes without exceeding either declared token budget."""

    def __init__(
        self, nodes: dict[str, dict[str, Any]], allowed: set[str], *,
        cpu_tokens: int, rss_tokens: int, max_workers: int,
        dependency_ids: Callable[[dict[str, Any]], list[str]],
        priority: Callable[[str], tuple[int, str]],
    ) -> None:
        protocol.require(cpu_tokens > 0 and rss_tokens > 0 and max_workers > 0,
                         "pipeline scheduler capacity differs")
        self.nodes = nodes
        self.allowed = allowed
        self.cpu_tokens = cpu_tokens
        self.rss_tokens = rss_tokens
        self.max_workers = max_workers
        self.dependency_ids = dependency_ids
        self.priority = priority
        self.dependents = {node_id: [] for node_id in allowed}
        self.pending: dict[str, int] = {}
        for node_id in allowed:
            dependencies = [item for item in dependency_ids(nodes[node_id])
                            if item in allowed]
            self.pending[node_id] = len(dependencies)
            for dependency in dependencies:
                self.dependents[dependency].append(node_id)

    def run(
        self, execute: Callable[[str], Any],
        accept: Callable[[str, Any, set[str]], None],
    ) -> SchedulerMetrics:
        ready = [self.priority(node_id) for node_id, count in self.pending.items()
                 if count == 0]
        heapq.heapify(ready)
        running: dict[Future[Any], tuple[str, int, int]] = {}
        completed: set[str] = set()
        used_cpu = 0
        used_rss = 0
        metrics = SchedulerMetrics()

        def take_fitting() -> str | None:
            held: list[tuple[int, str]] = []
            result = None
            while ready:
                item = heapq.heappop(ready)
                node = self.nodes[item[1]]
                if (node["cpu_tokens"] <= self.cpu_tokens - used_cpu
                        and node["rss_tokens"] <= self.rss_tokens - used_rss):
                    result = item[1]
                    break
                held.append(item)
            for item in held:
                heapq.heappush(ready, item)
            return result

        with ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="recursive-pipeline",
        ) as executor:
            while ready or running:
                while len(running) < self.max_workers:
                    node_id = take_fitting()
                    if node_id is None:
                        break
                    node = self.nodes[node_id]
                    cpu = node["cpu_tokens"]
                    rss = node["rss_tokens"]
                    used_cpu += cpu
                    used_rss += rss
                    future = executor.submit(execute, node_id)
                    running[future] = (node_id, cpu, rss)
                    metrics.peak_cpu_tokens = max(metrics.peak_cpu_tokens, used_cpu)
                    metrics.peak_rss_tokens = max(metrics.peak_rss_tokens, used_rss)
                    metrics.max_parallel_tasks = max(
                        metrics.max_parallel_tasks, len(running),
                    )
                protocol.require(bool(running),
                                 "ready pipeline nodes cannot fit token budget")
                done, _ = wait(tuple(running), return_when=FIRST_COMPLETED)
                for future in sorted(done, key=lambda item: self.priority(running[item][0])):
                    node_id, cpu, rss = running.pop(future)
                    used_cpu -= cpu
                    used_rss -= rss
                    value = future.result()
                    protected = {
                        dependency
                        for running_node, _, _ in running.values()
                        for dependency in self.dependency_ids(self.nodes[running_node])
                    }
                    accept(node_id, value, protected)
                    completed.add(node_id)
                    for dependent in self.dependents[node_id]:
                        self.pending[dependent] -= 1
                        if self.pending[dependent] == 0:
                            heapq.heappush(ready, self.priority(dependent))
        protocol.require(completed == self.allowed,
                         "pipeline scheduler did not close its selected DAG")
        return metrics
