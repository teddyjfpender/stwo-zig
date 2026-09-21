"""Crash-resumable DAG scheduler for the recursive proof pipeline.

Python owns custody, scheduling, and recovery.  A registered Zig worker owns
all production key derivation, proof construction, and cold validation.
"""

from __future__ import annotations

from dataclasses import dataclass
import heapq
import os
from typing import Any, Callable, Iterable

from scripts import ethereum_block_proof_protocol as proof_protocol
from scripts import recursive_pipeline_artifacts as artifacts_mod
from scripts import recursive_pipeline_journal as journal_mod
from scripts import recursive_pipeline_protocol as protocol
from scripts import recursive_pipeline_registry as registry_mod
from scripts import recursive_pipeline_scheduler as scheduler_mod
from scripts import recursive_pipeline_store as store_mod


SEMANTIC_KEY_KIND = 2
EXECUTION_KEY_KIND = 3
CONTROL_SCHEMA_VERSION = 1


class InjectedCrash(RuntimeError):
    """Test-only interruption after a durable phase boundary."""


CrashHook = Callable[[str, str], None]


@dataclass
class NodeState:
    node: dict[str, Any]
    cache_record: dict[str, Any]
    lease: registry_mod.Lease
    semantic: dict[str, Any] | None = None
    ordered_inputs: list[dict[str, Any]] | None = None


@dataclass
class RunSummary:
    committed: int = 0
    cache_hits: int = 0
    recovered: int = 0
    executed: int = 0
    reprofiled: int = 0
    max_live_leases: int = 0
    goal_output: dict[str, Any] | None = None
    goal_cache_record_sha256: str | None = None
    peak_cpu_tokens: int = 0
    peak_rss_tokens: int = 0
    max_parallel_tasks: int = 0


def dependency_ids(node: dict[str, Any]) -> list[str]:
    return [item["node_id"] for item in node["dependencies"]]


class Runner(artifacts_mod.ArtifactCustodyMixin):
    def __init__(
        self, workspace: store_mod.Workspace, manifest: dict[str, Any],
        run_id: str, registry: registry_mod.StageRegistry,
        execution_authorities: dict[str, str], *, cpu_tokens: int,
        rss_tokens: int, crash_hook: CrashHook | None = None,
        prepare_run: bool = True, lease_frontier_limit: int = 64,
    ) -> None:
        protocol.validate_pipeline_manifest(manifest)
        protocol.require(cpu_tokens > 0 and rss_tokens > 0,
                         "pipeline scheduler token budget differs")
        for field in protocol.EXECUTION_AUTHORITY_FIELDS:
            protocol.nonzero_digest(execution_authorities.get(field),
                                    f"pipeline execution authority {field}")
        protocol.require(set(execution_authorities)
                         == set(protocol.EXECUTION_AUTHORITY_FIELDS),
                         "pipeline execution authority fields differ")
        self.workspace = workspace
        self.manifest = manifest
        self.run_id = run_id
        self.registry = registry
        self.execution_authorities = dict(execution_authorities)
        self.cpu_tokens = cpu_tokens
        self.rss_tokens = rss_tokens
        self.crash_hook = crash_hook
        protocol.require(lease_frontier_limit > 0,
                         "pipeline lease frontier differs")
        self.lease_frontier_limit = lease_frontier_limit
        self.nodes = {node["node_id"]: node for node in manifest["nodes"]}
        self.order = {node["node_id"]: index
                      for index, node in enumerate(manifest["nodes"])}
        if prepare_run:
            self.workspace.prepare_run(run_id, manifest)
        else:
            self.workspace.open_run(run_id, manifest)
        self.promotion_intents: dict[str, str] = {}

    def run(
        self, *, through: str | None = None,
        reprofile: Iterable[str] = (), promote: dict[str, str] | None = None,
    ) -> RunSummary:
        with self.workspace.run_lock(self.run_id, exclusive=True):
            return self._run_locked(
                through=through, reprofile=reprofile, promote=promote,
            )

    def _run_locked(
        self, *, through: str | None = None,
        reprofile: Iterable[str] = (), promote: dict[str, str] | None = None,
    ) -> RunSummary:
        allowed = self._allowed_nodes(through)
        self._preflight_adapters(allowed)
        reprofile_set = set(reprofile)
        protocol.require(reprofile_set <= allowed,
                         "reprofile node is outside the selected pipeline")
        for node_id in reprofile_set:
            protocol.require(node_id in self.nodes,
                             "reprofile node is absent")
        self.promotion_intents = dict(promote or {})
        protocol.require(set(self.promotion_intents) <= allowed,
                         "pipeline promotion is outside the selected DAG")
        for node_id, identity in self.promotion_intents.items():
            protocol.require(node_id in self.nodes,
                             "pipeline promotion node is absent")
            protocol.digest(identity, "pipeline promotion candidate")

        dependents: dict[str, list[str]] = {node_id: [] for node_id in allowed}
        for node_id in allowed:
            dependencies = [item for item in dependency_ids(self.nodes[node_id])
                            if item in allowed]
            for dependency in dependencies:
                dependents[dependency].append(node_id)
        remaining_consumers = {
            node_id: len(dependents[node_id]) for node_id in allowed
        }
        summary = RunSummary()
        states: dict[str, NodeState] = {}

        def execute(node_id: str) -> tuple[NodeState, str]:
            node = self.nodes[node_id]
            dependencies = [item for item in dependency_ids(node) if item in allowed]
            dependency_states = [states[item] for item in dependencies]
            for dependency in dependency_states:
                if dependency.lease.released:
                    protocol.require(dependency.semantic is not None
                                     and dependency.ordered_inputs is not None,
                                     "evicted pipeline lease has no reopen authority")
                    dependency.lease = self._cold_open_record(
                        dependency.node, dependency.ordered_inputs,
                        dependency.semantic, dependency.cache_record, "cold",
                    ).lease
            ordered_inputs = self._ordered_inputs(node, dependency_states)
            return self._materialize_node(
                node, ordered_inputs, dependency_states,
                reprofile=node_id in reprofile_set,
            )

        def accept(
            node_id: str, value: tuple[NodeState, str], protected: set[str],
        ) -> None:
            state, disposition = value
            node = self.nodes[node_id]
            dependencies = [item for item in dependency_ids(node) if item in allowed]
            state.semantic = self._read_semantic(state.cache_record)
            state.ordered_inputs = self._stage_inputs(state.cache_record)
            states[node_id] = state
            setattr(summary, disposition, getattr(summary, disposition) + 1)
            summary.committed += 1
            for dependency in dependencies:
                remaining_consumers[dependency] -= 1
                if remaining_consumers[dependency] == 0:
                    states[dependency].lease.close()
            if remaining_consumers[node_id] == 0:
                state.lease.close()
            while sum(not item.lease.released for item in states.values()) > self.lease_frontier_limit:
                evictable = next((
                    item for candidate_id, item in states.items()
                    if candidate_id not in protected and candidate_id != node_id
                    and not item.lease.released
                ), None)
                protocol.require(evictable is not None,
                                 "pipeline live lease frontier cannot be evicted")
                evictable.lease.close()
            summary.max_live_leases = max(
                summary.max_live_leases,
                sum(not item.lease.released for item in states.values()),
            )

        try:
            scheduler = scheduler_mod.TokenScheduler(
                self.nodes, allowed, cpu_tokens=self.cpu_tokens,
                rss_tokens=self.rss_tokens,
                max_workers=self.registry.max_parallelism(),
                dependency_ids=dependency_ids, priority=self._priority,
            )
            metrics = scheduler.run(execute, accept)
            summary.peak_cpu_tokens = metrics.peak_cpu_tokens
            summary.peak_rss_tokens = metrics.peak_rss_tokens
            summary.max_parallel_tasks = metrics.max_parallel_tasks
            goal = self._selected_goal(allowed)
            if goal is not None:
                summary.goal_output = states[goal].cache_record["output_artifact"]
                summary.goal_cache_record_sha256 = states[goal].cache_record[
                    "content_sha256"
                ]
            return summary
        finally:
            for state in states.values():
                state.lease.close()

    def verify(self, *, mode: str = "deep") -> RunSummary:
        with self.workspace.run_lock(self.run_id, exclusive=False):
            return self._verify_locked(mode=mode)

    def _verify_locked(self, *, mode: str = "deep") -> RunSummary:
        protocol.require(mode in ("deep", "root"),
                         "pipeline verification mode differs")
        selected_nodes = set(self.nodes) if mode == "deep" else {self.manifest["goal"]}
        self._preflight_adapters(selected_nodes)
        dependents = {node_id: [] for node_id in selected_nodes}
        pending: dict[str, int] = {}
        for node_id in selected_nodes:
            internal = [item for item in dependency_ids(self.nodes[node_id])
                        if item in selected_nodes]
            pending[node_id] = len(internal)
            for dependency in internal:
                dependents[dependency].append(node_id)
        consumers = {node_id: len(dependents[node_id]) for node_id in selected_nodes}
        ready = [self._priority(node_id) for node_id, count in pending.items()
                 if count == 0]
        heapq.heapify(ready)
        states: dict[str, NodeState] = {}
        summary = RunSummary()
        try:
            while ready:
                _, node_id = heapq.heappop(ready)
                node = self.nodes[node_id]
                dependencies: list[NodeState] = []
                ordered_inputs = list(node["external_inputs"])
                for index, dependency_spec in enumerate(node["dependencies"]):
                    dependency_id = dependency_spec["node_id"]
                    if dependency_id in states:
                        dependency = states[dependency_id]
                        dependencies.append(dependency)
                        artifact = dependency.cache_record["output_artifact"]
                    else:
                        dependency_ref = self.workspace.read_run_ref(
                            self.run_id, dependency_id,
                        )
                        artifact = dependency_ref["output_artifact"]
                    ordered_inputs.append({
                        "role": dependency_spec["role"],
                        "ordinal": dependency_spec["ordinal"],
                        "blob": artifact,
                    })
                adapter = self.registry.get(node["adapter"])
                description = registry_mod.validate_stage_description(
                    adapter.describe(node), node,
                )
                if mode == "root":
                    protocol.require(description["root_cold_open_transitive"],
                                     "root coldOpen is not transitive")
                keys = adapter.derive(
                    self.manifest["campaign_namespace_sha256"], node, ordered_inputs,
                    self.execution_authorities,
                )
                semantic = keys.semantic
                run_ref = self.workspace.read_run_ref(self.run_id, node_id)
                protocol.require(run_ref["semantic_key_sha256"]
                                 == semantic["identity_sha256"],
                                 "selected pipeline semantic key is stale")
                record = self.workspace.cache_record_by_identity(
                    run_ref["semantic_key_sha256"],
                    run_ref["cache_record_sha256"],
                )
                state = self._revalidate_cache(
                    node, ordered_inputs, semantic, record, adapter,
                    validation_mode="root" if mode == "root" else "cold",
                )
                states[node_id] = state
                summary.committed += 1
                summary.cache_hits += 1
                summary.max_live_leases = max(
                    summary.max_live_leases,
                    sum(not item.lease.released for item in states.values()),
                )
                for dependency in dependencies:
                    dependency_id = dependency.node["node_id"]
                    consumers[dependency_id] -= 1
                    if consumers[dependency_id] == 0:
                        dependency.lease.close()
                        states.pop(dependency_id, None)
                for dependent in dependents[node_id]:
                    pending[dependent] -= 1
                    if pending[dependent] == 0:
                        heapq.heappush(ready, self._priority(dependent))
                if consumers[node_id] == 0 and node_id != self.manifest["goal"]:
                    state.lease.close()
                    states.pop(node_id, None)
            protocol.require(summary.committed == len(selected_nodes),
                             "pipeline verification DAG did not close")
            root = self.manifest["goal"]
            root_state = states[root]
            summary.goal_output = root_state.cache_record["output_artifact"]
            summary.goal_cache_record_sha256 = root_state.cache_record[
                "content_sha256"
            ]
            return summary
        finally:
            for state in states.values():
                state.lease.close()

    def status(self) -> dict[str, Any]:
        with self.workspace.run_lock(self.run_id, exclusive=False):
            return self._status_locked()

    def _status_locked(self) -> dict[str, Any]:
        selected = 0
        committed = 0
        active: list[str] = []
        for node in self.manifest["nodes"]:
            node_id = node["node_id"]
            if self.workspace.maybe_run_ref(self.run_id, node_id) is not None:
                selected += 1
            stage_root = self.workspace.runs / self.run_id / "stages" / node_id.replace("/", "@")
            if not os.path.lexists(stage_root):
                continue
            state = journal_mod.StageAttemptJournal.read_state(
                stage_root, self.manifest["content_sha256"], node_id,
            )
            committed += len(state["committed"])
            if state["active"] is not None:
                active.append(node_id)
        return {
            "manifest_sha256": self.manifest["content_sha256"],
            "node_count": len(self.nodes),
            "selected_count": selected,
            "committed_attempt_count": committed,
            "active_nodes": sorted(active),
        }

    def _materialize_node(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        dependency_states: list[NodeState], *, reprofile: bool,
    ) -> tuple[NodeState, str]:
        self._require_tokens(node)
        adapter = self.registry.get(node["adapter"])
        registry_mod.validate_stage_description(adapter.describe(node), node)
        keys = adapter.derive(
            self.manifest["campaign_namespace_sha256"], node, ordered_inputs,
            self.execution_authorities,
        )
        semantic, execution = keys.semantic, keys.execution
        semantic_ref = self.workspace.put_blob(
            keys.semantic_bytes, kind=SEMANTIC_KEY_KIND,
            schema_version=CONTROL_SCHEMA_VERSION,
        )
        execution_ref = self.workspace.put_blob(
            keys.execution_bytes, kind=EXECUTION_KEY_KIND,
            schema_version=CONTROL_SCHEMA_VERSION,
        )
        selected = self._selected_record(node, semantic)

        recovered = None
        if not reprofile:
            recovered = self._recover_attempt(
                node, ordered_inputs, semantic, execution, semantic_ref,
                execution_ref, adapter, dependency_states,
            )
        promotion = self.promotion_intents.get(node["node_id"])
        if promotion is not None:
            if recovered is not None:
                recovered.lease.close()
            protocol.require(selected is not None,
                             "pipeline promotion requires a selected candidate")
            promoted = self._promote_node(
                node, ordered_inputs, semantic, adapter, promotion,
            )
            return promoted, "cache_hits"
        if not reprofile:
            if recovered is not None:
                if selected is None:
                    self.workspace.publish_run_ref(
                        self.run_id, node["node_id"], recovered.cache_record,
                    )
                    return recovered, "recovered"
                if (recovered.cache_record["output_artifact"]
                        == selected["output_artifact"]
                        and recovered.cache_record["stage_result"]
                        == selected["stage_result"]):
                    return recovered, "recovered"
                recovered.lease.close()
                return self._open_selected(
                    node, ordered_inputs, semantic, selected,
                ), "recovered"
            cached = self._find_cached(node, ordered_inputs, semantic, execution, adapter)
            if cached is not None:
                if selected is None:
                    self.workspace.publish_run_ref(self.run_id, node["node_id"],
                                                   cached.cache_record)
                return cached, "cache_hits"

        built = self._execute_attempt(
            node, ordered_inputs, semantic, execution, semantic_ref,
            execution_ref, adapter, dependency_states,
        )
        if selected is None:
            self.workspace.publish_run_ref(self.run_id, node["node_id"],
                                           built.cache_record)
            return built, "executed"
        if reprofile:
            built.lease.close()
            selected_open = self._open_selected(node, ordered_inputs, semantic, selected)
            return selected_open, "reprofiled"
        return built, "executed"

    def _execute_attempt(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], execution: dict[str, Any],
        semantic_ref: dict[str, Any], execution_ref: dict[str, Any],
        adapter: registry_mod.StageAdapter, dependency_states: list[NodeState],
    ) -> NodeState:
        stage_root = self.workspace.stage_root(self.run_id, node["node_id"])
        with journal_mod.StageAttemptJournal(
            stage_root, self.manifest["content_sha256"], node["node_id"],
            self.workspace.staging,
        ) as journal:
            index, attempt_directory = journal.begin(
                semantic["identity_sha256"], execution["identity_sha256"],
            )
            self._crash("intent", node["node_id"])
            journal.mark_running(index)
            self._crash("running", node["node_id"])
            try:
                candidate = adapter.build(
                    node, ordered_inputs, semantic, execution,
                    [item.lease for item in dependency_states], attempt_directory,
                )
                refs = self._publish_candidate_files(
                    node, ordered_inputs, index, attempt_directory, candidate,
                    semantic_ref, execution_ref,
                )
                self._crash("candidate_written", node["node_id"])
                journal.outputs_published(
                    index, output_artifact=refs["output_artifact"],
                    stage_result=refs["stage_result"],
                    profile_receipt=refs["profile_receipt"],
                )
                self._crash("outputs_published", node["node_id"])
                opened = self._cold_open_refs(
                    node, ordered_inputs, semantic, execution,
                    refs["output_artifact"], adapter, "fresh",
                    dependency_stage_manifest_refs=[
                        item.cache_record["stage_manifest"]
                        for item in dependency_states
                    ],
                )
                validation_ref = self._validation_ref(opened.validation_receipt)
                validation_log_ref = self._validation_log_ref(adapter)
                journal.validated(index, validation_ref)
                self._crash("validated", node["node_id"])
                journal.commit(index)
                self._crash("committed", node["node_id"])
                record = self._cache_record(
                    node, semantic, execution, refs,
                    opened.stage_manifest_ref, validation_ref,
                    validation_log_ref,
                    adapter.validator_version,
                )
                self.workspace.publish_cache_record(record)
                return NodeState(node, record, opened.lease)
            except InjectedCrash:
                raise
            except BaseException as error:
                active = journal.state()["active"]
                if active is not None:
                    journal.fail(index, type(error).__name__)
                raise

    def _recover_attempt(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], execution: dict[str, Any],
        semantic_ref: dict[str, Any], execution_ref: dict[str, Any],
        adapter: registry_mod.StageAdapter,
        dependency_states: list[NodeState],
    ) -> NodeState | None:
        stage_root = self.workspace.stage_root(self.run_id, node["node_id"])
        with journal_mod.StageAttemptJournal(
            stage_root, self.manifest["content_sha256"], node["node_id"],
            self.workspace.staging,
        ) as journal:
            state = journal.state()
            candidates = list(reversed(state["committed"]))
            if state["active"] is not None:
                active = state["active"]
                if active["semantic_key_sha256"] != semantic["identity_sha256"]:
                    journal.fail(active["attempt_index"], "semantic_key_changed",
                                 indeterminate=True)
                else:
                    recovered = self._recover_active(
                        journal, active, node, ordered_inputs, semantic, execution,
                        semantic_ref, execution_ref, adapter, dependency_states,
                    )
                    if recovered is not None:
                        return recovered
            for attempt in candidates:
                record = attempt["record"]
                if record["semantic_key_sha256"] != semantic["identity_sha256"]:
                    continue
                return self._record_from_journal(
                    node, ordered_inputs, semantic, record, adapter,
                    dependency_states,
                )
        return None

    def _recover_active(
        self, journal: journal_mod.StageAttemptJournal, active: dict[str, Any],
        node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], execution: dict[str, Any],
        semantic_ref: dict[str, Any], execution_ref: dict[str, Any],
        adapter: registry_mod.StageAdapter,
        dependency_states: list[NodeState],
    ) -> NodeState | None:
        index = active["attempt_index"]
        phase = active["phase"]
        record = active["record"]
        if phase in ("intent", "running"):
            directory = journal.attempt_directory(index)
            candidate = self._read_candidate_files(directory, node, adapter)
            if candidate is None:
                journal.fail(index, "candidate_outputs_absent_or_partial",
                             indeterminate=True)
                return None
            refs = self._publish_candidate_files(
                node, ordered_inputs, index, directory, candidate,
                semantic_ref, execution_ref,
            )
            if phase == "intent":
                journal.mark_running(index)
            journal.outputs_published(
                index, output_artifact=refs["output_artifact"],
                stage_result=refs["stage_result"],
                profile_receipt=refs["profile_receipt"],
            )
        else:
            refs = self._refs_from_record(record)
        stage = self._read_stage_result(refs["stage_result"])
        recovered_semantic = protocol.decode_semantic_key(
            self.workspace.read_blob(stage["semantic_key"], "recovered semantic key"),
        )
        protocol.require(recovered_semantic == semantic,
                         "recovered semantic key differs")
        recovered_execution = self._read_execution(stage["execution_key"], semantic)
        opened = self._cold_open_refs(
            node, ordered_inputs, semantic, recovered_execution,
            refs["output_artifact"], adapter, "cold",
            dependency_stage_manifest_refs=[
                item.cache_record["stage_manifest"] for item in dependency_states
            ],
        )
        validation_ref = self._validation_ref(opened.validation_receipt)
        validation_log_ref = self._validation_log_ref(adapter)
        if phase in ("intent", "running", "outputs_published"):
            journal.validated(index, validation_ref)
        if phase != "committed":
            journal.commit(index)
        record_value = self._cache_record(
            node, semantic, recovered_execution, refs,
            opened.stage_manifest_ref, validation_ref, validation_log_ref,
            adapter.validator_version,
        )
        self.workspace.publish_cache_record(record_value)
        return NodeState(node, record_value, opened.lease)

    def _record_from_journal(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], journal_record: dict[str, Any],
        adapter: registry_mod.StageAdapter,
        dependency_states: list[NodeState],
    ) -> NodeState:
        refs = self._refs_from_record(journal_record)
        stage = self._read_stage_result(refs["stage_result"])
        execution = self._read_execution(stage["execution_key"], semantic)
        opened = self._cold_open_refs(
            node, ordered_inputs, semantic, execution,
            refs["output_artifact"], adapter, "cold",
            dependency_stage_manifest_refs=[
                item.cache_record["stage_manifest"] for item in dependency_states
            ],
        )
        validation_ref = self._validation_ref(opened.validation_receipt)
        validation_log_ref = self._validation_log_ref(adapter)
        record = self._cache_record(
            node, semantic, execution, refs, opened.stage_manifest_ref,
            validation_ref, validation_log_ref,
            adapter.validator_version,
        )
        self.workspace.publish_cache_record(record)
        return NodeState(node, record, opened.lease)

    def _find_cached(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], execution: dict[str, Any],
        adapter: registry_mod.StageAdapter,
    ) -> NodeState | None:
        records = list(self.workspace.cache_records(semantic["identity_sha256"]))
        records.sort(
            key=lambda item: (
                item["execution_key_sha256"] != execution["identity_sha256"],
                -item["validator_version"], item["content_sha256"],
            ),
        )
        for record in records:
            try:
                return self._revalidate_cache(
                    node, ordered_inputs, semantic, record, adapter,
                )
            except (OSError, protocol.PipelineError,
                    proof_protocol.ProofProtocolError):
                continue
        return None

    def _revalidate_cache(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], record: dict[str, Any],
        adapter: registry_mod.StageAdapter, *, validation_mode: str = "cold",
    ) -> NodeState:
        cached_semantic = self._read_semantic(record)
        protocol.require(cached_semantic == semantic,
                         "cached semantic key differs")
        execution = self._read_execution(record["execution_key"], semantic)
        opened = self._cold_open_record(
            node, ordered_inputs, semantic, record, validation_mode,
            adapter=adapter,
        )
        validation_ref = self._validation_ref(opened.validation_receipt)
        validation_log_ref = self._validation_log_ref(adapter)
        refreshed = protocol.seal({
            **{key: value for key, value in record.items()
               if key not in ("stage_manifest", "validation_receipt",
                              "validator_log",
                              "validator_version", "content_sha256")},
            "stage_manifest": opened.stage_manifest_ref,
            "validation_receipt": validation_ref,
            "validator_log": validation_log_ref,
            "validator_version": adapter.validator_version,
        })
        store_mod.validate_cache_record(refreshed)
        self.workspace.publish_cache_record(refreshed)
        return NodeState(node, refreshed, opened.lease)

    def _selected_record(
        self, node: dict[str, Any], semantic: dict[str, Any],
    ) -> dict[str, Any] | None:
        selected = self.workspace.maybe_run_ref(self.run_id, node["node_id"])
        if selected is None:
            return None
        if selected["semantic_key_sha256"] != semantic["identity_sha256"]:
            return None
        return self.workspace.cache_record_by_identity(
            selected["semantic_key_sha256"], selected["cache_record_sha256"],
        )

    def _open_selected(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], selected: dict[str, Any],
    ) -> NodeState:
        return self._revalidate_cache(
            node, ordered_inputs, semantic, selected,
            self.registry.get(node["adapter"]),
        )

    def _ordered_inputs(
        self, node: dict[str, Any], dependencies: list[NodeState],
    ) -> list[dict[str, Any]]:
        result = list(node["external_inputs"])
        for dependency_spec, state in zip(node["dependencies"], dependencies,
                                          strict=True):
            result.append({
                "role": dependency_spec["role"],
                "ordinal": dependency_spec["ordinal"],
                "blob": state.cache_record["output_artifact"],
            })
        roles = [(item["role"], item["ordinal"]) for item in result]
        protocol.require(len(roles) == len(set(roles)),
                         "pipeline input roles differ")
        return result

    def _require_tokens(self, node: dict[str, Any]) -> None:
        protocol.require(node["cpu_tokens"] <= self.cpu_tokens,
                         f"pipeline node {node['node_id']} exceeds CPU tokens")
        protocol.require(node["rss_tokens"] <= self.rss_tokens,
                         f"pipeline node {node['node_id']} exceeds RSS tokens")

    def _preflight_adapters(self, node_ids: set[str]) -> None:
        for node_id in sorted(node_ids, key=self.order.__getitem__):
            node = self.nodes[node_id]
            adapter = self.registry.get(node["adapter"])
            registry_mod.validate_stage_description(adapter.describe(node), node)

    def _priority(self, node_id: str) -> tuple[int, str]:
        level = self.nodes[node_id]["semantic_options"].get("tree_level", 0)
        protocol.require(type(level) is int and level >= 0,
                         "pipeline tree level differs")
        return -level, node_id

    def _allowed_nodes(self, through: str | None) -> set[str]:
        if through is None:
            return set(self.nodes)
        if through in self.nodes:
            allowed: set[str] = set()

            def include(node_id: str) -> None:
                if node_id in allowed:
                    return
                for dependency in dependency_ids(self.nodes[node_id]):
                    include(dependency)
                allowed.add(node_id)

            include(through)
            return allowed
        matching = [node for node in self.manifest["nodes"]
                    if node["semantic_options"].get("pipeline_stage") == through]
        protocol.require(bool(matching), "pipeline --through target differs")
        cutoff = max(self.order[node["node_id"]] for node in matching)
        return {node["node_id"] for node in self.manifest["nodes"][:cutoff + 1]}

    def _selected_goal(self, allowed: set[str]) -> str | None:
        goal = self.manifest["goal"]
        if goal in allowed:
            return goal
        if not allowed:
            return None
        return max(allowed, key=lambda node_id: self.order[node_id])

    def _promote_node(
        self, node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
        semantic: dict[str, Any], adapter: registry_mod.StageAdapter,
        record_sha256: str,
    ) -> NodeState:
        candidate = self.workspace.cache_record_by_identity(
            semantic["identity_sha256"], record_sha256,
        )
        protocol.require(candidate["node_id"] == node["node_id"],
                         "pipeline promotion candidate differs")
        opened = self._revalidate_cache(
            node, ordered_inputs, semantic, candidate, adapter,
            validation_mode="cold",
        )
        self.workspace.publish_run_ref(
            self.run_id, node["node_id"], opened.cache_record,
        )
        return opened

    def _crash(self, phase: str, node_id: str) -> None:
        if self.crash_hook is not None:
            self.crash_hook(phase, node_id)


def explain_run_difference(
    workspace: store_mod.Workspace, left_run: str, right_run: str,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Return the first direct-key difference and its invalidated descendants."""
    changed: list[str] = []
    for node in manifest["nodes"]:
        left = workspace.maybe_run_ref(left_run, node["node_id"])
        right = workspace.maybe_run_ref(right_run, node["node_id"])
        if left is None or right is None or (
            left["semantic_key_sha256"] != right["semantic_key_sha256"]
        ):
            changed.append(node["node_id"])
    first = changed[0] if changed else None
    first_field = None
    left_value = None
    right_value = None
    if first is not None:
        left_ref = workspace.maybe_run_ref(left_run, first)
        right_ref = workspace.maybe_run_ref(right_run, first)
        if left_ref is None or right_ref is None:
            first_field = "selected_candidate"
            left_value = left_ref
            right_value = right_ref
        else:
            left_record = workspace.cache_record_by_identity(
                left_ref["semantic_key_sha256"], left_ref["cache_record_sha256"],
            )
            right_record = workspace.cache_record_by_identity(
                right_ref["semantic_key_sha256"], right_ref["cache_record_sha256"],
            )
            left_semantic = protocol.decode_semantic_key(
                workspace.read_blob(left_record["semantic_key"], "left semantic key"),
            )
            right_semantic = protocol.decode_semantic_key(
                workspace.read_blob(right_record["semantic_key"], "right semantic key"),
            )
            fields = (
                "stage_kind", "stage_schema_version", "campaign_namespace_sha256",
                "local_task_identity_sha256", *protocol.KEY_AUTHORITY_FIELDS,
                "semantic_options_identity_sha256", "ordered_inputs",
            )
            for field in fields:
                if left_semantic[field] != right_semantic[field]:
                    first_field = field
                    left_value = left_semantic[field]
                    right_value = right_semantic[field]
                    break
    return {
        "left_run": left_run,
        "right_run": right_run,
        "first_difference": first,
        "invalidated_nodes": changed,
        "invalidated_count": len(changed),
        "first_field": first_field,
        "left_value": left_value,
        "right_value": right_value,
    }
