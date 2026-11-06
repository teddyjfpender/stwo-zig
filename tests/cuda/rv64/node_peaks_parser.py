#!/usr/bin/env python3
"""Compact RV64 allocator diagnostic parser. Never certifies physical node peak.

Each input is an independently ordered producer log. GPU_RESIDENT_BLOCK ends
one request; do not concatenate independent stdout/stderr streams out of order.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

PREFIXES = ("GPU_NODE_ALLOC_STAGE", "GPU_NODE_ALLOC_MODEL", "GPU_NODE_ALLOC_FIXED_LINK", "GPU_RESIDENT_BLOCK")
FAIL_MARKERS = ("GPU_NODE_ALLOC_COVERAGE_GAP", "GPU_NODE_ALLOC_CLOSE_FAILED")
REQUIRED_STAGES = ("main_witness", "main_commit", "inter_witness", "inter_commit", "composition", "pcs_metadata", "pcs_source_lde", "pcs_source_trees", "pcs_samples", "pcs_deep", "pcs_fri", "pcs_pow", "pcs_openings", "pcs_readback")
SETUP_STAGES = {"fixed_ingress", "fixed_commit", "fixed_adoption"}
MODEL_STAGES = {"main_witness", "main_commit", "inter_witness", "inter_commit", "composition", "pcs_metadata"}
COUNTER_FIELDS = (
    "baseline_active_bytes", "baseline_requested_bytes", "baseline_rounded_bytes", "baseline_large_bytes", "baseline_small_bytes",
    "active_requested_peak_bytes", "requested_reservation_peak_bytes", "rounded_reservation_peak_bytes", "rounded_large_peak_bytes", "rounded_small_peak_bytes",
    "pending_requested_peak_bytes", "pending_rounded_peak_bytes", "rounded_including_pending_upper_peak_bytes",
    "node_requested_peak_bytes", "node_rounded_peak_bytes", "node_including_pending_upper_peak_bytes",
    "end_requested_bytes", "end_rounded_bytes", "end_pending_rounded_bytes", "global_rounded_peak_bytes", "global_rounded_end_bytes",
    "shared_unattributed_rounded_end_bytes", "shared_unattributed_baseline_bytes", "shared_unattributed_rounded_peak_bytes",
    "global_pending_fence_bytes", "carve_bytes", "mapped_bytes", "mapped_free_bytes", "small_slab_bytes",
    "configured_stack_limit_bytes", "actual_stack_limit_bytes", "shared_long_rounded_end_bytes", "idle_cache_rounded_end_bytes", "init_stack_device_delta_bytes",
    "device_free_snapshot_bytes", "device_total_snapshot_bytes", "device_memory_rc", "coverage_gaps", "stage_coverage_gaps",
)
STAGE_COLUMNS = ("ordinal", "key", "domain", "stage", "device", "context", "cuda_lane", "epoch", "line") + COUNTER_FIELDS
MODEL_COLUMNS = ("ordinal", "key", "domain", "stage", "stage_additional_large", "stage_additional_small", "retained_after_large", "retained_after_small", "successor_large", "successor_small", "line")
COMPARISON_COLUMNS = ("ordinal", "key", "stage", "device", "context", "cuda_lane", "epoch", "baseline_plus_model_total", "observed_node_concurrent_rounded_peak", "node_only_residual", "observed_node_plus_shared_increment_upper", "residual_after_shared_increment_upper", "baseline_plus_model_large", "observed_large_peak", "baseline_plus_model_small", "observed_small_peak", "shared_increment_upper", "retirement_possible")
KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
KV_RE = re.compile(r"([A-Za-z_][A-Za-z_0-9]*)=([^\s]+)")
LIMIT = 1_000_000


def fields(text):
    result = {}
    for key, value in KV_RE.findall(text):
        if key in result:
            raise ValueError("duplicate field: " + key)
        if key.endswith("key") or key in {"key", "stage"}:
            result[key] = value
        elif re.fullmatch(r"-?\d+", value):
            result[key] = int(value)
        else:
            result[key] = value
    return result


def require_int(row, name):
    if not isinstance(row.get(name), int) or row[name] < 0:
        raise ValueError("missing/nonnegative integer field: " + name)


def validate_stage(row):
    for name in ("version", "ordinal", "domain", "device", "context", "cuda_lane", "epoch") + COUNTER_FIELDS:
        require_int(row, name)
    if row["version"] != 1 or not KEY_RE.fullmatch(str(row.get("key", ""))):
        raise ValueError("bad observer version or key")
    if not isinstance(row.get("stage"), str):
        raise ValueError("missing stage")
    if (row.get("diagnostic_host_join"), row.get("timing_qualified"), row.get("physical_node_peak_qualified")) != (1, 0, 0):
        raise ValueError("unexpected diagnostic/qualification flags")
    # Each recorded total is concurrent; its independent component peaks need
    # not occur at the same instant and must never be added for a measured peak.
    if row["rounded_reservation_peak_bytes"] < row["baseline_rounded_bytes"]:
        raise ValueError("stage total below its starting baseline")
    if row["rounded_including_pending_upper_peak_bytes"] < row["rounded_reservation_peak_bytes"]:
        raise ValueError("pending-inclusive bound below allocator peak")
    if row["requested_reservation_peak_bytes"] > row["rounded_reservation_peak_bytes"]:
        raise ValueError("requested reservations exceed rounded peak")
    if row["active_requested_peak_bytes"] > row["requested_reservation_peak_bytes"]:
        raise ValueError("active requests exceed full reservations")
    if row["coverage_gaps"] or row["stage_coverage_gaps"]:
        raise ValueError("nonzero observer coverage gap counter")


def parse_log(path, index, raw_ref):
    digest = hashlib.sha256()
    bucket = {"stages": [], "models": [], "fixed_links": []}
    requests, errors, gaps = [], [], []
    for number, raw in enumerate(Path(path).open("rb"), 1):
        digest.update(raw)
        text = raw.decode("utf-8", errors="replace").strip()
        for marker in FAIL_MARKERS:
            if marker in text:
                gaps.append({"line": number, "marker": marker, "text": text[:400]})
        matches = [(text.find(prefix), prefix) for prefix in PREFIXES if prefix in text]
        if not matches:
            continue
        if len(matches) != 1:
            errors.append({"line": number, "error": "interleaved or multiple observer/completion records"})
            continue
        offset, prefix = matches[0]
        try:
            row = fields(text[offset + len(prefix):])
            row["line"] = number
            if prefix == "GPU_NODE_ALLOC_STAGE":
                validate_stage(row)
                bucket["stages"].append(row)
            elif prefix == "GPU_NODE_ALLOC_MODEL":
                for name in MODEL_COLUMNS:
                    if name not in {"key", "stage", "line"}:
                        require_int(row, name)
                if row.get("model_changed") != 0 or not KEY_RE.fullmatch(str(row.get("key", ""))):
                    raise ValueError("unexpected model mutation flag/key")
                bucket["models"].append(row)
            elif prefix == "GPU_NODE_ALLOC_FIXED_LINK":
                for name in ("ordinal", "fixed_coefficient_alias_requested_bytes"):
                    require_int(row, name)
                if any(not KEY_RE.fullmatch(str(row.get(k, ""))) for k in ("provisional_key", "final_key")):
                    raise ValueError("malformed fixed authority link")
                if (row.get("shared_setup"), row.get("physical_alias_charge")) != (1, 0):
                    raise ValueError("unexpected physical alias charge")
                bucket["fixed_links"].append(row)
            else:
                for name in ("block", "trial", "iteration", "request_wall_ns"):
                    require_int(row, name)
                requests.append({**bucket, "completion": row, "completed": True, "stream_index": index})
                bucket = {"stages": [], "models": [], "fixed_links": []}
        except ValueError as error:
            errors.append({"line": number, "error": str(error), "text": text[:250]})
    if any(bucket.values()):
        requests.append({**bucket, "completion": None, "completed": False, "stream_index": index})
    return requests, {"stream_index": index, "path": str(path), "raw_ref": raw_ref or str(path), "sha256": digest.hexdigest(), "errors": errors, "gap_markers": gaps}


def summarize_request(request, expected, target_bytes):
    stages = request["stages"]
    final_rows = [r for r in stages if r["domain"] == 1 and r["stage"] not in SETUP_STAGES]
    final_keys = {}
    for row in final_rows:
        final_keys.setdefault(row["ordinal"], set()).add(row["key"])
    ordinals = set(final_keys)
    expected_set = set(range(expected))
    missing_ordinals, unexpected_ordinals = sorted(expected_set - ordinals), sorted(ordinals - expected_set)
    duplicate_keys = {str(o): sorted(keys) for o, keys in final_keys.items() if len(keys) != 1}
    models = {}
    model_conflicts = []
    for row in request["models"]:
        ident = (row["ordinal"], row["key"], row["domain"], row["stage"])
        if ident in models and any(models[ident][k] != row[k] for k in MODEL_COLUMNS if k != "line"):
            model_conflicts.append({"ordinal": row["ordinal"], "stage": row["stage"], "key": row["key"]})
        models[ident] = row
    nodes, comparisons, missing_models, missing_stages = [], [], [], {}
    for ordinal in sorted(ordinals):
        rows = [r for r in final_rows if r["ordinal"] == ordinal]
        names = {r["stage"] for r in rows}
        missing = sorted(set(REQUIRED_STAGES) - names)
        if missing:
            missing_stages[str(ordinal)] = missing
        concurrent = max(r["rounded_reservation_peak_bytes"] for r in rows)
        pending_upper = max(r["rounded_including_pending_upper_peak_bytes"] for r in rows)
        nodes.append({
            "ordinal": ordinal, "keys": sorted(final_keys[ordinal]),
            "devices": sorted({r["device"] for r in rows}), "contexts": sorted({r["context"] for r in rows}),
            "cuda_lanes": sorted({r["cuda_lane"] for r in rows}), "epochs": sorted({r["epoch"] for r in rows}),
            "concurrent_rounded_peak_bytes": concurrent,
            "active_requested_peak_bytes": max(r["active_requested_peak_bytes"] for r in rows),
            "requested_reservation_peak_bytes": max(r["requested_reservation_peak_bytes"] for r in rows),
            "rounded_including_pending_upper_peak_bytes": pending_upper,
            "pending_rounded_peak_bytes": max(r["pending_rounded_peak_bytes"] for r in rows),
            "shared_baseline_min_bytes": min(r["shared_unattributed_baseline_bytes"] for r in rows),
            "shared_baseline_max_bytes": max(r["shared_unattributed_baseline_bytes"] for r in rows),
            "shared_global_peak_max_bytes": max(r["shared_unattributed_rounded_peak_bytes"] for r in rows),
            "stage_rows": len(rows), "missing_required_stages": missing,
            "allocator_peak_within_target": concurrent <= target_bytes,
            "pending_upper_within_target": pending_upper <= target_bytes,
            "physical_node_peak_qualified": False,
        })
        for row in rows:
            if row["stage"] not in MODEL_STAGES:
                continue
            model = models.get((ordinal, row["key"], 1, row["stage"]))
            if not model:
                missing_models.append({"ordinal": ordinal, "key": row["key"], "stage": row["stage"]})
                continue
            planned = row["baseline_rounded_bytes"] + model["stage_additional_large"] + model["stage_additional_small"]
            observed = row["rounded_reservation_peak_bytes"]
            shared_increment = max(0, row["shared_unattributed_rounded_peak_bytes"] - row["shared_unattributed_baseline_bytes"])
            # Sum of independent peaks is explicitly an UPPER comparator, never
            # reported as a measured simultaneous peak or model overestimate.
            with_shared_upper = observed + shared_increment
            end_large_unknown = row["end_rounded_bytes"] < row["baseline_rounded_bytes"]
            comparisons.append([ordinal, row["key"], row["stage"], row["device"], row["context"], row["cuda_lane"], row["epoch"],
                planned, observed, planned-observed, with_shared_upper, planned-with_shared_upper,
                row["baseline_large_bytes"]+model["stage_additional_large"], row["rounded_large_peak_bytes"],
                row["baseline_small_bytes"]+model["stage_additional_small"], row["rounded_small_peak_bytes"], shared_increment,
                end_large_unknown or row["pending_rounded_peak_bytes"] > 0])
    complete = request["completed"] and not any((missing_ordinals, unexpected_ordinals, duplicate_keys, missing_stages, missing_models, model_conflicts))
    return {
        "stream_index": request["stream_index"], "completion": request["completion"], "completed_request": request["completed"],
        "allocator_table_complete_before_global_gap_check": complete,
        "expected_domain": 1, "expected_ordinals": [0, expected-1],
        "observed_recursion_nodes": len(ordinals), "missing_ordinals": missing_ordinals, "unexpected_ordinals": unexpected_ordinals,
        "multiple_final_keys_for_ordinal": duplicate_keys, "missing_stages": missing_stages, "missing_models": missing_models, "model_conflicts": model_conflicts,
        "nodes": nodes,
        "stage_rows": [[r.get(c) for c in STAGE_COLUMNS] for r in stages],
        "model_rows": [[r.get(c) for c in MODEL_COLUMNS] for r in request["models"]],
        "fixed_links": request["fixed_links"], "comparison_rows": comparisons,
        "comparison_status": "COMPARISON_ONLY_SHARED_COLD_AND_RETIREMENT_NOT_RESOLVED",
        "device_memory_snapshot_errors": sum(r["device_memory_rc"] != 0 for r in stages),
        "timing_qualified": False, "physical_node_peak_qualified": False,
    }


def gb(value):
    return f"{value/1e9:.3f}"


def markdown(summary):
    out = ["# RV64 node allocator diagnostic", "", f"Status: **{summary['status']}**. Exact scope: host allocator reservation lifetime with pending-fence bounds. GPU-completion and whole-process per-node physical peaks remain unqualified; diagnostic walls are not latency results.", "", "All GB below are decimal. Each node total is the maximum concurrent rounded total; independent large/small maxima are never summed as measured peaks."]
    for i, request in enumerate(summary["requests"]):
        c = request["completion"] or {}
        label = f"request {i}: block {c.get('block','incomplete')}, trial {c.get('trial','?')}, iteration {c.get('iteration','?')}"
        out += ["", "## " + label, "", f"Observed domain=1 ordinals: {request['observed_recursion_nodes']}/{summary['expected_nodes']}. Completed request: {request['completed_request']}. Table coverage: {request['allocator_table_complete_before_global_gap_check']} before global gap rejection.", "", "| Node | Device/context | Epoch | Active GB | Reservation requested GB | Concurrent rounded GB | Pending rounded max GB | Rounded + pending upper GB | Shared baseline range GB |", "|---:|---|---|---:|---:|---:|---:|---:|---|"]
        by_ordinal = {n["ordinal"]:n for n in request["nodes"]}
        for ordinal in range(summary["expected_nodes"]):
            n = by_ordinal.get(ordinal)
            if not n:
                out.append(f"| {ordinal} | MISSING | | | | | | | |")
            else:
                out.append(f"| {ordinal} | {','.join(map(str,n['devices']))}/{','.join(map(str,n['contexts']))} | {','.join(map(str,n['epochs']))} | {gb(n['active_requested_peak_bytes'])} | {gb(n['requested_reservation_peak_bytes'])} | {gb(n['concurrent_rounded_peak_bytes'])} | {gb(n['pending_rounded_peak_bytes'])} | {gb(n['rounded_including_pending_upper_peak_bytes'])} | {gb(n['shared_baseline_min_bytes'])}–{gb(n['shared_baseline_max_bytes'])} |")
        out += ["", "### Stage/lane and planner comparison", "", "Planned envelope = starting node rounded baseline + existing model stage-additional large/small charges. Node-only residual excludes shared cold setup; the second residual uses a conservative shared-increment upper comparator. Retirement, cache reuse and changing stable baselines can make either naive subtraction misleading. These columns do not establish model overestimation or authorize a discount.", "", "| Node | Stage | GPU/context/lane | Epoch | Rounded GB | Planned envelope GB | Node-only residual GB | Residual after shared increment upper GB | Pending upper GB |", "|---:|---|---|---:|---:|---:|---:|---:|---:|"]
        comp = {(r[0],r[1],r[2],r[3],r[4],r[5],r[6]):r for r in request["comparison_rows"]}
        for values in request["stage_rows"]:
            row = dict(zip(STAGE_COLUMNS, values))
            if row["domain"] != 1:
                continue
            key=(row["ordinal"],row["key"],row["stage"],row["device"],row["context"],row["cuda_lane"],row["epoch"])
            model=comp.get(key)
            planned, residual, with_shared = (gb(model[7]),gb(model[9]),gb(model[11])) if model else ("—","—","—")
            out.append(f"| {row['ordinal']} | {row['stage']} | {row['device']}/{row['context']}/{row['cuda_lane']} | {row['epoch']} | {gb(row['rounded_reservation_peak_bytes'])} | {planned} | {residual} | {with_shared} | {gb(row['rounded_including_pending_upper_peak_bytes'])} |")
        shared_rows=[dict(zip(STAGE_COLUMNS,v)) for v in request["stage_rows"] if dict(zip(STAGE_COLUMNS,v))["domain"]==1]
        if shared_rows:
            out += ["", "Backing boundary snapshots (global/shared, not node physical peaks):", "", "| GPU | Carve GB | Mapped GB | Mapped-free range GB | Shared-long GB | Idle cache GB | Driver used snapshot GB | Actual stack limit bytes |", "|---:|---:|---:|---:|---:|---:|---:|---:|"]
            for device in sorted({r["device"] for r in shared_rows}):
                rows=[r for r in shared_rows if r["device"]==device]
                maximum=lambda name:max(r[name] for r in rows)
                used=max(r["device_total_snapshot_bytes"]-r["device_free_snapshot_bytes"] for r in rows)
                out.append(f"| {device} | {gb(maximum('carve_bytes'))} | {gb(maximum('mapped_bytes'))} | {gb(maximum('mapped_free_bytes'))} | {gb(maximum('shared_long_rounded_end_bytes'))} | {gb(maximum('idle_cache_rounded_end_bytes'))} | {gb(used)} | {maximum('actual_stack_limit_bytes')} |")
        if request["fixed_links"]:
            out += ["", "FIXED provisional→final links (requested alias use, shared physical allocation):", "", "| Node | Provisional key | Final key | Alias requested GB |", "|---:|---|---|---:|"]
            for link in request["fixed_links"]:
                out.append(f"| {link['ordinal']} | {link['provisional_key'][:12]} | {link['final_key'][:12]} | {gb(link['fixed_coefficient_alias_requested_bytes'])} |")
        problems={k:request[k] for k in ("missing_ordinals","unexpected_ordinals","multiple_final_keys_for_ordinal","missing_stages","missing_models","model_conflicts") if request[k]}
        if problems:
            out += ["", "Coverage failures: `"+json.dumps(problems,separators=(",",":"))+"`."]
    out += ["", "## Raw references", "", "| Stream | Raw reference | SHA256 | Gap markers | Parse errors |", "|---:|---|---|---:|---:|"]
    for source in summary["sources"]:
        out.append(f"| {source['stream_index']} | {source['raw_ref']} | {source['sha256']} | {len(source['gap_markers'])} | {len(source['errors'])} |")
    out += ["", "Any coverage-gap/close-failure marker invalidates complete qualification, even outside a completed request or outside counters. Fused Blake shadow/check modes must be excluded by the runner. This parser does not independently verify proofs, receiver acceptance, environment scoping or allocations bypassing instrumented APIs.", ""]
    return "\n".join(out)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("logs",nargs="+",help="ordered producer log(s), each with its own completed-request markers")
    p.add_argument("--block",type=int,default=24628607)
    p.add_argument("--expected-nodes",type=int,default=19)
    p.add_argument("--target-bytes",type=int,default=11_000_000_000)
    p.add_argument("--raw-ref",action="append",default=[],help="raw pod reference for corresponding log; repeat in input order")
    p.add_argument("--json",required=True,dest="json_path")
    p.add_argument("--markdown",required=True,dest="md_path")
    args=p.parse_args(argv)
    if args.expected_nodes<=0 or args.target_bytes<=0:
        p.error("expected nodes and target bytes must be positive")
    requests,sources=[],[]
    for index,path in enumerate(args.logs):
        parsed,source=parse_log(path,index,args.raw_ref[index] if index<len(args.raw_ref) else None)
        requests.extend(r for r in parsed if not r["completed"] or r["completion"]["block"]==args.block)
        sources.append(source)
    results=[summarize_request(r,args.expected_nodes,args.target_bytes) for r in requests]
    any_gap=any(s["gap_markers"] or s["errors"] for s in sources)
    complete=bool(results) and all(r["allocator_table_complete_before_global_gap_check"] for r in results)
    snapshot_errors=sum(r["device_memory_snapshot_errors"] for r in results)
    status="REJECTED_COVERAGE_OR_PARSE" if any_gap else "INCOMPLETE_NODES_OR_STAGES" if not complete else "ALLOCATOR_TABLE_COMPLETE_BACKING_SNAPSHOT_ERROR" if snapshot_errors else "ALLOCATOR_TABLE_COMPLETE"
    summary={"schema":"rv64-node-allocator-diagnostic/v1","status":status,"block":args.block,"expected_nodes":args.expected_nodes,"target_bytes":args.target_bytes,"target_is_measured_physical_pass":False,"stage_columns":STAGE_COLUMNS,"model_columns":MODEL_COLUMNS,"comparison_columns":COMPARISON_COLUMNS,"required_stages":REQUIRED_STAGES,"sources":sources,"requests":results,"complete_allocator_coverage":complete and not any_gap,"receiver_acceptance":"NOT_CHECKED_BY_PARSER","timing_qualified":False,"physical_node_peak_qualified":False,"model_discount_authorized":False}
    encoded=json.dumps(summary,separators=(",",":"),ensure_ascii=False)+"\n"
    md=markdown(summary)
    size=len(encoded.encode())+len(md.encode())
    if size>=LIMIT:
        p.error(f"combined summary exceeds1MB ({size}bytes); select a bounded checkpoint log without dropping failure markers")
    Path(args.json_path).write_text(encoded)
    Path(args.md_path).write_text(md)
    print(json.dumps({"status":status,"requests":len(results),"node_counts":[r["observed_recursion_nodes"] for r in results],"gap_markers":sum(len(s["gap_markers"]) for s in sources),"parse_errors":sum(len(s["errors"]) for s in sources),"summary_bytes":size,"json":args.json_path,"markdown":args.md_path}))
    return 0 if status=="ALLOCATOR_TABLE_COMPLETE" else 2

if __name__=="__main__":
    sys.exit(main())
