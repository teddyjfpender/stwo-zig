"""Export one or more DEEP queries from an accepted native worker."""

import argparse
import gzip
import hashlib
import json
import re
import struct
from pathlib import Path

from export_fri_layers import RECORD as FRI
from export_fri_layers import ashex, blake, canonical_words, export_record, raw_positions, unhex
from export_pcs_suffix import RECORD as PCS

P = 0x7fff_ffff
TRACE = re.compile(
    r"^FRI_TRACE_BEGIN ([a-f0-9]{64})\nFRI_TRACE_ALPHA ([a-f0-9]{64})\n(.*?)^FRI_TRACE_END$",
    re.MULTILINE | re.DOTALL,
)
TREE = re.compile(
    r"^FRI_TRACE_TREE ([a-f0-9]{64}) (\d+) (\d+)\nFRI_TRACE_POSITIONS(.*?)\n"
    r"FRI_TRACE_SIBLINGS ([a-f0-9]*)\n(.*?)(?=^FRI_TRACE_TREE|\Z)",
    re.MULTILINE | re.DOTALL,
)
COLUMN = re.compile(
    r"^FRI_TRACE_COLUMN (\d+) (\d+) ([a-f0-9]*)\nFRI_TRACE_VALUES ([a-f0-9]*)$",
    re.MULTILINE,
)


def field(value):
    canonical_words(value)
    return list(struct.unpack("<8I", value))


def chunks(data, width):
    if len(data) % width:
        raise ValueError("truncated chunk")
    return [data[i:i + width] for i in range(0, len(data), width)]


def project(position, log, tree_log):
    if not tree_log:
        return 0
    pair = position >> 1
    delta = tree_log - log
    pair = pair << delta if delta > 0 else pair >> -delta
    return pair * 2 + (position & 1)


def narrow_opening(rows, witness, depth, required, root):
    def tag(name, *parts):
        return blake(name.ljust(64, b"\x00"), *parts)
    if list(rows) != sorted(rows) or not rows or max(rows) >= 1 << depth:
        raise ValueError("malformed full rows")
    known = {i: tag(b"leaf", value) for i, value in rows.items()}
    wanted = list(required)
    projected_witness = []
    remaining = iter(witness)
    for _ in range(depth):
        parents = {}
        for index, value in list(known.items()):
            parent = index >> 1
            if parent in parents:
                continue
            sibling = known.get(index ^ 1)
            if sibling is None:
                sibling = next(remaining, None)
                if sibling is None:
                    raise ValueError("missing Merkle sibling")
                known[index ^ 1] = sibling
            left, right = (sibling, value) if index & 1 else (value, sibling)
            parents[parent] = tag(b"node", left, right)
        for index in wanted:
            if index ^ 1 not in wanted:
                projected_witness.append(known[index ^ 1])
        known = parents
        wanted = sorted(set(index >> 1 for index in wanted))
    if known != {0: root} or next(remaining, None) is not None:
        raise ValueError("native Merkle root mismatch")
    return projected_witness


def narrow_first_fri(layer, root, queries, chosen, domain_log):
    step = min(4, domain_log - 1)
    leaf_log = 2 if step > 1 else 0
    leaves_per_group = 1 << (step - leaf_log)
    group_indices = sorted({position >> step for position in queries})
    indices = [
        group * leaves_per_group + offset
        for group in group_indices
        for offset in range(leaves_per_group)
    ]
    row_bytes = 32 << leaf_log
    values = chunks(unhex(layer["rows"]), row_bytes)
    if len(indices) != len(values):
        raise ValueError("unexpected first FRI leaf count")
    rows = dict(zip(indices, values))
    positions = sorted({query >> leaf_log for query in chosen})
    witness = narrow_opening(
        rows, [unhex(sibling) for sibling in layer["siblings"]], domain_log - leaf_log, positions, root
    )
    return {
        "root": ashex(root),
        "depth": domain_log - leaf_log,
        "rowBytes": row_bytes,
        "positions": positions,
        "rows": ashex(b"".join(rows[index] for index in positions)),
        "witness": [ashex(sibling) for sibling in witness],
    }


def export(log_text, worker, count):
    pcs_records = {record[5]: record for record in PCS.findall(log_text)}
    fri_records = {record[0]: record for record in FRI.findall(log_text)}
    trace_records = {record[0]: record for record in TRACE.findall(log_text)}
    keys = set(pcs_records) & set(fri_records) & set(trace_records)
    if not keys:
        raise ValueError("no complete native trace captures")
    matching = [
        key for key in keys
        if all(unhex(root) in worker for root in pcs_records[key][3].split())
    ]
    if len(matching) != 1:
        raise ValueError("expected one trace and PCS record matching the worker's FRI roots")
    pre_pow = matching[0]
    prefix, sample_count, samples, fri_roots, last, _, log = pcs_records[pre_pow]
    _, alpha, lines = trace_records[pre_pow]
    _, _, nonce, *_ = fri_records[pre_pow]
    log = int(log)
    sample_count = int(sample_count)
    nonce = int(nonce)
    if len(samples) != sample_count * 64:
        raise ValueError("sample length mismatch")
    digest = blake(unhex(prefix), unhex(samples))
    expected_alpha = [limb % P for limb in struct.unpack("<8I", blake(digest, bytes(5)))]
    if field(unhex(alpha)) != expected_alpha:
        raise ValueError("captured DEEP challenge mismatch")
    queries = sorted(set(raw_positions(unhex(pre_pow), nonce, log)))
    input_pcs = {
        "worker": "native capture",
        "workerSha256": "",
        "domainLog": log,
        "prefix": ashex(unhex(prefix)),
        "samples": ashex(unhex(samples)),
        "friRoots": [ashex(unhex(root)) for root in fri_roots.split()],
        "lastCoefficient": ashex(unhex(last)),
        "prePowDigest": ashex(unhex(pre_pow)),
    }
    fri = export_record(fri_records[pre_pow], input_pcs, {"nonce": nonce})
    chosen = queries[:count]
    first_fri = narrow_first_fri(fri["layers"][0], unhex(input_pcs["friRoots"][0]), queries, chosen, log)
    point_indices = {}
    points = []
    columns = []
    trees = []
    openings = []
    observed_count = 0
    parsed_trees = TREE.findall(lines)
    if not parsed_trees or len(parsed_trees) != lines.count("FRI_TRACE_TREE "):
        raise ValueError("incomplete tree capture")
    for root, tree_log, width, raw_positions_line, siblings, column_lines in parsed_trees:
        tree_log, width = int(tree_log), int(width)
        positions = [int(x) for x in raw_positions_line.split()]
        projected = [project(query, log, tree_log) for query in queries] if width else []
        if positions != projected:
            raise ValueError("native projection mismatch")
        tree_columns = COLUMN.findall(column_lines)
        if len(tree_columns) != width:
            raise ValueError("native column count mismatch")
        value_columns = []
        for column_log, samples_in_col, point_hex, values in tree_columns:
            point_list = chunks(unhex(point_hex), 64)
            if len(point_list) != int(samples_in_col):
                raise ValueError("native sample point count mismatch")
            ids = []
            for point in point_list:
                if point not in point_indices:
                    point_indices[point] = len(points)
                    points.append({"x": field(point[:32]), "y": field(point[32:])})
                ids.append(point_indices[point])
            observed_count += len(ids)
            columns.append({"logSize": int(column_log), "samplePoints": ids})
            value_column = chunks(unhex(values), 4)
            if len(value_column) != len(positions) or any(int.from_bytes(v, "little") >= P for v in value_column):
                raise ValueError("malformed native base column")
            value_columns.append(value_column)
        trees.append({"root": "0x" + root, "logSize": tree_log, "columnCount": width})
        if not width:
            if siblings:
                raise ValueError("unexpected witness for empty tree")
            openings.append({"positions": [], "rows": "0x", "witness": []})
            continue
        rows = {}
        leaf_order = sorted(range(width), key=lambda i: (int(tree_columns[i][0]), i))
        for position, row_values in zip(positions, zip(*(value_columns[i] for i in leaf_order))):
            row = b"".join(row_values)
            if rows.setdefault(position, row) != row:
                raise ValueError("inconsistent repeated trace row")
        positions = sorted({project(query, log, tree_log) for query in chosen})
        witness = narrow_opening(
            dict(sorted(rows.items())), chunks(unhex(siblings), 32), tree_log, positions, unhex(root)
        )
        openings.append({
            "positions": positions,
            "rows": ashex(b"".join(rows[pos] for pos in positions)),
            "witness": [ashex(sibling) for sibling in witness],
        })
    if observed_count != sample_count:
        raise ValueError("captured trace/sample shape mismatch")
    return {
        "domainLog": log,
        "prefix": input_pcs["prefix"],
        "samples": input_pcs["samples"],
        "prePowDigest": input_pcs["prePowDigest"],
        "nonce": str(nonce),
        "queries": chosen,
        "answers": [field(unhex(value)) for value in fri["deepValues"][:len(chosen)]],
        "columns": columns,
        "points": points,
        "trees": trees,
        "openings": openings,
        "firstFri": first_fri,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("diagnostic", "receipt", "worker", "output"):
        parser.add_argument(field, type=Path)
    parser.add_argument("--block", required=True, type=int)
    parser.add_argument("--queries", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.queries <= 108:
        parser.error("choose one through 108 queries")
    receipt = json.loads(args.receipt.read_text())
    if not receipt["accepted"] or not receipt["completed_ethereum_block"]:
        raise ValueError("capture requires an accepted complete block")

    worker = args.worker.read_bytes()
    result = export(args.diagnostic.read_text(), worker, args.queries)
    result["blockNumber"] = args.block
    result["worker"] = args.worker.name
    result["workerSha256"] = hashlib.sha256(worker).hexdigest()
    payload = (json.dumps(result, separators=(",", ":")) + "\n").encode()
    if args.output.suffix == ".gz":
        payload = gzip.compress(payload, mtime=0)
    args.output.write_bytes(payload)


if __name__ == "__main__":
    main()
