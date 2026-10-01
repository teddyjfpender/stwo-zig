#!/usr/bin/env python3
"""Fetch named Starknet OS PIEs and their sizing metadata from Lord of the Pies.

Set STWO_PIE_API_KEY or STWO_PIE_API_KEY_FILE in the environment. The key is
never written to receipts or forwarded to the redirected object-storage host.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile


DEFAULT_BASE = "https://15-237-92-219.sslip.io"
NAME = re.compile(r"^(\d+)_(\d+)$")


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, new_url):
        old = urllib.parse.urlsplit(request.full_url)
        new = urllib.parse.urlsplit(new_url)
        if new.scheme != "https":
            raise ValueError("PIE download redirected to a non-HTTPS URL")
        # urllib has inserted the API host into the request by this point.
        # Carrying that Host header to a presigned S3 URL invalidates its
        # signature, even when Authorization is correctly stripped.
        forwarded = {key: value for key, value in request.header_items()
                     if key.lower() != "host"}
        if old.netloc != new.netloc:
            forwarded = {key: value for key, value in forwarded.items()
                         if key.lower() != "authorization"}
        return urllib.request.Request(new_url, headers=forwarded)


def open_api(opener, base: str, path: str, key: str):
    url = base.rstrip("/") + path
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}"})
    try:
        return opener.open(request, timeout=120)
    except urllib.error.HTTPError as error:
        if error.code == 401:
            raise RuntimeError("PIE API rejected STWO_PIE_API_KEY") from error
        raise


def fetch_meta(opener, base: str, name: str, key: str) -> dict:
    with open_api(opener, base, f"/v1/pies/{name}/meta", key) as response:
        meta = json.load(response)
    if not isinstance(meta, dict) or not isinstance(meta.get("os_steps"), int):
        raise ValueError(f"invalid PIE metadata for {name}")
    return meta


def select_catalog(opener, base: str, key: str, targets: list[int], max_pages: int) -> list[str]:
    entries = []
    after = None
    for _ in range(max_pages):
        query = {"status": "ready", "limit": "1000"}
        if after is not None:
            query["after"] = str(after)
        with open_api(opener, base, "/v1/pies?" + urllib.parse.urlencode(query), key) as response:
            page = json.load(response)
        if not isinstance(page, dict) or not isinstance(page.get("pies"), list):
            raise ValueError("invalid PIE catalogue page")
        entries.extend(item for item in page["pies"]
                       if isinstance(item, dict) and isinstance(item.get("os_steps"), int)
                       and isinstance(item.get("pie"), str) and NAME.fullmatch(item["pie"]))
        after = page.get("next_after")
        if after is None:
            break
    else:
        raise RuntimeError("PIE catalogue exceeded --max-pages; increase it for an unbiased cohort")
    if len(entries) < len(targets):
        raise ValueError("fewer ready PIEs than requested step targets")
    selected = []
    used = set()
    for target in targets:
        item = min((item for item in entries if item["pie"] not in used),
                   key=lambda item: abs(item["os_steps"] - target))
        selected.append(item["pie"])
        used.add(item["pie"])
        print(f"target {target} steps -> {item['pie']} ({item['os_steps']} steps)", flush=True)
    return selected


def select_contiguous(opener, base: str, key: str, first: int, last: int) -> list[str]:
    names = []
    next_block = first
    while next_block <= last:
        query = urllib.parse.urlencode({"from": next_block, "to": last})
        with open_api(opener, base, "/v1/pies?" + query, key) as response:
            ranges = json.load(response)
        if not isinstance(ranges, list) or not ranges:
            raise ValueError(f"PIE catalogue has a gap after block {next_block - 1}")
        for item in ranges:
            if not isinstance(item, dict) or item.get("status") != "ready":
                raise ValueError(f"PIE covering block {next_block} is not ready")
            name = item.get("pie")
            match = NAME.fullmatch(name) if isinstance(name, str) else None
            if match is None or not (int(match.group(1)) <= next_block <= int(match.group(2))):
                raise ValueError(f"PIE catalogue is not contiguous at block {next_block}")
            names.append(name)
            next_block = int(match.group(2)) + 1
            if next_block > last:
                break
    return names


def fetch_zip(opener, base: str, name: str, key: str, output: Path) -> dict:
    partial = output.with_suffix(".zip.partial")
    digest = hashlib.sha256()
    try:
        with open_api(opener, base, f"/v1/pies/{name}", key) as response, partial.open("wb") as sink:
            while block := response.read(1 << 20):
                digest.update(block)
                sink.write(block)
        with zipfile.ZipFile(partial) as archive:
            members = set(archive.namelist())
            required = {"version.json", "metadata.json", "memory.bin",
                        "additional_data.json", "execution_resources.json"}
            if not required.issubset(members):
                raise ValueError(f"PIE {name} lacks required zip members")
        partial.replace(output)
    finally:
        partial.unlink(missing_ok=True)
    return {"path": str(output), "bytes": output.stat().st_size, "sha256": digest.hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("names", nargs="*", help="exact PIE names, in block order")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--meta-only", action="store_true")
    parser.add_argument("--require-contiguous", action="store_true")
    parser.add_argument("--catalog-target-steps", type=int, nargs="+", default=[],
                        help="add the ready PIE nearest each step target")
    parser.add_argument("--from-block", type=int)
    parser.add_argument("--to-block", type=int)
    parser.add_argument("--max-pages", type=int, default=100)
    args = parser.parse_args()
    key = os.environ.get("STWO_PIE_API_KEY")
    if not key and (key_file := os.environ.get("STWO_PIE_API_KEY_FILE")):
        key = Path(key_file).read_text().strip()
    if not key:
        parser.error("STWO_PIE_API_KEY or STWO_PIE_API_KEY_FILE must be set")
    if urllib.parse.urlsplit(args.base).scheme != "https":
        parser.error("--base must use HTTPS")
    if (args.from_block is None) != (args.to_block is None):
        parser.error("--from-block and --to-block must be used together")
    if args.from_block is not None and (args.from_block > args.to_block or args.names or args.catalog_target_steps):
        parser.error("a block interval must be valid and cannot be combined with other selectors")
    if not args.names and not args.catalog_target_steps and args.from_block is None:
        parser.error("provide PIE names, --catalog-target-steps, or a block interval")
    if args.max_pages < 1 or any(target < 1 for target in args.catalog_target_steps):
        parser.error("page count and step targets must be positive")
    opener = urllib.request.build_opener(SafeRedirect())
    if args.from_block is not None:
        args.names = select_contiguous(opener, args.base, key, args.from_block, args.to_block)
        args.require_contiguous = True
    if args.catalog_target_steps:
        args.names.extend(select_catalog(opener, args.base, key,
                                         args.catalog_target_steps, args.max_pages))
    args.names = list(dict.fromkeys(args.names))
    ranges = []
    for name in args.names:
        match = NAME.fullmatch(name)
        if match is None or int(match.group(1)) > int(match.group(2)):
            parser.error(f"invalid PIE name: {name}")
        ranges.append((int(match.group(1)), int(match.group(2))))
    if args.require_contiguous:
        for previous, current in zip(ranges, ranges[1:]):
            if previous[1] + 1 != current[0]:
                parser.error("PIE ranges are not contiguous")
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, (first, last) in zip(args.names, ranges):
        meta = fetch_meta(opener, args.base, name, key)
        row = {"pie": name, "first": first, "last": last, "meta": meta}
        if not args.meta_only:
            row["zip"] = fetch_zip(opener, args.base, name, key, args.out / f"{name}.zip")
        rows.append(row)
        receipt = {"schema": "stwo-starknet-pie-download-v1", "base": args.base,
                   "contiguous": args.require_contiguous, "rows": rows}
        (args.out / "manifest.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(f"{name}: {meta['os_steps']} steps, {meta.get('bytes', 'unknown')} bytes", flush=True)


if __name__ == "__main__":
    main()
