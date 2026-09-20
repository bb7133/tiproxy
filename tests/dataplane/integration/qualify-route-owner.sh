#!/usr/bin/env bash
# Copyright 2026 PingCAP, Inc.
# SPDX-License-Identifier: Apache-2.0

# Formal CP-ROUTE physical-matrix recorder. It is intentionally fail-closed:
# one immutable clean tree, one Rust binary, no cell reuse/rerun, first failure
# stops the matrix, and each run must publish its row-specific receipt plus the
# global route-tap and ledger evidence before it can count.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/../../.." && pwd)
workspace_root=$(cd "$repo_root/../.." && pwd)
artifact_root=${DATAPLANE_T4_ARTIFACT_ROOT:-$repo_root/artifacts/tiproxy/223/t4-qualification}
rows_csv=M1,M2,M3,M4,M5,M6,M7,M8,M9
# Optional ROW-COLUMN selection (for example M4-X) that only narrows which
# physical cells of the fixed plan are recorded; every selected cell still runs
# the full T4 route-owner path with its conservation evidence. Empty = all.
cells_csv=${DATAPLANE_T4_CELLS:-}
port_offset=${DATAPLANE_PORT_OFFSET:-12000}
print_plan=false

while (($# > 0)); do
	case "$1" in
		--artifact-root)
			artifact_root=${2:?missing value for --artifact-root}
			shift 2
			;;
		--rows)
			rows_csv=${2:?missing value for --rows}
			shift 2
			;;
		--cells)
			cells_csv=${2:?missing value for --cells}
			shift 2
			;;
		--port-offset)
			port_offset=${2:?missing value for --port-offset}
			shift 2
			;;
		--print-plan)
			print_plan=true
			shift
			;;
		*)
			echo "unknown argument: $1" >&2
			exit 2
			;;
	esac
done

IFS=, read -r -a requested_rows <<<"$rows_csv"
rows=()
seen_rows=""
for row in "${requested_rows[@]}"; do
	if [[ ! $row =~ ^M[1-9]$ ]]; then
		echo "invalid row $row (want M1..M9)" >&2
		exit 2
	fi
	if [[ " $seen_rows " == *" $row "* ]]; then
		echo "duplicate row $row" >&2
		exit 2
	fi
	seen_rows="$seen_rows $row"
	rows+=("$row")
done
if ((${#rows[@]} == 0)); then
	echo "at least one row is required" >&2
	exit 2
fi
# Validate the optional cell selection against the fixed plan: every token
# must be ROW-COLUMN with the row requested and the column defined for that
# row (sentinel exists only on M1/M7/M9). Unknown cells fail closed.
selected_cells=""
if [[ -n $cells_csv ]]; then
	IFS=, read -r -a requested_cells <<<"$cells_csv"
	for cell in "${requested_cells[@]}"; do
		cell_row=${cell%%-*}
		cell_column=${cell#*-}
		if [[ -z $cell_row || -z $cell_column || $cell != "$cell_row-$cell_column" ]] ||
			[[ " $seen_rows " != *" $cell_row "* ]]; then
			echo "unknown T4 cell selection: $cell (expected ROW-COLUMN within --rows)" >&2
			exit 2
		fi
		case "$cell_column" in
			P | T | X | C-zlib | C-zstd) ;;
			sentinel)
				case "$cell_row" in
					M1 | M7 | M9) ;;
					*)
						echo "unknown T4 cell selection: $cell (sentinel exists only on M1/M7/M9)" >&2
						exit 2
						;;
				esac
				;;
			*)
				echo "unknown T4 cell selection: $cell (unknown logical column)" >&2
				exit 2
				;;
		esac
		if [[ " $selected_cells " != *" $cell "* ]]; then
			selected_cells="$selected_cells $cell"
		fi
	done
fi
cell_selected() {
	[[ -z $selected_cells || " $selected_cells " == *" $1-$2 "* ]]
}
if [[ $print_plan == true ]]; then
	plan_cell() {
		if cell_selected "$1" "$2"; then
			printf '%s\t%s\t%s\n' "$1" "$2" "$3"
		fi
	}
	for row in "${rows[@]}"; do
		plan_cell "$row" P plain
		plan_cell "$row" T tls
		plan_cell "$row" X proxy
		plan_cell "$row" C-zlib compress-zlib
		plan_cell "$row" C-zstd compress-zstd
		case "$row" in
			M1 | M7 | M9) plan_cell "$row" sentinel tls-proxy-zstd ;;
		esac
	done
	exit 0
fi

git_bin=$(command -v git)
if [[ $(uname -s) == Darwin && -x /opt/homebrew/bin/git ]]; then
	git_bin=/opt/homebrew/bin/git
fi
sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

if [[ -n $($git_bin -C "$repo_root" status --porcelain) ]]; then
	echo "formal qualification requires a clean immutable worktree" >&2
	exit 2
fi
commit=$($git_bin -C "$repo_root" rev-parse HEAD)
tree=$($git_bin -C "$repo_root" rev-parse 'HEAD^{tree}')
parent=$($git_bin -C "$repo_root" rev-parse 'HEAD^')
design="$workspace_root/notes/tiproxy-223-design-final.md"
if [[ ! -f $design ]]; then
	echo "frozen design not found: $design" >&2
	exit 2
fi
design_sha=$(sha256_file "$design")
if [[ $design_sha != eddcc7fb9ece5e82d45ae3b953567197664d4c6633ef3861a5d6a8f677f06f2e ]]; then
	echo "frozen design hash changed: $design_sha" >&2
	exit 2
fi

platform=$(uname -sm)
if [[ " $seen_rows " == *" M5 "* && $(uname -s) != Linux ]]; then
	echo "M5 qualification requires Linux real TiDB metrics; platform is $platform" >&2
	exit 2
fi
if [[ ! $port_offset =~ ^[0-9]+$ ]] || ((port_offset < 1000 || port_offset > 19900)); then
	echo "port offset must be an integer from 1000 through 19900" >&2
	exit 2
fi

mkdir -p "$artifact_root"
artifact_root=$(cd "$artifact_root" && pwd)
root_manifest="$artifact_root/matrix.json"
if [[ -e $root_manifest || -d $artifact_root/cells ]]; then
	echo "artifact root already contains a qualification attempt; never rerun cells in place: $artifact_root" >&2
	exit 2
fi
mkdir -p "$artifact_root/cells"

# A clean qualification runner has neither implementation binary. The Rust
# dataplane is the route owner under test, while the Go TiProxy remains the
# residual control bridge used by the real-topology harness and is also hashed
# into every immutable receipt.
make -C "$repo_root" rust-build cmd_tiproxy
rust_binary=${TIPROXY_RS_BIN:-$repo_root/rust/target/debug/tiproxy-rs}
go_binary="$repo_root/bin/tiproxy"
for binary in "$rust_binary" "$go_binary"; do
	if [[ ! -x $binary ]]; then
		echo "qualification binary missing or not executable: $binary" >&2
		exit 1
	fi
done
rust_sha=$(sha256_file "$rust_binary")
go_sha=$(sha256_file "$go_binary")

python3 - "$root_manifest" "$commit" "$tree" "$parent" "$design_sha" "$platform" "$rust_sha" "$go_sha" "$rows_csv" "$selected_cells" <<'PYROOT'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "schema": 1,
    "status": "running",
    "commit": sys.argv[2],
    "tree": sys.argv[3],
    "parent": sys.argv[4],
    "design_sha256": sys.argv[5],
    "platform": sys.argv[6],
    "rust_binary_sha256": sys.argv[7],
    "go_binary_sha256": sys.argv[8],
    "requested_rows": sys.argv[9].split(","),
    # Empty means the full fixed plan; a non-empty list marks a narrowed
    # recording that must never be presented as a complete matrix.
    "requested_cells": sys.argv[10].split(),
    "completed_physical_cells": [],
}, sort_keys=True, indent=2) + "\n")
PYROOT

record_cell() {
	local row=$1 column=$2 variant=$3 cell_root=$4
	local run_dir
	run_dir=$(find "$cell_root" -mindepth 1 -maxdepth 1 -type d -name 'tiproxy-dp-rust-*' -print)
	if [[ -z $run_dir || $(wc -l <<<"$run_dir" | tr -d ' ') != 1 ]]; then
		echo "cell $row/$column/$variant did not produce exactly one run directory" >&2
		return 1
	fi
	python3 - "$root_manifest" "$run_dir" "$row" "$column" "$variant" "$commit" "$tree" "$parent" "$design_sha" "$platform" "$rust_sha" "$go_sha" <<'PYCELL'
import hashlib
import json
import pathlib
import sys

(root_manifest, run_text, row, column, variant, commit, tree, parent,
 design_sha, platform, rust_sha, go_sha) = sys.argv[1:]
run = pathlib.Path(run_text)
required = {
    "row_receipt": run / f"t4-row-{row}.json",
    "route_audit": run / "t4-route-audit-final.json",
    "route_audit_ka": run / "t4-route-audit-ka-final.json",
    "ledger_before": run / "t4-ledger-before.json",
    "ledger_after": run / "t4-ledger-after.json",
    "process_lineage": run / "t4-process-lineage.json",
}
missing = [name for name, path in required.items() if not path.is_file()]
if missing:
    raise SystemExit(f"cell {row}/{column}/{variant} missing evidence: {missing}")
receipt = json.loads(required["row_receipt"].read_text())
if (
    receipt.get("schema") != 1
    or receipt.get("row") != row
    or receipt.get("result") != "pass"
    or receipt.get("variant") != variant
    or receipt.get("platform") != platform
    or not isinstance(receipt.get("evidence"), dict)
):
    raise SystemExit(f"invalid row receipt: {receipt}")
lineage = json.loads(required["process_lineage"].read_text())
if lineage.get("row") != row or lineage.get("variant") != variant or not lineage.get("events"):
    raise SystemExit(f"invalid process lineage: {lineage}")
ledger_before = json.loads(required["ledger_before"].read_text())
ledger_after = json.loads(required["ledger_after"].read_text())
source_generations = {
    "before": ledger_before.get("source_generations"),
    "after": ledger_after.get("source_generations"),
}
if not all(isinstance(value, dict) for value in source_generations.values()):
    raise SystemExit(f"cell {row}/{column}/{variant} has no source-generation evidence")

for name in ("route_audit", "route_audit_ka"):
    audit = json.loads(required[name].read_text()).get("route_audit")
    if not isinstance(audit, dict):
        raise SystemExit(f"cell {row}/{column}/{variant} has no {name} payload")
    events = audit.get("metering_events")
    if not isinstance(events, list):
        raise SystemExit(f"cell {row}/{column}/{variant} has no ordered metering events in {name}")
    fatal = [event for event in events if event.get("kind") == "protocol_error" and event.get("fatal")]
    if audit.get("fatal_protocol_errors") != len(fatal) or fatal:
        raise SystemExit(f"cell {row}/{column}/{variant} observed a spontaneous fatal in {name}: {fatal}")

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

config_hashes = {}
for name in ("tiproxy.toml", "tidb.toml", "tidb-b.toml", "variant.env"):
    path = run / name
    if path.is_file():
        config_hashes[name] = digest(path)
manifest = {
    "schema": 1,
    "result": "pass",
    "row": row,
    "logical_column": column,
    "physical_variant": variant,
    "commit": commit,
    "tree": tree,
    "parent": parent,
    "design_sha256": design_sha,
    "platform": platform,
    "rust_binary_sha256": rust_sha,
    "go_binary_sha256": go_sha,
    "config_sha256": config_hashes,
    "source_generations": source_generations,
    "process_lineage_events": len(lineage["events"]),
    "evidence_sha256": {name: digest(path) for name, path in required.items()},
    "run_directory": str(run),
}
(run / "t4-cell-manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
root_path = pathlib.Path(root_manifest)
root = json.loads(root_path.read_text())
root["completed_physical_cells"].append({
    "row": row, "logical_column": column, "physical_variant": variant,
    "manifest": str(run / "t4-cell-manifest.json"),
})
root_path.write_text(json.dumps(root, sort_keys=True, indent=2) + "\n")
PYCELL
}

run_cell() {
	local row=$1 column=$2 variant=$3
	if ! cell_selected "$row" "$column"; then
		return 0
	fi
	local cell="$row-$column-$variant"
	local cell_root="$artifact_root/cells/$cell"
	if [[ -e $cell_root ]]; then
		echo "cell artifact already exists; refusing a same-tree rerun: $cell_root" >&2
		exit 2
	fi
	mkdir -p "$cell_root"
	echo "T4 physical cell start: $cell commit=$commit tree=$tree platform=$platform"
	if ! DATAPLANE_T4_QUALIFICATION=1 DATAPLANE_T4_ROW="$row" \
		TIPROXY_RS_BIN="$rust_binary" DATAPLANE_ARTIFACT_ROOT="$cell_root" \
		"$script_dir/run.sh" --mode rust --variant "$variant" --port-offset "$port_offset"; then
		echo "T4 first failure: $cell (artifact preserved; no automatic rerun)" >&2
		exit 1
	fi
	if ! record_cell "$row" "$column" "$variant" "$cell_root"; then
		echo "T4 evidence closure failed: $cell (artifact preserved; no automatic rerun)" >&2
		exit 1
	fi
}

for row in "${rows[@]}"; do
	run_cell "$row" P plain
	run_cell "$row" T tls
	run_cell "$row" X proxy
	run_cell "$row" C-zlib compress-zlib
	run_cell "$row" C-zstd compress-zstd
	case "$row" in
		M1 | M7 | M9) run_cell "$row" sentinel tls-proxy-zstd ;;
	esac
done

python3 - "$root_manifest" "$selected_cells" <<'PYDONE'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
manifest = json.loads(path.read_text())
# A narrowed recording is closed as "pass-selected-cells" so its manifest can
# never be read as a complete 48-cell qualification.
manifest["status"] = "pass" if not sys.argv[2].split() else "pass-selected-cells"
path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
PYDONE
if [[ -n $selected_cells ]]; then
	echo "PASS: selected T4 cells recorded at $artifact_root (not a complete matrix):$selected_cells"
else
	echo "PASS: immutable T4 qualification matrix recorded at $artifact_root"
fi
