"""vuln-export — copy reviewed repositories to a staging directory.

Reads ``repo_report.json`` (produced by the review-queue stage) and copies
each repository's local clone to a destination directory, ready for deeper
static analysis or manual review.

Usage::

    vuln-export --dest /path/to/staging
    vuln-export --report repo_report.json --dest /path/to/staging --min-score 7
    vuln-export --report repo_report.json --dest /path/to/staging --min-findings 5

Each repository is copied as ``<dest>/<repository_name>`` (or
``<dest>/<repository_name>_<id>`` when names collide).  Repositories whose
local clone no longer exists on disk are reported and skipped.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-export",
        description="Copy pipeline-reviewed repositories to a staging directory.",
    )
    parser.add_argument(
        "--report",
        default="repo_report.json",
        help="Path to repo_report.json (default: repo_report.json)",
    )
    parser.add_argument(
        "--dest",
        required=True,
        help="Destination directory to copy repositories into.",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=0,
        help="Only export repos whose top_score is at least this value (default: 0 = all).",
    )
    parser.add_argument(
        "--min-findings",
        type=int,
        default=0,
        help="Only export repos with at least this many findings (default: 0 = all).",
    )
    return parser


def main() -> None:
    args = _build_parser().parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"ERROR: report file not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    with report_path.open(encoding="utf-8") as fh:
        repos: list[dict] = json.load(fh)

    dest = Path(args.dest)
    dest.mkdir(parents=True, exist_ok=True)

    # Apply filters.
    if args.min_score > 0:
        repos = [r for r in repos if r.get("top_score", 0) >= args.min_score]
    if args.min_findings > 0:
        repos = [r for r in repos if r.get("finding_count", 0) >= args.min_findings]

    if not repos:
        print("No repositories match the specified filters.")
        sys.exit(0)

    print(f"Exporting {len(repos)} repositories to {dest}")

    exported = 0
    skipped = 0
    seen_names: set[str] = set()

    for repo in repos:
        src = Path(repo.get("local_path", ""))
        name = repo.get("repository_name", repo.get("repository_id", "unknown"))
        repo_id = repo.get("repository_id", "")

        if not src.is_dir():
            print(f"  SKIP  {name} — local clone not found at {src}")
            skipped += 1
            continue

        # Ensure unique destination name.
        dest_name = name
        if dest_name in seen_names:
            dest_name = f"{name}_{repo_id}"
        seen_names.add(dest_name)

        dest_path = dest / dest_name
        if dest_path.exists():
            print(f"  SKIP  {name} — destination already exists at {dest_path}")
            skipped += 1
            continue

        shutil.copytree(src, dest_path)
        score = repo.get("top_score", 0)
        count = repo.get("finding_count", 0)
        vtypes = ", ".join(repo.get("vulnerability_types", []))
        print(f"  OK    {name}  (score={score}, findings={count}, types={vtypes})")
        exported += 1

    print(f"\nDone. {exported} exported, {skipped} skipped.")
    if skipped and exported == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
