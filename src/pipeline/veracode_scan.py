"""vuln-scan — package and statically scan repositories with Veracode CLI.

For each project directory found in the source folder:
  1. Runs ``veracode package -s . -o ./.veracode-packaging`` to produce
     language-appropriate scan packages.
  2. Runs ``veracode static scan <package> --results-file <package_stem>.json``
     for every file produced by the packaging step.  Results are written
     alongside the package file in ``.veracode-packaging/``.

Usage::

    vuln-scan --source /path/to/staging
    vuln-scan --source /path/to/staging --package-dir .veracode-packaging
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


_PACKAGE_DIR_NAME = ".veracode-packaging"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-scan",
        description="Package and statically scan repositories with the Veracode CLI.",
    )
    parser.add_argument(
        "--source",
        required=True,
        help="Directory containing the project folders to scan (e.g. the output of vuln-export).",
    )
    parser.add_argument(
        "--package-dir",
        default=_PACKAGE_DIR_NAME,
        help=(
            f"Subdirectory name (relative to each project) where veracode package "
            f"writes its output (default: {_PACKAGE_DIR_NAME})."
        ),
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Skip packaging and scanning; just regenerate the high-severity summary from existing result files.",
    )
    return parser


def _run(cmd: list[str], cwd: Path) -> bool:
    """Run *cmd* in *cwd*, streaming output.  Returns True on success."""
    print(f"    $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        print(f"    ERROR: command exited with code {result.returncode}")
        return False
    return True


def _package(project_dir: Path, package_subdir: str) -> list[Path]:
    """Run ``veracode package`` and return the list of generated files."""
    pkg_dir = project_dir / package_subdir
    ok = _run(
        ["veracode", "package", "-s", ".", "-a", "-o", str(pkg_dir)],
        cwd=project_dir,
    )
    if not ok or not pkg_dir.is_dir():
        return []
    return [f for f in pkg_dir.iterdir() if f.is_file() and f.suffix != ".json"]


def _build_summary(source: Path, package_subdir: str) -> dict[str, list[dict]]:
    """Glob all filtered result JSONs under source and return high-severity findings."""
    summary: dict[str, list[dict]] = {}
    pattern = f"*/{package_subdir}/filtered_veracode-auto*.json"
    for result_file in sorted(source.glob(pattern)):
        project_name = result_file.parts[len(source.parts)]
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        high = [f for f in data.get("findings", []) if f.get("severity", 0) >= 4]
        if high:
            summary.setdefault(project_name, []).extend(high)
    return summary


def _write_summary(source: Path, package_subdir: str) -> None:
    """Build and write high_severity_summary.json, printing a breakdown."""
    summary = _build_summary(source, package_subdir)
    summary_file = source / "high_severity_summary.json"
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    total_high = sum(len(v) for v in summary.values())
    print(f"High-severity summary written to {summary_file}")
    print(f"{total_high} finding(s) across {len(summary)} project(s)")
    for project_name, findings in summary.items():
        print(f"  [{project_name}] {len(findings)} finding(s)")
        for fnd in findings:
            loc = fnd.get("files", {}).get("source_file", {})
            loc_str = f"{loc.get('file', '?')}:{loc.get('line', '?')}"
            print(f"    [CWE-{fnd.get('cwe_id','?')}] sev={fnd.get('severity')} "
                  f"{fnd.get('issue_type','?')} -- {loc_str}")


def _scan(package_file: Path, results_file: Path) -> bool:
    """Run ``veracode static scan`` for *package_file*."""
    filtered_results_file = results_file.parent / f"filtered_{results_file.name}"
    return _run(
        [
            "veracode", "static", "scan",
            str(package_file),
            "--results-file", str(results_file),
            "--filtered-json-output-file", str(filtered_results_file),
        ],
        cwd=package_file.parent,
    )


def main() -> None:
    args = _build_parser().parse_args()

    source = Path(args.source)
    if not source.is_dir():
        print(f"ERROR: source directory not found: {source}", file=sys.stderr)
        sys.exit(1)

    if args.summary_only:
        _write_summary(source, args.package_dir)
        return

    projects = sorted(p for p in source.iterdir() if p.is_dir())
    if not projects:
        print(f"No project directories found in {source}")
        sys.exit(0)

    print(f"Found {len(projects)} project(s) in {source}\n")

    total_scans = 0
    total_errors = 0

    for project in projects:
        print(f"[{project.name}]")

        print(f"  Packaging...")
        packages = _package(project, args.package_dir)

        if not packages:
            print(f"  SKIP -- no packages produced")
            continue

        print(f"  Produced {len(packages)} package(s)")

        for pkg in sorted(packages):
            results_file = pkg.with_suffix(".json")
            print(f"  Scanning {pkg.name} -> {results_file.name}")
            ok = _scan(pkg, results_file)
            total_scans += 1
            if not ok:
                total_errors += 1

        print()

    print(f"Done. {total_scans} scan(s) attempted, {total_errors} error(s).")

    print("\nBuilding high-severity summary...")
    _write_summary(source, args.package_dir)

    if total_errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
