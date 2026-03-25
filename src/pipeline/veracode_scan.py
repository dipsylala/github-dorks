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
import datetime
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
    parser.add_argument(
        "--repo-report",
        default="repo_report.json",
        help="Path to repo_report.json for enriching summary with repo metadata (default: repo_report.json).",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Skip projects that have already been packaged and scanned. "
            "Packaging is skipped when the package directory already contains "
            "zip files.  Scanning is skipped when a filtered result JSON already "
            "exists for that package."
        ),
    )
    return parser


def _run(cmd: list[str], cwd: Path, log_file: Path | None = None) -> bool:
    """Run *cmd* in *cwd*, streaming output to console (and optionally *log_file*).

    When *log_file* is given the file is created (or overwritten) in the same
    directory and receives a timestamped header plus every line of output
    (stdout and stderr merged) while still printing to the console.
    Returns True on success.
    """
    cmd_str = ' '.join(cmd)
    print(f"    $ {cmd_str}")

    log_fh = None
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_fh = log_file.open("w", encoding="utf-8")
        started = datetime.datetime.now().isoformat(timespec="seconds")
        log_fh.write(f"# Started : {started}\n")
        log_fh.write(f"# Command : {cmd_str}\n")
        log_fh.write(f"# Cwd     : {cwd}\n")
        log_fh.write("#" + "-" * 78 + "\n")
        log_fh.flush()

    returncode: int | None = None
    try:
        with subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        ) as proc:
            assert proc.stdout is not None
            for line in proc.stdout:
                print(line, end="")  # already has newline
                if log_fh is not None:
                    log_fh.write(line)
            proc.wait()
            returncode = proc.returncode
    except FileNotFoundError as exc:
        msg = f"# ERROR   : executable not found — {exc}\n"
        print(f"    ERROR: {exc}")
        if log_fh is not None:
            log_fh.write(msg)
        returncode = -1
    finally:
        if log_fh is not None:
            finished = datetime.datetime.now().isoformat(timespec="seconds")
            log_fh.write("#" + "-" * 78 + "\n")
            log_fh.write(f"# Finished: {finished}\n")
            log_fh.write(f"# Exit    : {returncode}\n")
            log_fh.close()

    if returncode != 0:
        print(f"    ERROR: command exited with code {returncode}")
        if log_file is not None:
            print(f"    Log written to: {log_file}")
        return False
    if log_file is not None:
        print(f"    Log written to: {log_file}")
    return True


def _existing_packages(project_dir: Path, package_subdir: str) -> list[Path]:
    """Return already-produced package files without running the packager."""
    pkg_dir = project_dir / package_subdir
    if not pkg_dir.is_dir():
        return []
    return [f for f in pkg_dir.iterdir() if f.is_file() and f.suffix not in (".json", ".log")]


def _package(project_dir: Path, package_subdir: str) -> list[Path]:
    """Run ``veracode package`` and return the list of generated files."""
    pkg_dir = project_dir / package_subdir
    ok = _run(
        ["veracode", "package", "-s", ".", "-a", "-o", str(pkg_dir)],
        cwd=project_dir,
    )
    if not ok or not pkg_dir.is_dir():
        return []
    return [f for f in pkg_dir.iterdir() if f.is_file() and f.suffix not in (".json", ".log")]


def _load_repo_lookup(repo_report_path: Path) -> dict[str, dict]:
    """Return a dict keyed by repository_name from repo_report.json, or empty if unavailable."""
    if not repo_report_path.exists():
        return {}
    try:
        repos: list[dict] = json.loads(repo_report_path.read_text(encoding="utf-8"))
        return {r["repository_name"]: r for r in repos if r.get("repository_name")}
    except Exception:
        return {}


def _build_summary(
    source: Path,
    package_subdir: str,
    repo_lookup: dict[str, dict] | None = None,
) -> dict[str, dict]:
    """Glob all filtered result JSONs under source and return high-severity findings."""
    summary: dict[str, dict] = {}
    pattern = f"*/{package_subdir}/filtered_veracode-auto*.json"
    for result_file in sorted(source.glob(pattern)):
        project_name = result_file.parts[len(source.parts)]
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        high = [f for f in data.get("findings", []) if f.get("severity", 0) >= 4]
        if high:
            if project_name not in summary:
                repo_meta = (repo_lookup or {}).get(project_name, {})
                summary[project_name] = {
                    "repository_name": repo_meta.get("repository_name", project_name),
                    "repository_url":  repo_meta.get("repository_url"),
                    "local_path":      repo_meta.get("local_path"),
                    "findings": [],
                }
            summary[project_name]["findings"].extend(high)
    return summary


def _write_summary(
    source: Path,
    package_subdir: str,
    repo_lookup: dict[str, dict] | None = None,
) -> None:
    """Build and write high_severity_summary.json, printing a breakdown."""
    summary = _build_summary(source, package_subdir, repo_lookup=repo_lookup)
    summary_file = source / "high_severity_summary.json"
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    total_high = sum(len(v["findings"]) for v in summary.values())
    print(f"High-severity summary written to {summary_file}")
    print(f"{total_high} finding(s) across {len(summary)} project(s)")
    for project_name, entry in summary.items():
        findings = entry["findings"]
        print(f"  [{project_name}] {len(findings)} finding(s)")
        if entry.get("repository_url"):
            print(f"    URL: {entry['repository_url']}")
        for fnd in findings:
            loc = fnd.get("files", {}).get("source_file", {})
            loc_str = f"{loc.get('file', '?')}:{loc.get('line', '?')}"
            print(f"    [CWE-{fnd.get('cwe_id','?')}] sev={fnd.get('severity')} "
                  f"{fnd.get('issue_type','?')} -- {loc_str}")


def _scan(package_file: Path, results_file: Path) -> bool:
    """Run ``veracode static scan`` for *package_file*.

    Scan output is streamed to the console and also written to a log file
    named ``<package_stem>.log`` inside the same ``.veracode-packaging``
    directory as the package itself.
    """
    filtered_results_file = results_file.parent / f"filtered_{results_file.name}"
    log_file = package_file.parent / f"{package_file.stem}.log"
    return _run(
        [
            "veracode", "static", "scan",
            str(package_file),
            "--results-file", str(results_file),
            "--filtered-json-output-file", str(filtered_results_file),
        ],
        cwd=package_file.parent,
        log_file=log_file,
    )


def main() -> None:
    args = _build_parser().parse_args()

    source = Path(args.source)
    if not source.is_dir():
        print(f"ERROR: source directory not found: {source}", file=sys.stderr)
        sys.exit(1)

    if args.summary_only:
        repo_lookup = _load_repo_lookup(Path(args.repo_report))
        _write_summary(source, args.package_dir, repo_lookup=repo_lookup)
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

        if args.resume:
            packages = _existing_packages(project, args.package_dir)
            if packages:
                print(f"  Resuming -- found {len(packages)} existing package(s), skipping packaging")
            else:
                print(f"  Packaging...")
                packages = _package(project, args.package_dir)
        else:
            print(f"  Packaging...")
            packages = _package(project, args.package_dir)

        if not packages:
            print(f"  SKIP -- no packages produced")
            continue

        if not args.resume:
            print(f"  Produced {len(packages)} package(s)")

        for pkg in sorted(packages):
            results_file = pkg.with_suffix(".json")
            filtered_results_file = results_file.parent / f"filtered_{results_file.name}"
            if args.resume and filtered_results_file.exists():
                print(f"  SKIP  {pkg.name} -- already scanned")
                continue
            print(f"  Scanning {pkg.name} -> {results_file.name}")
            ok = _scan(pkg, results_file)
            total_scans += 1
            if not ok:
                total_errors += 1

        print()

    print(f"Done. {total_scans} scan(s) attempted, {total_errors} error(s).")

    print("\nBuilding high-severity summary...")
    repo_lookup = _load_repo_lookup(Path(args.repo_report))
    _write_summary(source, args.package_dir, repo_lookup=repo_lookup)

    if total_errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
