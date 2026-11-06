"""Read-only verifier for a ZIP containing one folder with index.html.

Use only after confirming that the target platform requires this structure.
No upload, extraction, external dependency, or built-in size budget.
"""
import argparse
import hashlib
import json
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath


def sha256(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def inspect(path, max_zip=None, max_unpacked=None, dist=None):
    report = {"archive": str(path.resolve()), "errors": []}
    errors = report["errors"]
    report["zip_bytes"] = path.stat().st_size
    with path.open("rb") as stream:
        report["sha256"] = sha256(stream)
    if max_zip is not None and report["zip_bytes"] > max_zip:
        errors.append("ZIP exceeds requested byte budget")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        files = [entry for entry in entries if not entry.is_dir()]
        report["files"] = len(files)
        report["unpacked_bytes"] = sum(entry.file_size for entry in files)
        if max_unpacked is not None and report["unpacked_bytes"] > max_unpacked:
            errors.append("Unpacked content exceeds requested byte budget")
        if len(names) != len(set(names)):
            errors.append("Duplicate archive entry")
        for entry in entries:
            name = entry.filename
            parts = name.rstrip("/").split("/")
            if (not name or "\\" in name or name.startswith("/")
                    or any(p in ("", ".", "..") or ":" in p for p in parts)
                    or "\x00" in name):
                errors.append("Unsafe or ambiguous ZIP path: " + repr(name))
            if stat.S_ISLNK(entry.external_attr >> 16):
                errors.append("Symbolic link in archive: " + name)
            if entry.flag_bits & 1:
                errors.append("Encrypted entry: " + name)
        roots = sorted({name.split("/")[0] for name in names})
        report["root_entries"] = roots
        root = roots[0] if len(roots) == 1 else None
        if root is None or any("/" not in entry.filename for entry in files):
            errors.append("Expected exactly one root folder and no root-level files")
        entry_name = root + "/index.html" if root else None
        by_name = {entry.filename: entry for entry in files}
        if entry_name not in by_name or by_name[entry_name].file_size == 0:
            errors.append("Missing or empty index.html immediately inside root folder")
        # Budget/path failures stop before expanding archive entries in memory.
        if not errors:
            corrupt = archive.testzip()
            if corrupt:
                errors.append("CRC failure: " + corrupt)
        if dist is not None and not errors:
            if not dist.is_dir():
                errors.append("Build directory not found: " + str(dist))
            else:
                sources = {}
                for source in dist.rglob("*"):
                    if source.is_symlink():
                        errors.append("Build directory contains a symbolic link")
                    elif source.is_file():
                        sources[source.relative_to(dist).as_posix()] = source
                packaged = {name[len(root) + 1:]: name for name in by_name}
                missing = sorted(sources.keys() - packaged.keys())
                extra = sorted(packaged.keys() - sources.keys())
                if missing:
                    errors.append("Files absent from ZIP: " + ", ".join(missing))
                if extra:
                    errors.append("Files absent from build: " + ", ".join(extra))
                for relative in sorted(sources.keys() & packaged.keys()):
                    with sources[relative].open("rb") as src, archive.open(packaged[relative]) as dst:
                        if sha256(src) != sha256(dst):
                            errors.append("Content differs: " + relative)
                report["build_directory"] = str(dist.resolve())
    report["ok"] = not errors
    return report


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Byte budget must be positive")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--max-zip-bytes", type=positive)
    parser.add_argument("--max-unpacked-bytes", type=positive)
    parser.add_argument("--dist", type=Path)
    args = parser.parse_args()
    try:
        report = inspect(args.archive, args.max_zip_bytes, args.max_unpacked_bytes, args.dist)
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError, NotImplementedError) as exc:
        report = {"ok": False, "errors": [str(exc)]}
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
