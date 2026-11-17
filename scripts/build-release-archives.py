#!/usr/bin/env python3
"""Build the four reproducible doubleshell release archives and check them.

Each archive holds the doubleshell program, the license of doubleshell, and
the license and notice files of the dependencies and of Go, which the
program contains. Two builds of one commit give identical archive bytes.
"""

import argparse
import gzip
import hashlib
import io
import os
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
PLATFORMS = (("linux", "amd64"), ("linux", "arm64"), ("macos", "amd64"), ("macos", "arm64"))
LICENSE_NAMES = ("LICENSE", "NOTICE", "COPYING", "PATENTS", "AUTHORS")
VERSION_PATTERN = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?")


def validate_version(version):
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError(f"Version {version!r} must be a semantic version without a v prefix.")
    return version


def development_version():
    return re.search(r'var version = "([^"]+)"', (REPOSITORY / "commands.go").read_text()).group(1)


def license_files(goroot):
    """Map each archive path to a file that a copy of the program must carry."""
    files = {"LICENSE": REPOSITORY / "LICENSE", "third_party/go/LICENSE": goroot / "LICENSE"}
    for path in sorted((REPOSITORY / "third_party").rglob("*")):
        if path.is_file() and path.name.startswith(LICENSE_NAMES):
            files[path.relative_to(REPOSITORY).as_posix()] = path
    return files


def write_archive(destination, top_directory, payload, timestamp):
    """Write the same bytes whatever the source modes, owners, and times are."""
    entries = {top_directory: None}
    for name in payload:
        for parent in Path(name).parents:
            if parent != Path("."):
                entries[f"{top_directory}/{parent.as_posix()}"] = None
    entries.update({f"{top_directory}/{name}": content for name, content in payload.items()})
    with destination.open("wb") as output:
        # An empty gzip file name keeps the output path out of the header.
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=timestamp) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, content in sorted(entries.items()):
                    entry = tarfile.TarInfo(name)
                    entry.mtime = timestamp
                    entry.uid = entry.gid = 0
                    entry.uname = entry.gname = ""
                    if content is None:
                        entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                    else:
                        entry.mode = 0o755 if name.endswith("/doubleshell") else 0o644
                        entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content) if content is not None else None)


def check_archive(path, top_directory, payload, version, system, architecture):
    with tarfile.open(path, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        files = {name.removeprefix(top_directory + "/"): archive.extractfile(member).read()
                 for name, member in members.items() if member.isfile()}
    if files != payload:
        raise ValueError(f"{path.name} does not hold exactly the expected files.")
    if any(not name.startswith(top_directory) for name in members):
        raise ValueError(f"{path.name} has an entry outside {top_directory}/.")
    host = ({"Darwin": "macos", "Linux": "linux"}.get(platform.system()),
            {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine()))
    if host == (system, architecture):
        with tempfile.TemporaryDirectory(prefix="doubleshell-release-check-") as directory:
            program = Path(directory) / "doubleshell"
            program.write_bytes(payload["doubleshell"])
            program.chmod(0o755)
            printed = subprocess.run([str(program), "version"], capture_output=True, text=True)
            if printed.returncode or printed.stdout != f"doubleshell {version}\n":
                raise ValueError(f"{path.name}: `doubleshell version` printed {printed.stdout!r}, "
                                 f"expected 'doubleshell {version}'.")


def build_archives(version, output_dir):
    validate_version(version)
    output_dir.mkdir(parents=True, exist_ok=True)
    toolchain = next(line.split()[1] for line in (REPOSITORY / "go.mod").read_text().splitlines()
                     if line.startswith("toolchain "))
    env = dict(os.environ, CGO_ENABLED="0", GOTOOLCHAIN=toolchain, GOFLAGS="")
    goroot = Path(subprocess.check_output(["go", "env", "GOROOT"], cwd=REPOSITORY, env=env, text=True).strip())
    timestamp = int(os.environ["SOURCE_DATE_EPOCH"]) if "SOURCE_DATE_EPOCH" in os.environ else int(
        subprocess.check_output(["git", "log", "-1", "--format=%ct", "HEAD"], cwd=REPOSITORY, text=True).strip())
    licenses = {name: source.read_bytes() for name, source in license_files(goroot).items()}
    checksums = []
    with tempfile.TemporaryDirectory(prefix="doubleshell-release-build-") as directory:
        for system, architecture in PLATFORMS:
            top_directory = f"doubleshell-{version}-{system}-{architecture}"
            destination = output_dir / f"{top_directory}.tar.gz"
            program = Path(directory) / f"doubleshell-{system}-{architecture}"
            subprocess.run(["go", "build", "-trimpath", "-buildvcs=false",
                            "-ldflags", f"-X main.version={version}", "-o", str(program), "."],
                           cwd=REPOSITORY, check=True,
                           env=dict(env, GOOS="darwin" if system == "macos" else system, GOARCH=architecture))
            payload = dict(licenses, doubleshell=program.read_bytes())
            write_archive(destination, top_directory, payload, timestamp)
            check_archive(destination, top_directory, payload, version, system, architecture)
            checksums.append(f"{hashlib.sha256(destination.read_bytes()).hexdigest()}  {destination.name}\n")
            print(f"Built {destination.name}: {destination.stat().st_size} bytes.", flush=True)
    (output_dir / "SHA256SUMS").write_text("".join(sorted(checksums)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", help="the release version, such as 0.1.0, without a v prefix")
    parser.add_argument("--output-dir", type=Path, help="the directory that receives the archives")
    parser.add_argument("--print-development-version", action="store_true",
                        help="print the version of a build that sets no version, and exit")
    arguments = parser.parse_args()
    if arguments.print_development_version:
        print(development_version())
        return 0
    if not arguments.version or not arguments.output_dir:
        parser.error("--version and --output-dir are required")
    try:
        build_archives(arguments.version, arguments.output_dir.resolve())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Release build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
