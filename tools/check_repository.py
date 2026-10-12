

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
LOCAL_ROOTS = {"out", "bin", "build", ".vs", ".idea"}
ARTIFACT_SUFFIXES = {
    ".exe", ".dll", ".sys", ".cat", ".obj", ".pch", ".pdb", ".ilk",
    ".res", ".idb", ".ipch", ".suo", ".user", ".tlog", ".lastbuildstate",
    ".log", ".pyc", ".pyo", ".tmp", ".bak", ".dmp", ".dxbc",
    ".i64", ".id0", ".id1", ".id2", ".nam", ".til", ".sdf", ".md",
}


def git_paths(*args):
    result = subprocess.check_output(["git", *args, "-z"], cwd=ROOT)
    return {path.decode("utf-8") for path in result.split(b"\0") if path}


def main():
    candidates = git_paths("ls-files") | git_paths(
        "ls-files", "--others", "--exclude-standard"
    )
    bad = []
    checked = 0
    for name in sorted(candidates):
        path = Path(name)
        if not (ROOT / path).exists():
            continue
        checked += 1
        if (
            path.parts[0] in LOCAL_ROOTS
            or "__pycache__" in path.parts
            or name.startswith("research/")
            or path.suffix.lower() in ARTIFACT_SUFFIXES
            or path.name.startswith(".env")
            or path.name.endswith((".VC.db", ".VC.opendb"))
            or path.name in {"Thumbs.db", "Desktop.ini", ".DS_Store"}
        ):
            bad.append(name)
    if bad:
        print("local files or documents eligible for git:")
        print("\n".join(bad))
        return 1
    print(f"pass: {checked} git candidates; no outputs, caches or documents")
    return 0


if __name__ == "__main__":
    sys.exit(main())
