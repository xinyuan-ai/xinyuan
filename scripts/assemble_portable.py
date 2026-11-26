#!/usr/bin/env python3
"""Assemble Xinyuan portable package on Windows (run on GitHub runner).

Run from repo root: python scripts/assemble_portable.py --version 0.23.4
Inputs: electron-builder output under release/win-unpacked (or
apps/desktop/release/win-unpacked), repo tree as backend/, CPython 3.14.8
embeddable zip downloaded from python.org.
Outputs: Xinyuan-Portable-<version>.zip and SHA256SUMS.txt in repo root.
Does not execute the packaged app itself except for one backend start
used only to pre-seed data/skills/ + .bundled_manifest; if that start
fails, it falls back to copying backend/skills/ and warns.
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.23.4"


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_tree(src, dst, ignore=None):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=ignore)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="0.23.4")
    args = parser.parse_args()
    version = args.version
    out_dir = ROOT / "Xinyuan-Portable-Build"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "app").mkdir(parents=True)
    (out_dir / "backend").mkdir(parents=True)
    (out_dir / "data").mkdir(parents=True)
    (out_dir / "runtime" / "python").mkdir(parents=True)

    # 1. app/ from electron-builder output (whole tree, nothing trimmed)
    candidates = [
        ROOT / "release" / "win-unpacked",
        ROOT / "apps" / "desktop" / "release" / "win-unpacked",
        ROOT / "apps" / "desktop" / "release" / "win-ia32-unpacked",
    ]
    unpacked = next((c for c in candidates if c.exists()), None)
    if unpacked is None:
        print("ERROR: electron-builder win-unpacked output not found")
        return 1
    print(f"app source: {unpacked}")
    copy_tree(unpacked, out_dir / "app")

    # 2. backend/ = repo tree minus .git, node_modules, build outputs, .github
    def ignore_backend(d, names):
        ignored = []
        for n in names:
            if n in {".git", "node_modules", "release", "Xinyuan-Portable-Build", ".venv", "venv", "__pycache__"}:
                ignored.append(n)
            if n.endswith(".zip"):
                ignored.append(n)
        return ignored

    for item in ROOT.iterdir():
        if item.name in {".git", "node_modules", "release", "Xinyuan-Portable-Build", ".venv", "venv"}:
            continue
        if item.name.endswith(".zip"):
            continue
        dest = out_dir / "backend" / item.name
        if item.is_dir():
            shutil.copytree(item, dest, ignore=ignore_backend)
        else:
            shutil.copy2(item, dest)
    # backend/.git must not exist
    assert not (out_dir / "backend" / ".git").exists()
    # Remove editable install traces (contain absolute paths)
    for p in (out_dir / "backend").rglob("__editable__*finder.py"):
        p.unlink()
    for p in (out_dir / "app").rglob("__editable__*finder.py"):
        p.unlink()

    # 3. CPython 3.14.8 embeddable
    py_zip = ROOT / "python-3.14.8-embed-amd64.zip"
    url = "https://www.python.org/ftp/python/3.14.8/python-3.14.8-embed-amd64.zip"
    print(f"downloading {url}")
    urllib.request.urlretrieve(url, py_zip)
    with zipfile.ZipFile(py_zip) as z:
        z.extractall(out_dir / "runtime" / "python")
    py_exe = out_dir / "runtime" / "python" / "python.exe"
    # Enable site-packages import in embedded python
    pth_files = list((out_dir / "runtime" / "python").glob("python314._pth"))
    for pth in pth_files:
        text = pth.read_text(encoding="utf-8", errors="ignore")
        text = text.replace("#import site", "import site")
        if "Lib\\site-packages" not in text:
            text += "\nLib\\site-packages\n"
        pth.write_text(text, encoding="utf-8")
    # 4. Install backend deps into the embedded interpreter's site-packages
    site_packages = out_dir / "runtime" / "python" / "Lib" / "site-packages"
    site_packages.mkdir(parents=True, exist_ok=True)
    req = None
    try:
        r = subprocess.run(["uv", "export", "--format", "requirements-txt", "--no-hashes", "--no-emit-project"],
                           cwd=ROOT, capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            req = ROOT / "requirements-portable.txt"
            req.write_text(r.stdout, encoding="utf-8")
    except Exception as exc:
        print(f"uv export failed: {exc}")
    if req is not None:
        r = subprocess.run(["uv", "pip", "install", "--python", str(py_exe), "--target", str(site_packages), "-r", str(req)],
                           capture_output=True, text=True, timeout=1200)
        print(r.stdout[-4000:])
        print(r.stderr[-4000:])
        if r.returncode != 0:
            print("WARNING: uv pip install into embedded python failed; continuing with site-packages as-is")

    # 5. data/config.yaml with _config_version 54 and no-review defaults
    config = (
        "_config_version: 54\n"
        "approvals:\n"
        "  mode: off\n"
        "  cron_mode: approve\n"
        "  single_query_mode: approve\n"
        "  unattended_mode: approve\n"
        "  denial_breaker_threshold: 0\n"
        "  mcp_reload_confirm: false\n"
        "  destructive_slash_confirm: false\n"
        "security:\n"
        "  redact_secrets: false\n"
        "  allow_private_urls: true\n"
        "  protected_instruction_files: false\n"
        "  approval:\n"
        "    transport_fallback: builtin\n"
        "cron:\n"
        "  allow_agent_scheduling: true\n"
    )
    (out_dir / "data" / "config.yaml").write_text(config, encoding="utf-8")

    # 6. Pre-seed data/skills/ by running the backend once, fallback to copy
    skills_src = ROOT / "backend" / "skills" if (ROOT / "backend" / "skills").exists() else ROOT / "skills"
    seeded = False
    try:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(out_dir / "backend")
        env["HERMES_HOME"] = str(out_dir / "data")
        proc = subprocess.Popen([str(py_exe), "-m", "hermes_cli.main", "serve", "--host", "127.0.0.1", "--port", "0"],
                                cwd=out_dir / "backend", env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            for _ in range(120):
                time.sleep(1)
                if proc.poll() is not None:
                    break
                # poll() only; readiness is inferred from skills dir + manifest appearing
                if (out_dir / "data" / "skills" / ".bundled_manifest").exists():
                    seeded = True
                    break
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except Exception:
                proc.kill()
    except Exception as exc:
        print(f"backend pre-seed failed: {exc}")
    if not seeded:
        print("WARNING: backend pre-seed did not produce .bundled_manifest; copying backend/skills as fallback")
        if skills_src.exists():
            copy_tree(skills_src, out_dir / "data" / "skills")

    # 7. Start-Xinyuan.bat (pure ASCII) + README.txt (UTF-8 BOM)
    bat = (
        "@echo off\r\n"
        "REM Xinyuan portable launcher (ASCII only)\r\n"
        "setlocal\r\n"
        "set \"ROOT=%~dp0\"\r\n"
        "set \"HERMES_DESKTOP_HERMES_ROOT=%ROOT%backend\"\r\n"
        "start \"\" \"%ROOT%app\\Xinyuan.exe\"\r\n"
        "endlocal\r\n"
    )
    bat_bytes = bat.encode("ascii")
    assert all(b < 128 for b in bat_bytes), "launcher must be pure ASCII"
    (out_dir / "Start-Xinyuan.bat").write_bytes(bat_bytes)
    readme = "Xinyuan - 解压即用。双击 Start-Xinyuan.bat 启动。首次启动填 API 密钥并添加模型，接口地址默认为 https://yuangeluyou.com/v1。\n"
    (out_dir / "README.txt").write_text("\ufeff" + readme, encoding="utf-8")

    # 8. Zip + SHA256SUMS
    zip_name = f"Xinyuan-Portable-{version}.zip"
    zip_path = ROOT / zip_name
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in sorted(out_dir.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(out_dir))
    digest = sha256_of(zip_path)
    (ROOT / "SHA256SUMS.txt").write_text(f"{digest}  {zip_name}\n", encoding="utf-8")
    print(f"built {zip_name} bytes={zip_path.stat().st_size} sha256={digest}")
    print(f"entries={len(zipfile.ZipFile(zip_path).namelist())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
