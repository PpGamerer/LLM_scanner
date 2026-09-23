"""
runners/promptmap2_runner.py — เรียก promptmap2 (external tool) ผ่าน subprocess

ข้อกำหนดก่อนใช้:
    pip install -r requirements ของ promptmap2 เอง (ดู github.com/utkusen/promptmap)
    วางไฟล์ promptmap2.py ไว้ใน PATH หรือระบุ path เต็มผ่าน PROMPTMAP2_PATH
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import requests

from ..parsers.promptmap2_parser import parse_promptmap2_report

# หา Path ของ Project Root และ venv เพื่อป้องกัน Environment เพี้ยน
_CURRENT_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _CURRENT_FILE.parents[1]
_VENV_PYTHON = _PROJECT_ROOT / "venv" / "Scripts" / "python.exe"
PYTHON_BIN = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else sys.executable

# ไฟล์ผลสแกนทั้งหมดเก็บรวมไว้ที่ results/ แทนที่จะกองอยู่ที่ project root
# (ตัวเดียวกับที่ garak_runner.py ใช้ — ถ้าจะย้ายทีหลัง แก้ที่นี่กับ garak_runner.py คู่กัน)
RESULTS_DIR = _PROJECT_ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

_DEFAULT_SCRIPT_CANDIDATES = [
    _PROJECT_ROOT / "promptmap" / "promptmap2.py",
    Path("./promptmap/promptmap2.py"),
]


def _resolve_promptmap2_script() -> Path:
    env_path = os.environ.get("PROMPTMAP2_PATH")
    if env_path:
        p = Path(env_path).resolve()
        if p.exists():
            return p

    for candidate in _DEFAULT_SCRIPT_CANDIDATES:
        p = Path(candidate).resolve()
        if p.exists():
            return p

    found = shutil.which("promptmap2.py") or shutil.which("promptmap2")
    if found:
        return Path(found).resolve()

    raise FileNotFoundError(
        "หา promptmap2.py ไม่เจอ — clone https://github.com/utkusen/promptmap มาไว้ที่ "
        "./promptmap/promptmap2.py หรือ set env var PROMPTMAP2_PATH ชี้ไปที่ path เต็มของไฟล์"
    )


DEFAULT_SYSTEM_PROMPT_PATH = "system-prompt.txt"

_REPO_SYSTEM_PROMPT_CANDIDATES = [
    _PROJECT_ROOT / "promptmap" / "system-prompts.txt",
    _PROJECT_ROOT / "promptmap" / "system-prompt.txt",
    Path("./promptmap/system-prompts.txt"),
    Path("./promptmap/system-prompt.txt"),
]


def _fetch_ollama_system_prompt(model_name: str, base_url: str) -> str:
    """ดึง system prompt จริงของ model จาก Ollama (ถ้า Modelfile กำหนดไว้) ผ่าน /api/show"""
    try:
        resp = requests.post(
            f"{base_url.rstrip('/')}/api/show",
            json={"name": model_name},
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(
            f"ดึง system prompt จาก Ollama ไม่ได้ (model={model_name}, url={base_url}): {exc} "
            "— เช็คว่า `ollama serve` รันอยู่ และ pull โมเดลนี้ไว้แล้ว"
        ) from exc
    return resp.json().get("system", "") or ""


def _resolve_system_prompt_file(model_name: str, ollama_url: str, system_prompt_path: str) -> Path:
    """
    ลำดับการหาไฟล์:
      1. ไฟล์ที่ระบุ (system_prompt_path) ถ้ามีอยู่แล้ว ใช้เลย
      2. ถ้า user ไม่ได้ระบุ path เอง — ลองหาไฟล์ system-prompts.txt ที่มากับ repo promptmap2
      3. ถ้ายังไม่เจอ — ดึง system prompt จริงจาก Ollama model มาสร้างไฟล์ให้อัตโนมัติ
    """
    path = Path(system_prompt_path).resolve()
    if path.exists():
        return path

    if system_prompt_path != DEFAULT_SYSTEM_PROMPT_PATH:
        raise FileNotFoundError(
            f"ไม่พบ system prompt file: {system_prompt_path} — ต้องสร้างไฟล์ txt ที่มี system "
            "prompt ของ target ที่จะสแกน แล้วส่ง path เข้ามาทาง system_prompt_path"
        )

    for candidate in _REPO_SYSTEM_PROMPT_CANDIDATES:
        candidate_path = Path(candidate).resolve()
        if candidate_path.exists():
            return candidate_path

    system_text = _fetch_ollama_system_prompt(model_name, ollama_url)
    if not system_text:
        system_text = "You are a helpful assistant."

    path.write_text(system_text, encoding="utf-8")
    return path


def run_promptmap2_scan(
    model_name: str,
    ollama_url: str = "http://localhost:11434",
    iterations: int = 5,
    system_prompt_path: str = DEFAULT_SYSTEM_PROMPT_PATH,
    controller_model: str | None = None,
    controller_model_type: str | None = None,
    rule_types: list[str] | None = None,
    timeout_sec: int = 7200,
    output_dir: Path | None = None,
) -> list[dict]:
    """รัน promptmap2 เข้า Ollama model ที่ระบุ คืนค่าเป็น list ของ dict ตาม schema กลาง

    rule_types: จำกัด promptmap2 ให้รันเฉพาะ rule type ที่เกี่ยวกับ OWASP category ที่ user
    เลือกจริง (เช่น ["prompt_stealing"] สำหรับ LLM07) ผ่าน --rule-type แทนที่จะรันทุก rule
    แล้วมากรองทีหลัง — ถ้าไม่ระบุ จะปล่อยให้ promptmap2 รันตาม default ของมันเอง (ทุก rule)

    output_dir: โฟลเดอร์ที่จะเซฟ output json ลง — ถ้าไม่ระบุ ใช้ RESULTS_DIR (core/results/)
    ตรงๆ ถ้า selector.py ระบุมา (เช่น results/<scan_id>/) จะไปเซฟที่นั่นแทน
    """

    script = _resolve_promptmap2_script()
    system_prompt_file = _resolve_system_prompt_file(model_name, ollama_url, system_prompt_path)

    # ใช้ Absolute Path เซฟไว้ที่ output_dir (หรือ results/ ถ้าไม่ระบุ)
    safe_model = model_name.replace(":", "_").replace("/", "_")
    target_dir = output_dir or RESULTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    output_path = (target_dir / f"promptmap2_scan_{safe_model}.json").resolve()

    cmd = [
        PYTHON_BIN,
        str(script),
        "--target-model", model_name,
        "--target-model-type", "ollama",
        "--ollama-url", ollama_url,
        "--iterations", str(iterations),
        "--prompts", str(system_prompt_file),
        "--output", str(output_path),
        "-y",
    ]
    if controller_model:
        cmd += ["--controller-model", controller_model]
    if controller_model_type:
        cmd += ["--controller-model-type", controller_model_type]
    if rule_types:
        cmd += ["--rule-type", ",".join(rule_types)]

    try:
        # กำหนด cwd เป็นโฟลเดอร์ของ script เสมอ เพื่อให้อ่าน rules ได้ถูกต้อง
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=str(script.parent),
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"promptmap2 scan timeout หลัง {timeout_sec} วินาที") from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"promptmap2 scan failed (exit code {result.returncode}):\n"
            f"--- STDERR ---\n{result.stderr[-2000:]}\n"
            f"--- STDOUT ---\n{result.stdout[-1000:]}"
        )

    if not output_path.exists():
        raise FileNotFoundError(
            f"หา promptmap2 output ไม่เจอ: {output_path}\n"
            f"Console Output:\n{result.stdout[-2000:]}"
        )

    return parse_promptmap2_report(output_path)