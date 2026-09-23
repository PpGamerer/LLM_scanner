"""
runners/garak_runner.py — เรียก Garak ผ่าน subprocess
"""

import subprocess
import sys
from pathlib import Path

from ..parsers.garak_parser import parse_garak_report

_CURRENT_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _CURRENT_FILE.parents[1]
_VENV_PYTHON = _PROJECT_ROOT / "venv" / "Scripts" / "python.exe"
PYTHON_BIN = str(_VENV_PYTHON) if _VENV_PYTHON.exists() else sys.executable

# ไฟล์ผลสแกนทั้งหมดเก็บรวมไว้ที่ results/ แทนที่จะกองอยู่ที่ project root
RESULTS_DIR = _PROJECT_ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

PRESET_PROBES = {
    "quick": ["dan"],
    "deep": ["promptinject", "dan", "latentinjection", "leakreplay", "misleading"],
}


def run_garak_scan(
    model_name: str,
    probes: list[str] | None = None,
    preset: str = "quick",
    timeout_sec: int = 7200,
    generations: int | None = None,
    output_dir: Path | None = None,
) -> list[dict]:
    """
    output_dir: โฟลเดอร์ที่จะเซฟ report ลง — ถ้าไม่ระบุ ใช้ RESULTS_DIR (core/results/) ตรงๆ
    ถ้า selector.py เรียกแบบระบุ output_dir มา (เช่น results/<scan_id>/) จะไปเซฟที่นั่นแทน
    เพื่อให้ไฟล์ของทุก tool ในสแกนรอบเดียวกันอยู่โฟลเดอร์เดียวกัน
    """
    # ใช้ "is None" แทน "or" — probes=[] (ตั้งใจส่ง list ว่างมา เช่นจาก selector.py
    # ตอนไม่มี category ไหนต้องการ garak เลย) ต้องไม่รัน ไม่ใช่ fallback ไปใช้ preset
    # (ของเดิมใช้ `probes or PRESET_PROBES[...]` ทำให้ [] ถูกตีความเหมือน None แล้ว
    # ไปยิง preset probe อยู่ดี ทั้งที่ผู้เรียกตั้งใจบอกว่า "ไม่ต้องรัน")
    if probes is None:
        probes = PRESET_PROBES.get(preset, PRESET_PROBES["quick"])
    if not probes:
        return []

    safe_model = model_name.replace(":", "_").replace("/", "_")
    target_dir = output_dir or RESULTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    # บังคับใช้ Absolute Path เพื่อไม่ให้ Garak แอบเอาไฟล์ไปซ่อนที่อื่น
    report_prefix = (target_dir / f"garak_scan_{safe_model}").resolve()

    cmd = [
        PYTHON_BIN, "-m", "garak",
        "--model_type", "ollama",
        "--model_name", model_name,
        "--probes", ",".join(probes),
        "--report_prefix", str(report_prefix),  # ส่ง Path เต็มเข้าไปแทนชื่อลอยๆ
    ]
    
    if generations:
        cmd += ["--generations", str(generations)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=str(_PROJECT_ROOT),
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        stdout_tail = (exc.stdout or "")[-1000:]
        stderr_tail = (exc.stderr or "")[-1000:]
        raise RuntimeError(
            f"Garak scan timed out หลัง {timeout_sec}s\n"
            f"--- Last STDOUT ---\n{stdout_tail}\n"
            f"--- Last STDERR ---\n{stderr_tail}"
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(f"garak scan failed:\n{result.stderr[-2000:]}")

    # ค้นหาไฟล์จาก Path เต็มที่เรากำหนดไว้
    report_path = Path(f"{report_prefix}.report.jsonl")
    
    if not report_path.exists():
        # Fallback กรณีสุดวิสัย
        fallback = list(Path.home().glob(f"**/{safe_model}*.report.jsonl"))
        if not fallback:
            raise FileNotFoundError(
                f"หา garak report ไม่เจอ: {report_path}\n"
                f"--- Garak Console ---\n{result.stdout[-1500:]}"
            )
        report_path = fallback[-1]

    return parse_garak_report(report_path)