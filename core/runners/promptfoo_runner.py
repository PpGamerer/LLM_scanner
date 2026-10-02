"""
runners/promptfoo_runner.py — เรียก Promptfoo (external tool, Node.js) ผ่าน subprocess

ต่างจาก garak/promptmap2 (Python, เรียกผ่าน venv python.exe ตรงๆ) ตรงที่ Promptfoo
เป็น Node.js CLI ติดตั้งแยกจาก python venv ของโปรเจกต์นี้โดยสิ้นเชิง — ต้องมี Node.js
+ npm บนเครื่อง (หรือใน container ของ backend) แล้วติดตั้งด้วยหนึ่งในสองทาง:

    npm install -g promptfoo
    # หรือถ้าไม่อยากติดตั้ง global (ช้ากว่าตอนแรกเพราะต้องดาวน์โหลด แต่ไม่ต้อง npm install -g):
    #   set PROMPTFOO_USE_NPX=1

ถ้าจะรันผ่าน Docker: ต้องเพิ่ม Node.js เข้า Dockerfile.backend เอง (ไฟล์นี้ไม่ได้ถูก
อัปโหลดมาด้วยตอนที่เขียน runner นี้ เลยไม่ได้แก้ให้ตรงนี้ — อย่างน้อยต้องมีบรรทัดทำนอง
`RUN apt-get install -y nodejs npm && npm install -g promptfoo` เพิ่มเข้าไป)

Promptfoo เป็น config-driven (ไม่ใช่ CLI flag ล้วนแบบ garak) — flow คือ:
    1. generate ไฟล์ YAML config ตาม plugin ที่ต้องการ (ฟังก์ชัน _build_config ด้านล่าง)
    2. เรียก `promptfoo redteam run -c <config>.yaml -o <output>.json --no-cache`
       (คำสั่งนี้ตาม official doc ที่อ่านมา รวม generate testcase + eval ในคำสั่งเดียว)
    3. parse ผลจาก output json (promptfoo_parser.py)

⚠️ เหมือน promptmap2_parser.py ตอนที่เพิ่งเขียนใหม่ๆ: **flow นี้เขียนตาม official doc
ยังไม่เคยรันจริงบนเครื่องที่มี promptfoo ติดตั้งอยู่จริง** ก่อนใช้งานจริงต้อง:
    1. รัน `promptfoo --version` เช็คว่าติดตั้งสำเร็จ
    2. รัน `promptfoo redteam run --help` เทียบชื่อ flag ในนี้ (โดยเฉพาะ -o/--no-cache
       ที่อาจเปลี่ยนชื่อไปตามเวอร์ชัน)
    3. รัน scan เล็กๆ 1 plugin แล้วเปิดไฟล์ output.json ดูโครงสร้างจริงเทียบกับที่
       promptfoo_parser.py สมมติไว้ — ถ้าไม่ตรง parser จะ raise KeyError พร้อม list
       key ที่เจอจริงให้ debug ต่อได้เร็ว (ดู comment ใน promptfoo_parser.py)
"""

import os
import shutil
import subprocess
from pathlib import Path

import yaml  # ต้องเพิ่ม pyyaml เข้า requirements-backend.txt (ดูไฟล์ที่แก้คู่กัน)

from ..parsers.promptfoo_parser import parse_promptfoo_report
from .promptmap2_runner import _resolve_system_prompt_file  # เหตุผลที่ reuse ดูใน
# docstring ของ run_promptfoo_scan ด้านล่าง — ไม่อยากมี logic หา system prompt file
# ซ้ำสองที่ (owasp_mapping.py เตือนเรื่องนี้ไว้แล้วว่า "ไฟล์เดียว แก้ที่เดียว")

_CURRENT_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _CURRENT_FILE.parents[1]

# ไฟล์ผลสแกนรวมไว้ที่ results/ เดียวกับ garak/promptmap2 (ดู garak_runner.py/
# promptmap2_runner.py — ถ้าจะย้ายทีหลัง ต้องแก้ทั้ง 3 ไฟล์พร้อมกัน)
RESULTS_DIR = _PROJECT_ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

USE_NPX = os.environ.get("PROMPTFOO_USE_NPX", "0") == "1"


def _resolve_promptfoo_bin() -> list[str]:
    """คืนค่าเป็น list ของคำสั่งฐาน (ไม่ใช่ str เดียวแบบ PYTHON_BIN ของ garak/promptmap2)
    เพราะถ้าใช้ npx จะเป็นคำสั่ง 2 ท่อน (["npx", "promptfoo@latest"]) ส่วนติดตั้ง global
    เป็นคำสั่งเดียว (["promptfoo"] หรือ path เต็มที่ระบุผ่าน PROMPTFOO_PATH)

    ลำดับการหา (เหมือน _resolve_promptmap2_script ใน promptmap2_runner.py):
      1. env var PROMPTFOO_PATH ถ้ามี — ใช้ path นี้ตรงๆ
      2. PROMPTFOO_USE_NPX=1 — ใช้ npx (ไม่ต้องติดตั้ง global แต่ช้ากว่ารอบแรก)
      3. shutil.which("promptfoo") — หาจาก PATH ปกติ (กรณี npm install -g มาแล้ว)
    """
    env_path = os.environ.get("PROMPTFOO_PATH")
    if env_path:
        return [env_path]

    if USE_NPX:
        return ["npx", "promptfoo@latest"]

    found = shutil.which("promptfoo")
    if found:
        return [found]

    raise FileNotFoundError(
        "หา promptfoo CLI ไม่เจอ — ติดตั้งด้วย `npm install -g promptfoo` ก่อน หรือ set "
        "env var PROMPTFOO_USE_NPX=1 เพื่อใช้ `npx promptfoo@latest` แทน หรือ set "
        "PROMPTFOO_PATH ชี้ไปที่ binary ตรงๆ"
    )


def _build_config(
    model_name: str,
    ollama_url: str,
    plugins: list[str],
    num_tests: int,
    system_prompt: str | None,
    grader_model: str | None = None,
) -> dict:
    """สร้าง dict ที่แปลงเป็น promptfooconfig.yaml
    ...(docstring เดิม)...

    grader_model: โมเดลที่ใช้ตัดสิน pass/fail (redteam.provider) แยกจาก target
    (model_name) — ถ้าไม่ระบุ (None) fallback ไปใช้ target model ตัวเดียวกันเหมือนเดิม
    (พฤติกรรมเดิม 100%) 2026-09 (รอบหก): พบจากข้อมูลจริงว่าให้ target model เล็ก
    (1B, abliterated) ตัดสินคำตอบของตัวเองเองมีปัญหา — grader ตอบไม่เป็น JSON ที่
    parse ได้ ("Could not extract JSON from llm-rubric response") หรือ timeout
    รวมกันเฉลี่ย ~6% ของทุกแถว สูงสุด 20% ใน divergent-repetition (LLM10) — แถวพวกนี้
    ถูกนับเป็น fail อัตโนมัติทั้งที่ไม่รู้ว่า target จริงๆ ทำถูกหรือผิด (false negative
    ปนอยู่ใน pass rate โดยไม่มีใครรู้) แก้โดยให้ใช้โมเดล local อีกตัว (เช่น dolphin3)
    เป็น grader แทน ยังคง local-only ไม่ต้องมี OPENAI_API_KEY เหมือนที่ตั้งใจไว้แต่แรก
    """
    grading_provider = f"ollama:chat:{grader_model or model_name}"

    config: dict = {
        "targets": [
            {"id": f"ollama:chat:{model_name}", "config": {"apiBaseUrl": ollama_url}}
        ],
        "redteam": {
            # ถ้า grader_model ระบุมา (ต่างจาก target) ส่งเป็น object พร้อม config.apiBaseUrl
            # เอง (โมเดล grader อยู่บน ollama server เดียวกับ target — คนละโมเดล คนละ id)
            # ถ้าไม่ระบุ fallback เป็น string เดิม (พฤติกรรมเดิมเป๊ะ ไม่กระทบ caller เก่า)
            "provider": (
                {"id": grading_provider, "config": {"apiBaseUrl": ollama_url}}
                if grader_model and grader_model != model_name
                else grading_provider
            ),
            "plugins": list(plugins),
            "numTests": num_tests,
            "strategies": [],
        },
    }

    # LLM07 (prompt-extraction) ต้องมี systemPrompt ระบุไว้ใน config ของ plugin นั้นเอง
    # ไม่ใช่ top-level ของไฟล์ (ดู owasp_mapping.PROMPTFOO_PLUGIN_OWASP_MAP ที่ผูก
    # "prompt-extraction" ไว้กับ LLM07) — ถ้าไม่มี system_prompt (หา system prompt file
    # ไม่เจอ) ปล่อยให้ plugin นี้รันแบบไม่มี systemPrompt ไปก่อน (มีแค่ warning พิมพ์ออกมา
    # ไม่ raise) เพราะไม่อยากให้ plugin เดียวทำให้ scan ทั้งก้อนพังหมด
    if "prompt-extraction" in plugins and system_prompt:
        config["redteam"]["plugins"] = [
            {"id": "prompt-extraction", "config": {"systemPrompt": system_prompt}}
            if p == "prompt-extraction" else p
            for p in plugins
        ]

    return config


def run_promptfoo_scan(
    model_name: str,
    plugins: list[str] | None,
    ollama_url: str = "http://localhost:11434",
    system_prompt_path: str = "system-prompt.txt",
    num_tests: int = 5,
    grader_model: str | None = None,   # <-- เพิ่มบรรทัดนี้ (default None = พฤติกรรมเดิม)
    timeout_sec: int | None = 7200,
    output_dir: Path | None = None,
) -> list[dict]:
    """เหมือน run_garak_scan/run_promptmap2_scan — plugins=None หรือ [] คือ "ไม่ต้องรันเลย"
    (pattern เดียวกับที่แก้ไว้ใน garak_runner.py กัน [] ถูกตีความเหมือน None แล้ว
    fallback ไปยิง preset — ที่นี่เช็คด้วย `not plugins` ตรงๆ ไม่มี preset ให้ fallback อยู่แล้ว)

    system_prompt_path: ใช้ logic เดียวกับ promptmap2_runner._resolve_system_prompt_file
    (reuse ตรงๆ ไม่เขียนซ้ำ) เพื่อหา system prompt สำหรับ plugin "prompt-extraction"
    (LLM07) — ถ้าหาไม่เจอเลย (ทั้งไฟล์ที่ระบุเอง, ไฟล์จาก repo promptmap2, และดึงจาก
    Ollama /api/show ไม่ได้) จะ warn เฉยๆ ไม่ raise เพราะ plugin อื่นๆ ที่ไม่ใช่
    prompt-extraction ยังรันได้ปกติ
    grader_model: โมเดลแยกสำหรับตัดสิน pass/fail — ไม่ระบุ = ใช้ model_name ตัวเดียวกัน
    เหมือนเดิม (ดูเหตุผลเต็มใน _build_config)
    """
    if not plugins:
        return []

    system_prompt = None
    try:
        system_prompt_file = _resolve_system_prompt_file(model_name, ollama_url, system_prompt_path)
        system_prompt = system_prompt_file.read_text(encoding="utf-8")
    except (FileNotFoundError, RuntimeError) as exc:
        if "prompt-extraction" in plugins:
            print(
                f"[promptfoo_runner] หา system prompt ไม่เจอ ({exc}) — plugin "
                "'prompt-extraction' (LLM07) จะรันแบบไม่มี systemPrompt กำกับ "
                "ผลอาจไม่แม่นเท่าที่ควร"
            )

    safe_model = model_name.replace(":", "_").replace("/", "_")
    target_dir = output_dir or RESULTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    config_path = (target_dir / f"promptfoo_config_{safe_model}.yaml").resolve()
    output_path = (target_dir / f"promptfoo_scan_{safe_model}.json").resolve()

    config = _build_config(model_name, ollama_url, plugins, num_tests, system_prompt, grader_model)
    config_path.write_text(
        yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )

    base_cmd = _resolve_promptfoo_bin()
    cmd = base_cmd + [
        "redteam", "run",
        "-c", str(config_path),
        "-o", str(output_path),
        "--no-cache",  # กัน promptfoo cache ผลเก่าไว้แล้วคืนผลเดิมซ้ำ (สำคัญมากตอน
                        # เทียบผลข้าม guard-level เพราะ prompt เดียวกันอาจถูกยิงซ้ำ
                        # ด้วย system prompt คนละแบบ)
    ]

    # promptfoo redteam ถามอีเมล (telemetry/lead-capture prompt) ถ้าไม่ปิดไว้ — พอเรียก
    # ผ่าน subprocess.run(capture_output=True) prompt นั้นจะถูกดักไปอยู่ใน stdout pipe
    # เงียบๆ ไม่มีวันโผล่ให้เห็น แต่ตัว subprocess ยังค้างรอ stdin ตลอดกาล (ไม่ error ไม่
    # timeout เพราะปิด timeout ไว้) — นี่คือสาเหตุจริงที่ "หยุดเอง" เจอตอน debug
    env = {**os.environ, "PROMPTFOO_DISABLE_TELEMETRY": "true"}

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=str(_PROJECT_ROOT),
            encoding="utf-8",
            errors="replace",
            env=env,
            stdin=subprocess.DEVNULL,  # กัน promptfoo ค้างรอ input (เช่น email
                                       # prompt) เงียบๆ ตามที่ comment ด้านบนเตือนไว้ —
                                       # DEVNULL ทำให้มันเจอ EOF ทันทีแทนที่จะ inherit
                                       # stdin จาก parent ซึ่งไม่มี terminal จริงตอนรัน
                                       # ผ่าน FastAPI background task
        )
    except subprocess.TimeoutExpired as exc:
        stdout_tail = (exc.stdout or "")[-1000:]
        stderr_tail = (exc.stderr or "")[-1000:]
        raise RuntimeError(
            f"Promptfoo scan timed out หลัง {timeout_sec}s\n"
            f"--- Last STDOUT ---\n{stdout_tail}\n"
            f"--- Last STDERR ---\n{stderr_tail}"
        ) from exc

    if result.returncode != 0 and not output_path.exists():
    # promptfoo redteam ใช้ exit code สื่อผล pass/fail ของ target model เอง
    # (เจอจริง: exit 100 ตอน target สอบตกทุก test) ไม่ใช่ตัวโปรแกรม crash — เพราะงั้น
    # เช็ค returncode!=0 เฉยๆ ไม่พอ ต้องเช็คคู่กับว่ามี output file จริงไหม ถ้ามีไฟล์
    # output แปลว่าสแกนรันจบสมบูรณ์แล้ว (ต่อให้ target สอบตกทุกข้อ) ให้ผ่านไป parse
    # ผลตามปกติ ไม่ raise ที่นี่
        raise RuntimeError(
            f"promptfoo scan failed (exit {result.returncode})\n"
            f"--- STDOUT (tail) ---\n{result.stdout[-2000:]}\n"
            f"--- STDERR (tail) ---\n{result.stderr[-2000:]}"
        )

    if not output_path.exists():
        raise FileNotFoundError(
            f"หา promptfoo output ไม่เจอ: {output_path}\n"
            f"--- Console ---\n{result.stdout[-1500:]}"
        )

    return parse_promptfoo_report(output_path)