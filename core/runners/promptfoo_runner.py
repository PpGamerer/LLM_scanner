"""
runners/promptfoo_runner.py

เรียก Promptfoo (external Node.js CLI) ผ่าน subprocess

ข้อกำหนด:
    - ติดตั้ง Node.js และ npm
    - ติดตั้ง Promptfoo ด้วย:
          npm install -g promptfoo

      หรือกำหนด PROMPTFOO_USE_NPX=1 เพื่อใช้ npx

Flow:
    1. สร้าง Promptfoo config YAML
    2. เรียก `promptfoo redteam generate` เพื่อสร้าง test cases
       และบันทึกเป็นไฟล์ YAML แยกต่างหาก
    3. เรียก `promptfoo redteam eval` เพื่อประเมินผล
       และบันทึกทั้ง JSON และ HTML
    4. ส่ง JSON ให้ parse_promptfoo_report()

ไฟล์ผลลัพธ์:
    promptfoo_config_<model>.yaml
        Config เริ่มต้นของ Promptfoo

    promptfoo_redteam_<model>.yaml
        Config ที่มี test cases ซึ่ง generate แล้ว

    promptfoo_scan_<model>.json
        ผลการประเมินสำหรับ parser

    promptfoo_scan_<model>.html
        รายงาน HTML สำหรับเปิดดูใน browser

    promptfoo_generate_<model>.log
        Log ของขั้น generate กรณีมีข้อผิดพลาด

    promptfoo_run_<model>.log
        Log ของขั้น eval กรณีมีข้อผิดพลาด

หมายเหตุ:
    - ใช้ `redteam generate` และ `redteam eval` แยกกัน
      เพื่อไม่ให้ path ของรายงาน HTML ถูกส่งไปเป็น config
    - ใช้ --no-cache เพื่อหลีกเลี่ยงผลเก่าจาก cache
    - ปิด telemetry และปิด stdin เพื่อป้องกัน CLI ค้างรอ input
    - target และ grader ใช้ Ollama ตาม config ที่กำหนด
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import yaml


from ..parsers.promptfoo_parser import parse_promptfoo_report
from .promptmap2_runner import _resolve_system_prompt_file


_CURRENT_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _CURRENT_FILE.parents[1]

# เก็บผลไว้ใน results/ เช่นเดียวกับ runner ตัวอื่น
RESULTS_DIR = _PROJECT_ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

USE_NPX = os.environ.get("PROMPTFOO_USE_NPX", "0") == "1"


def _resolve_promptfoo_bin() -> list[str]:
    """
    คืนค่า command สำหรับเรียก Promptfoo

    ลำดับการเลือก:
        1. PROMPTFOO_PATH
        2. PROMPTFOO_USE_NPX=1 -> npx promptfoo@latest
        3. promptfoo ที่อยู่ใน PATH
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
        "หา Promptfoo CLI ไม่เจอ\n"
        "ติดตั้งด้วย `npm install -g promptfoo` หรือกำหนด "
        "PROMPTFOO_USE_NPX=1 เพื่อใช้ npx หรือกำหนด PROMPTFOO_PATH "
        "ให้ชี้ไปยัง executable ของ Promptfoo"
    )


def _build_config(
    model_name: str,
    ollama_url: str,
    plugins: list[str],
    num_tests: int,
    system_prompt: str | None,
    grader_model: str | None = None,
) -> dict:
    """
    สร้าง Promptfoo config

    model_name:
        ชื่อโมเดลเป้าหมายบน Ollama

    grader_model:
        โมเดลที่ใช้ประเมิน pass/fail
        หากไม่ระบุ จะใช้โมเดลเดียวกับ target
    """
    grading_model = grader_model or model_name
    grading_provider = f"ollama:chat:{grading_model}"

    config: dict = {
        "targets": [
            {
                "id": f"ollama:chat:{model_name}",
                "config": {
                    "apiBaseUrl": ollama_url,
                },
            }
        ],
        "redteam": {
            "provider": (
                {
                    "id": grading_provider,
                    "config": {
                        "apiBaseUrl": ollama_url,
                    },
                }
                if grader_model and grader_model != model_name
                else grading_provider
            ),
            "plugins": list(plugins),
            "numTests": num_tests,
            "strategies": ["jailbreak"],
        },
    }

    # LLM07: prompt-extraction ต้องมี systemPrompt ใน plugin config
    if "prompt-extraction" in plugins and system_prompt:
        config["redteam"]["plugins"] = [
            (
                {
                    "id": "prompt-extraction",
                    "config": {
                        "systemPrompt": system_prompt,
                    },
                }
                if plugin == "prompt-extraction"
                else plugin
            )
            for plugin in plugins
        ]

    return config


def _tail(value: str | bytes | None, limit: int = 1500) -> str:
    """แปลง subprocess output เป็นข้อความและคืนเฉพาะส่วนท้าย."""
    if value is None:
        return ""

    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")

    return value[-limit:]


def _run_command(
    cmd: list[str],
    timeout_sec: int | None,
) -> subprocess.CompletedProcess:
    """
    เรียก subprocess โดยปิด stdin และ telemetry

    ไม่แสดง output ระหว่างรัน เพราะ subprocess ใช้ capture_output
    แต่จะส่ง stdout/stderr กลับให้ caller เพื่อบันทึก log ได้
    """
    env = {
        **os.environ,
        "PROMPTFOO_DISABLE_TELEMETRY": "true",
    }

    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=str(_PROJECT_ROOT),
            encoding="utf-8",
            errors="replace",
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
        )

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Promptfoo command timed out หลัง {timeout_sec} วินาที\n"
            f"Command: {' '.join(cmd)}\n"
            f"--- STDOUT (tail) ---\n{_tail(exc.stdout)}\n"
            f"--- STDERR (tail) ---\n{_tail(exc.stderr)}"
        ) from exc

    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"ไม่สามารถเรียก Promptfoo executable ได้\n"
            f"Command: {' '.join(cmd)}\n"
            "ตรวจสอบ Node.js, npm, PATH และ PROMPTFOO_PATH"
        ) from exc


def _run_stage(
    cmd: list[str],
    timeout_sec: int | None,
    log_path: Path,
    stage_name: str,
    allowed_exit_codes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess:
    """รัน Promptfoo stage และตรวจสอบ exit code ที่อนุญาต."""

    try:
        result = _run_command(cmd, timeout_sec)

    except (RuntimeError, FileNotFoundError) as exc:
        log_path.write_text(
            f"Stage: {stage_name}\n"
            f"Command: {' '.join(cmd)}\n\n"
            f"ERROR:\n{exc}\n",
            encoding="utf-8",
        )
        raise

    if result.returncode not in allowed_exit_codes:
        log_path.write_text(
            f"Stage: {stage_name}\n"
            f"Command: {' '.join(cmd)}\n"
            f"Exit code: {result.returncode}\n\n"
            f"--- STDOUT ---\n{result.stdout}\n\n"
            f"--- STDERR ---\n{result.stderr}\n",
            encoding="utf-8",
        )

        raise RuntimeError(
            f"Promptfoo {stage_name} failed "
            f"(exit {result.returncode})\n"
            f"Log เต็ม: {log_path}\n"
            f"--- STDOUT (tail) ---\n{_tail(result.stdout)}\n"
            f"--- STDERR (tail) ---\n{_tail(result.stderr)}"
        )

    return result


def run_promptfoo_scan(
    model_name: str,
    plugins: list[str] | None,
    ollama_url: str = "http://localhost:11434",
    system_prompt_path: str = "system-prompt.txt",
    num_tests: int = 5,
    grader_model: str | None = None,
    timeout_sec: int | None = 7200,
    output_dir: Path | None = None,
) -> list[dict]:
    """
    รัน Promptfoo red-team scan และคืนผลที่ parse จาก JSON

    plugins=None หรือ [] หมายถึงไม่ต้องรัน scan และคืน [] ทันที

    system_prompt_path:
        ตำแหน่ง system prompt ที่ใช้กับ prompt-extraction
        ใช้ resolver ตัวเดียวกับ promptmap2_runner

    grader_model:
        โมเดล Ollama ที่ใช้ประเมินผล
        หากไม่ระบุจะใช้ model_name

    timeout_sec:
        timeout สำหรับแต่ละ subprocess stage

    output_dir:
        โฟลเดอร์เก็บ config, logs และผลลัพธ์
    """
    if not plugins:
        return []

    # ---------------------------------------------------------
    # 1. Resolve system prompt (ใช้ logic ร่วมกับ promptmap2)
    # ---------------------------------------------------------
    system_prompt = None

    try:
        system_prompt_file = _resolve_system_prompt_file(
            model_name,
            ollama_url,
            system_prompt_path,
        )
        system_prompt = system_prompt_file.read_text(encoding="utf-8")

    except (FileNotFoundError, RuntimeError) as exc:
        if "prompt-extraction" in plugins:
            print(
                "[promptfoo_runner] หา system prompt ไม่เจอ "
                f"({exc}) — plugin 'prompt-extraction' (LLM07) "
                "จะรันโดยไม่มี systemPrompt กำกับ "
                "ผลอาจไม่แม่นเท่าที่ควร"
            )

    # ---------------------------------------------------------
    # 2. เตรียม paths
    # ---------------------------------------------------------
    safe_model = (
        model_name
        .replace(":", "_")
        .replace("/", "_")
        .replace("\\", "_")
    )

    target_dir = Path(output_dir) if output_dir else RESULTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    config_path = (
        target_dir / f"promptfoo_config_{safe_model}.yaml"
    ).resolve()

    # Config ที่ generate test cases แล้ว ต้องเป็น YAML
    redteam_config_path = (
        target_dir / f"promptfoo_redteam_{safe_model}.yaml"
    ).resolve()

    # JSON ใช้กับ parser; HTML ใช้เปิดรายงานใน browser
    output_path = (
        target_dir / f"promptfoo_scan_{safe_model}.json"
    ).resolve()

    html_report_path = (
        target_dir / f"promptfoo_scan_{safe_model}.html"
    ).resolve()

    generate_log_path = (
        target_dir / f"promptfoo_generate_{safe_model}.log"
    ).resolve()

    eval_log_path = (
        target_dir / f"promptfoo_run_{safe_model}.log"
    ).resolve()

    # ---------------------------------------------------------
    # 3. เขียน config เริ่มต้น
    # ---------------------------------------------------------
    config = _build_config(
        model_name=model_name,
        ollama_url=ollama_url,
        plugins=plugins,
        num_tests=num_tests,
        system_prompt=system_prompt,
        grader_model=grader_model,
    )

    config_path.write_text(
        yaml.safe_dump(
            config,
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    # ---------------------------------------------------------
    # 4. Resolve Promptfoo executable
    # ---------------------------------------------------------
    base_cmd = _resolve_promptfoo_bin()

    # ลบผลเก่าก่อนเริ่ม เพื่อไม่ให้เผลออ่านไฟล์จาก scan ก่อนหน้า
    for path in (
        redteam_config_path,
        output_path,
        html_report_path,
    ):
        if path.exists():
            path.unlink()

    # ---------------------------------------------------------
    # 5. Generate test cases
    #
    # สำคัญ:
    # - -o ขั้นนี้ต้องชี้ไปยัง YAML config
    # - ห้ามใช้ html_report_path ในขั้น generate
    # ---------------------------------------------------------
    generate_cmd = base_cmd + [
        "redteam",
        "generate",
        "-c",
        str(config_path),
        "-o",
        str(redteam_config_path),
        "--no-cache",
    ]

    generate_result = _run_stage(
        cmd=generate_cmd,
        timeout_sec=timeout_sec,
        log_path=generate_log_path,
        stage_name="generate",
    )

    if not redteam_config_path.is_file():
        raise FileNotFoundError(
            "Promptfoo generate จบโดยไม่มี error "
            "แต่ไม่พบไฟล์ config ที่สร้างขึ้น\n"
            f"Expected: {redteam_config_path}\n"
            f"--- STDOUT (tail) ---\n"
            f"{_tail(generate_result.stdout)}\n"
            f"--- STDERR (tail) ---\n"
            f"{_tail(generate_result.stderr)}"
        )

    # ---------------------------------------------------------
    # 6. Evaluate test cases
    #
    # ใช้ redteam eval กับ generated YAML
    # -o JSON และ -o HTML เป็น output ของการประเมิน
    # ไม่ใช่ config input
    # ---------------------------------------------------------
    eval_cmd = base_cmd + [
        "redteam",
        "eval",
        "-c",
        str(redteam_config_path),
        "-o",
        str(output_path),
        "-o",
        str(html_report_path),
        "--no-cache",
    ]

    eval_result = _run_stage(
        cmd=eval_cmd,
        timeout_sec=timeout_sec,
        log_path=eval_log_path,
        stage_name="eval",
        allowed_exit_codes=(0, 100),
    )


    # ---------------------------------------------------------
    # 7. ตรวจสอบ output ก่อนเรียก parser
    # ---------------------------------------------------------
    if not output_path.is_file():
        raise FileNotFoundError(
            "Promptfoo eval จบโดยไม่มี JSON output\n"
            f"Expected JSON: {output_path}\n"
            f"--- STDOUT (tail) ---\n"
            f"{_tail(eval_result.stdout)}\n"
            f"--- STDERR (tail) ---\n"
            f"{_tail(eval_result.stderr)}"
        )

    try:
        with output_path.open("r", encoding="utf-8") as f:
            json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(
            f"Promptfoo สร้าง JSON ที่อ่านไม่ได้: {output_path}\n"
            f"รายละเอียด: {exc}\n"
            f"ตรวจสอบ log: {eval_log_path}"
        ) from exc

    if not html_report_path.is_file():
        print(
            "[promptfoo_runner] คำเตือน: ไม่พบ HTML report\n"
            f"Expected: {html_report_path}"
        )
    else:
        print(f"[promptfoo_runner] HTML report: {html_report_path}")

    print(f"[promptfoo_runner] JSON result: {output_path}")

    return parse_promptfoo_report(output_path)