"""
api/main.py — FastAPI layer

ทำหน้าที่แค่: รับ config จากฟอร์มเว็บ -> รัน scan เป็น background job -> ให้ Streamlit poll สถานะ/ผล

user เลือกแค่ "OWASP category ที่อยากทดสอบ" — โปรแกรม (core/selector.py)
เป็นคนตัดสินใจเองว่า category ไหนต้องใช้ tool ไหน (ดู tool_plan ใน response)

มี 2 ประเภท job:
    - /scan            = สแกนเต็มรูปแบบ (อาจใช้เวลาเป็นชั่วโมง)
    - /scan/smoke-test  = สแกนจิ๋ว ยิงจริงแต่ย่อ (garak 1 probe, promptmap2 1 iteration)
                          ใช้เช็คว่า pipeline พร้อมก่อนสั่งสแกนเต็มรูปแบบ — เก็บ job แยก dict
                          (SMOKE_JOBS) กัน job สองแบบปนกัน แต่ pattern เดียวกันทุกอย่าง

หมายเหตุ: เก็บ job status ใน memory (dict) เพื่อความง่ายของ MVP นี้ —
ถ้า container restart job history จะหาย ถ้าต้องการ persist จริงจัง
ค่อยเปลี่ยนเป็น SQLite ทีหลัง (ไม่กระทบ endpoint ด้านนอก)

หมายเหตุสำคัญ: ถ้ารัน uvicorn ด้วย --reload ตอน dev — core/runners เขียน report
file (garak_scan_*.report.jsonl, promptmap2_scan_*.json) ลง project root ตรงๆ
ระหว่างสแกน (ทั้งสแกนเต็มรูปแบบและ smoke test) ถ้า reload watcher เฝ้าดู
โฟลเดอร์เดียวกัน ไฟล์ใหม่ที่โผล่ขึ้นมากลางสแกนจะทำให้ server รีสตาร์ทตัวเอง
กลางทาง (connection ที่ Streamlit poll ค้างอยู่จะโดนตัดกลางคัน) — ปิด --reload
ตอนทดสอบสแกนจริง หรือ --reload-exclude โฟลเดอร์ที่เขียน report ออกไป
"""
import time
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel

from core.selector import (
    run_scan,
    summarize_by_owasp,
    SUPPORTED_OWASP_CATEGORIES,
    RESULTS_DIR,
    CATEGORY_CAPABLE_TOOLS,
    CATEGORY_DEFAULT_TOOL,
)
from core.owasp_mapping import OWASP_CATEGORIES
from core.smoke_test import run_smoke_test, smoke_test_passed
from fastapi.responses import FileResponse

app = FastAPI(title="LLM Security Scanner API")

# job_id -> {"status": ..., "result": ..., "error": ...}
JOBS: dict[str, dict] = {}
SMOKE_JOBS: dict[str, dict] = {}


class TargetConfig(BaseModel):
    type: str  # "ollama" | "openai_compatible" | "matthew"
    base_url: str | None = None
    api_key: str | None = None
    model: str
    # ใช้เฉพาะตอน promptmap2 ถูกเลือก (LLM07) — เดิม TargetConfig ไม่มี field พวกนี้
    # แต่ core/runners/promptmap2_runner.py อ่านจาก target_config.get(...) อยู่แล้ว
    system_prompt_path: str | None = None
    controller_model: str | None = None
    controller_model_type: str | None = None


class ScanRequest(BaseModel):
    target: TargetConfig
    owasp_categories: list[str] | None = None  # เช่น ["LLM01", "LLM07"] — None = ทุก category ที่รองรับ
    depth: str = "deep"  # "quick" (เร็ว ครอบคลุมน้อยกว่า) | "deep" (ค่าเริ่มต้น — ครอบคลุมเต็ม)
    # เช่น {"LLM07": "garak"} — บังคับหมวดนั้นให้ใช้ tool อื่นแทน default ของ
    # CATEGORY_DEFAULT_TOOL ใน core/selector.py หมวดที่ไม่ได้ระบุใช้ default ตามปกติ
    # ค่าที่ไม่ใช่ตัวเลือกที่หมวดนั้นรองรับจะถูกเมินเงียบๆ (แค่ print คำเตือนที่ backend
    # log) ไม่ทำให้ scan ทั้งก้อน error — ดู selector.resolve_tool_plan()
    tool_overrides: dict[str, str] | None = None


class SmokeTestRequest(BaseModel):
    target: TargetConfig
    tools: list[str] | None = None  # เช่น ["garak"] ถ้าอยากทดสอบแค่ tool เดียว — None = ทุก tool ที่มี


def _execute_scan(job_id, target_config, owasp_categories, depth, tool_overrides):
    JOBS[job_id]["status"] = "running"
    JOBS[job_id]["started_at"] = time.time()

    def on_progress(done, total, label):
        JOBS[job_id]["progress"] = {"done": done, "total": total, "label": label}

    try:
        rows, tool_plan, scan_id = run_scan(
            target_config,
            owasp_categories=owasp_categories,
            depth=depth,
            tool_overrides=tool_overrides,
            on_progress=on_progress,
        )
        summary = summarize_by_owasp(rows)

        p = JOBS[job_id].get("progress")
        if p:
            on_progress(p["total"], p["total"], "เสร็จสิ้น")

        JOBS[job_id]["result"] = {
            "raw": rows,
            "summary": summary,
            "tool_plan": tool_plan,
            "scan_id": scan_id,
        }
        JOBS[job_id]["finished_at"] = time.time()
        JOBS[job_id]["status"] = "done"   # ตั้งหลังสุด
    except Exception as e:  # noqa: BLE001
        JOBS[job_id]["finished_at"] = time.time()
        JOBS[job_id]["status"] = "failed"
        JOBS[job_id]["error"] = str(e)


def _execute_smoke_test(job_id: str, target_config: dict, tools: list[str] | None):
    SMOKE_JOBS[job_id]["status"] = "running"
    try:
        checks = run_smoke_test(target_config, tools=tools)
        SMOKE_JOBS[job_id]["status"] = "done"
        SMOKE_JOBS[job_id]["result"] = {
            "passed": smoke_test_passed(checks),
            "checks": checks,
        }
    except Exception as e:  # noqa: BLE001
        SMOKE_JOBS[job_id]["status"] = "failed"
        SMOKE_JOBS[job_id]["error"] = str(e)


@app.get("/owasp_categories")
def list_owasp_categories():
    """ให้ frontend ดึงรายชื่อ category + tool ที่เลือกได้ต่อหมวด มาแสดงเป็น
    checkbox + dropdown เลือก tool (เฉพาะหมวดที่มีมากกว่า 1 ตัวเลือก)

    ⚠️ BREAKING CHANGE: เดิม endpoint นี้คืน {code: label} แบบ flat string —
    ui/app.py แก้ตามแล้ว (คาดหวัง {code: {"label","tools","default_tool"}})
    ถ้ามี client อื่นเรียก endpoint นี้อยู่ ต้องอัปเดตตามด้วย
    """
    return {
        code: {
            "label": OWASP_CATEGORIES[code],
            "tools": CATEGORY_CAPABLE_TOOLS.get(code, []),
            "default_tool": CATEGORY_DEFAULT_TOOL.get(code),
        }
        for code in SUPPORTED_OWASP_CATEGORIES
    }


@app.post("/scan")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    JOBS[job_id] = {
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "finished_at": None,
        "progress": None,
        "result": None,
        "error": None,
    }
    # หมายเหตุ: ไม่เก็บ api_key ไว้ใน JOBS dict ถาวร — ส่งแค่ตอน execute แล้วปล่อยผ่าน
    background_tasks.add_task(
        _execute_scan, job_id, req.target.model_dump(), req.owasp_categories, req.depth, req.tool_overrides
    )
    return {"job_id": job_id, "status": "queued"}


@app.get("/scan/{job_id}/status")
def get_status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="ไม่พบ job นี้")

    started = job.get("started_at")
    elapsed = int((job.get("finished_at") or time.time()) - started) if started else None

    return {
        "job_id": job_id,
        "status": job["status"],
        "error": job.get("error"),
        "progress": job.get("progress"),
        "elapsed_sec": elapsed,
    }

@app.get("/scan/{job_id}/report")
def get_report(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="ไม่พบ job นี้")
    if job["status"] != "done":
        raise HTTPException(status_code=409, detail=f"job ยังไม่เสร็จ (สถานะ: {job['status']})")
    return job["result"]


@app.post("/scan/smoke-test")
def start_smoke_test(req: SmokeTestRequest, background_tasks: BackgroundTasks):
    """เริ่ม smoke test job — เหมือน /scan แต่เล็กและเร็วกว่ามาก (นาที ไม่ใช่ชั่วโมง)"""
    job_id = str(uuid.uuid4())
    SMOKE_JOBS[job_id] = {
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "result": None,
        "error": None,
    }
    background_tasks.add_task(_execute_smoke_test, job_id, req.target.model_dump(), req.tools)
    return {"job_id": job_id, "status": "queued"}


@app.get("/scan/smoke-test/{job_id}/status")
def get_smoke_test_status(job_id: str):
    """
    ต่างจาก /scan/{job_id}/status ตรงที่ endpoint นี้ส่ง result มาพร้อม status เลย
    เมื่อ status == "done" — ไม่ต้องมี /report endpoint แยก เพราะผล smoke test
    เล็กพอที่จะส่งมาด้วยกันได้โดยไม่ต้อง round-trip เพิ่ม
    """
    job = SMOKE_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="ไม่พบ smoke test job นี้")
    return {
        "job_id": job_id,
        "status": job["status"],
        "error": job.get("error"),
        "result": job.get("result"),
    }

@app.get("/scan/{job_id}/report/html")
def get_report_html_file(job_id: str):
    job = JOBS.get(job_id)
    if not job or job["status"] != "done":
        raise HTTPException(status_code=404, detail="ไม่พบ report หรือยังไม่เสร็จ")
    scan_id = job["result"]["scan_id"]
    html_path = RESULTS_DIR / scan_id / "report.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="ไม่พบไฟล์ report.html บน backend")
    return FileResponse(html_path, media_type="text/html")

@app.get("/scan/{job_id}/files/{filename}")
def get_scan_file(job_id: str, filename: str):
    job = JOBS.get(job_id)
    if not job or not job.get("result"):
        raise HTTPException(status_code=404, detail="ไม่พบ job นี้")
    scan_dir = (RESULTS_DIR / job["result"]["scan_id"]).resolve()
    path = (scan_dir / filename).resolve()
    if path.parent != scan_dir or not path.is_file():  # กัน ../
        raise HTTPException(status_code=404, detail="ไม่พบไฟล์")
    return FileResponse(path)

@app.get("/health")
def health():
    return {"status": "ok"}