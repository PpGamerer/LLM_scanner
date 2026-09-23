"""
selector.py — Decision logic: "ทดสอบอันนี้ ควรใช้ tool ไหน"

นี่คือส่วนที่เป็น IP ของทีมเอง — โปรแกรมเลือก tool ให้เองตาม OWASP category
ที่ผู้ใช้ต้องการทดสอบ ไม่ใช่ให้ผู้ใช้เลือก tool ตรงๆ (user ไม่จำเป็นต้องรู้จัก
Garak/promptmap2/Giskard/PyRIT เลยด้วยซ้ำ)

ตอนนี้ implement จริงแค่ Garak + promptmap2 (target type "ollama")
ส่วน Giskard/PyRIT ใส่ไว้เป็นโครงให้เห็นจุดที่ต้องเติมทีหลัง (ดู TODO)
"""

from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .runners.garak_runner import run_garak_scan, RESULTS_DIR
from .runners.promptmap2_runner import run_promptmap2_scan
from .owasp_mapping import garak_probes_for_owasp, promptmap2_rule_types_for_owasp, OWASP_CATEGORIES
from .report import save_reports

# Decision table: OWASP category -> tool ที่เหมาะสุด
# อ้างอิงจากตาราง pros/cons ที่ทำไว้ (Garak=baseline กว้าง, Giskard=RAG,
# PyRIT=multi-turn, promptmap2=เจาะจง prompt stealing)
# ค่าเป็น list ได้ ถ้า category นั้นอยากให้มากกว่า 1 tool ยืนยันผลร่วมกัน
CATEGORY_TOOL_MAP = {
    "LLM01": ["garak"],        # Prompt Injection -> Garak (coverage กว้างสุด)
    "LLM06": ["garak"],        # Sensitive Info -> Garak (leakreplay probe)
    "LLM07": ["promptmap2"],   # System Prompt Leakage -> promptmap2 (เจาะจงกว่า Garak's latentinjection)
    "LLM09": ["garak"],        # Misinformation -> Garak
    # "LLM08": ["pyrit"],       # TODO: Excessive Agency / multi-turn -> PyRIT (ยังไม่ implement runner)
}

SUPPORTED_OWASP_CATEGORIES = list(CATEGORY_TOOL_MAP.keys())


def run_scan(
    target_config: dict,
    owasp_categories: list[str] | None = None,
    depth: str = "deep",
) -> tuple[list[dict], dict, str]:
    """
    Entry point หลักของ engine — รับ config + OWASP category ที่อยากทดสอบ
    โปรแกรมตัดสินใจเองว่า category ไหนต้องใช้ tool ไหน (จาก CATEGORY_TOOL_MAP)
    รันแต่ละ tool "แค่ครั้งเดียว" แม้จะถูกเลือกจากหลาย category (ไม่ยิงซ้ำ)

    depth: "quick" (เร็ว ครอบคลุมน้อยกว่า — probe ตัวแทน 1 ตัว/category, promptmap2
    1 iteration) หรือ "deep" (ค่าเริ่มต้น — ทุก probe ที่ map ไว้, promptmap2
    5 iterations) ให้ user เลือกได้เองว่าจะแลกความเร็วกับความครอบคลุมแค่ไหน
    โดยไม่ต้องไปยุ่งกับ category ที่เลือกไว้เลย (คนละมิติกัน)

    คืนค่า: (results, tool_plan, scan_id)
        results   = list ของ dict ตาม schema กลาง รวมทุก tool ที่ถูกเรียก
        tool_plan = dict อธิบายว่า category ไหนใช้ tool ไหน (โชว์ผู้ใช้ได้ว่าทำไมเลือกแบบนี้)
        scan_id   = ชื่อโฟลเดอร์ผลสแกนรอบนี้ใน results/<scan_id>/ (มี report.html/.json/.csv
        + ไฟล์ดิบของแต่ละ tool อยู่ข้างใน) — เดิมเซฟไฟล์จริงแต่ไม่คืนค่าตรงนี้เลย ทำให้
        caller (main.py/UI) หาไฟล์ที่เซฟไว้บนดิสก์ไม่เจอ ต้องพึ่งการ build ใหม่ใน
        memory (build_report_html) เท่านั้น
    """
    target_type = target_config.get("type")
    if target_type != "ollama":
        # TODO: target type อื่น (openai_compatible, matthew) ต้องเขียน
        # garak REST-generator config หรือใช้ Giskard/PyRIT ที่รองรับ custom
        # HTTP endpoint ได้ตรงกว่า — ยังไม่ implement ในเวอร์ชันนี้
        raise NotImplementedError(
            f"target type '{target_type}' ยังไม่รองรับในเวอร์ชันนี้ — "
            "ตอนนี้ทำงานได้กับ 'ollama' เท่านั้น"
        )

    if depth not in ("quick", "deep"):
        depth = "deep"  # กัน input แปลกๆ จาก API เงียบๆ แทนที่จะ error กลางสแกน

    categories = owasp_categories or SUPPORTED_OWASP_CATEGORIES
    categories = [c for c in categories if c in CATEGORY_TOOL_MAP]  # กรองเฉพาะที่รู้จัก

    # 0. แยกโฟลเดอร์ผลสแกนตามรอบ — results/<timestamp>_<model>/ เก็บไฟล์ของทุก tool
    #    ในสแกนรอบนี้ไว้ด้วยกัน แทนที่จะเขียนทับไฟล์ผลของรอบก่อนหน้าใน results/ เฉยๆ
    safe_model = str(target_config.get("model", "unknown")).replace(":", "_").replace("/", "_")
    scan_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe_model}"
    scan_dir = RESULTS_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    # 1. หาว่า tool ไหนถูกเลือกจาก category ไหนบ้าง (สำหรับโชว์ user + dedupe การรัน)
    tool_plan: dict[str, list[str]] = defaultdict(list)
    for cat in categories:
        for tool in CATEGORY_TOOL_MAP.get(cat, []):
            tool_plan[tool].append(cat)

    results = []

    # generations/iterations ต่อ depth — quick ยิงน้อยกว่าเพื่อความเร็ว
    generations = 1  # เท่าเดิมทั้ง quick/deep (ตัวแปรความเร็วหลักคือจำนวน probe/rule ที่เลือก)
    promptmap2_iterations = 1 if depth == "quick" else 5

    # 2. รัน Garak "ครั้งเดียว" ด้วย probe ที่รวมมาจากทุก category ที่ต้องการ Garak
    if "garak" in tool_plan:
        garak_categories = tool_plan["garak"]
        probes = garak_probes_for_owasp(garak_categories, depth=depth)
        results.extend(run_garak_scan(
            model_name=target_config["model"], 
            probes=probes,
            generations=generations,
            # ปิด timeout ตามที่ตกลงกันไว้ (2026-09) — เจอเคสจริงว่า promptmap2
            # ยิงนานเกิน 600s ได้ง่ายถ้า rule_types ไม่ได้ถูกจำกัด (ดู smoke_test.py)
            # เลยขอปิด timeout ให้ทั้ง garak/promptmap2 สอดคล้องกัน แทนที่จะกำหนด
            # ตัวเลขที่ยังไม่รู้ว่าพอหรือไม่พอ — ข้อเสีย: ถ้า subprocess ค้างจริง
            # (เช่น Ollama ไม่ตอบ) job จะแขวนไม่มีวัน fail เอง ต้อง kill เองถ้าเจอ
            timeout_sec=None,
            output_dir=scan_dir,
        ))

    # 3. รัน promptmap2 ถ้าถูกเลือก
    if "promptmap2" in tool_plan:
        promptmap2_categories = tool_plan["promptmap2"]
        rule_types = promptmap2_rule_types_for_owasp(promptmap2_categories)
        results.extend(run_promptmap2_scan(
            model_name=target_config["model"],
            ollama_url=target_config.get("base_url") or "http://localhost:11434",
            iterations=promptmap2_iterations,
            system_prompt_path=target_config.get("system_prompt_path") or "system-prompt.txt",
            controller_model=target_config.get("controller_model"),
            controller_model_type=target_config.get("controller_model_type"),
            rule_types=rule_types,
            timeout_sec=None,  # ปิด timeout — เหตุผลเดียวกับ run_garak_scan ด้านบน
            output_dir=scan_dir,
        ))

    # 4. filter ผลลัพธ์สุดท้ายให้เหลือแค่ category ที่ user เลือกจริง
    #    (เผื่อ tool ตัวใดตัวหนึ่งคืนผลของ category ที่ไม่ได้ขอมาด้วย)
    results = [r for r in results if r.get("owasp_category") in categories]

    # 5. เซฟ report รวม (.html + .json) ไว้ในโฟลเดอร์เดียวกับผลดิบของสแกนรอบนี้
    #    ไม่ block การคืนค่าถ้าเซฟไม่สำเร็จ — ผลสแกนสำคัญกว่า report ไฟล์
    try:
        save_reports(results, dict(tool_plan), scan_dir, target_config)
    except OSError as exc:
        print(f"[selector] เซฟ report ไม่สำเร็จ (ไม่กระทบผลสแกน): {exc}")

    return results, dict(tool_plan), scan_id


def summarize_by_owasp(rows: list[dict]) -> dict:
    """จับกลุ่มผลลัพธ์ (จาก tool ไหนก็ได้ ตราบใดที่เป็น schema กลาง) ตาม OWASP category"""
    summary = defaultdict(lambda: {"pass": 0, "total": 0})
    for r in rows:
        cat = r.get("owasp_category", "Uncategorized")
        summary[cat]["pass"] += r.get("passed", 0)
        summary[cat]["total"] += r.get("total", 0)
    return dict(summary)