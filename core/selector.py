"""
selector.py — Decision logic: "ทดสอบอันนี้ ควรใช้ tool ไหน"

2026-09 (รอบเจ็ด): เปลี่ยน CATEGORY_TOOL_MAP (list ของ tool ที่ "รันพร้อมกันเสมอ")
เป็น 2 dict แยกกัน:
    CATEGORY_CAPABLE_TOOLS — tool ไหน "ทำหมวดนี้ได้บ้าง" (verify แล้วจากการเทียบ
    probe/plugin/rule ของแต่ละ tool กับ OWASP category — ดู owasp_mapping.py)
    CATEGORY_DEFAULT_TOOL  — ถ้า user ไม่ได้เลือกเอง ใช้ตัวไหนเป็นค่าเริ่มต้น

promptmap2 หายไปจาก CATEGORY_TOOL_MAP เดิมโดยไม่มีใครตั้งใจ — รอบนี้ใส่กลับเข้า
CATEGORY_CAPABLE_TOOLS["LLM07"] ให้เป็นตัวเลือกที่ 3 คู่กับ garak/promptfoo
(ไม่ได้ตั้งเป็น default เปลี่ยนจากเดิม ยังใช้ promptfoo เป็น default LLM07 เหมือนเดิม)

2026-10 (รอบสิบเอ็ด): แก้บั๊ก dual-category ที่เจอตอน verify owasp_mapping.py รอบ 10 —
garak_probes_for_owasp() ถูกแก้ให้ "เลือกรัน" probe อย่าง web_injection/exploitation/
divergence.Repeat เข้า category รองด้วยแล้ว (เช่น web_injection ถูกรันตอนขอ LLM02
ทั้งที่ primary category ของมันคือ LLM05) แต่ตอน filter ผลลัพธ์สุดท้ายเดิมเช็คแค่
`r["owasp_category"] in categories` ซึ่ง owasp_category ที่ parser ใส่มาเป็น primary
เดียวเสมอ (LLM05) — ทำให้ผลของ web_injection/exploitation ที่ควรนับเป็น LLM02 ด้วย
โดนกรองทิ้งเงียบๆ ทุกครั้งที่ user ขอ category รอง (เจอกับ divergence.Repeat/LLM10
มาก่อนแล้วเหมือนกัน เพิ่งมาสังเกตว่าเป็น pattern เดียวกัน)

แก้โดยเพิ่ม `_expand_dual_category_garak_rows()`: หา category ที่ "ตรงกับที่ user ขอ
จริง" ของแต่ละแถวผล garak (อาจมากกว่า 1 ถ้า user ขอ category คู่พร้อมกัน) แล้ว
duplicate แถวเป็นหลายแถวเท่าจำนวน category ที่ match — pass/total ของ probe เดียวกัน
จะถูกนับใน summary ของทุก category ที่ user เลือกและ probe นั้นตรง concept ด้วยจริง
(ใช้ owasp_mapping.garak_probe_categories() เป็นแหล่งความจริงเดียวกับฝั่งเลือกรัน
ไม่ใช่เดาเอง) เฉพาะผลจาก tool=="garak" เท่านั้นที่ผ่านฟังก์ชันนี้ — promptmap2/
promptfoo ยังกรองด้วย owasp_category ตรงๆ แบบเดิม (ไม่มีปัญหา dual-category นี้)
"""

import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .runners.garak_runner import run_garak_scan, RESULTS_DIR
from .runners.promptmap2_runner import run_promptmap2_scan
from .runners.promptfoo_runner import run_promptfoo_scan
from .owasp_mapping import (
    garak_probes_for_owasp,
    garak_probe_categories,
    promptmap2_rule_types_for_owasp,
    promptfoo_plugins_for_owasp,
    OWASP_CATEGORIES,
)
from .report import save_reports

# tool ไหน "ทำได้" บ้างในแต่ละหมวด — verify แล้วว่ามี probe/plugin/rule ที่ active
# จริงรองรับ concept ของหมวดนั้น (ไม่ใช่แค่มี tag ลอยๆ) ลำดับใน list ไม่มีความหมาย
# พิเศษ (ไม่ใช่ลำดับความสำคัญ) — เอาไว้ให้ UI/API โชว์เป็นตัวเลือกเฉยๆ
CATEGORY_CAPABLE_TOOLS = {
    "LLM01": ["garak", "promptfoo"],
    "LLM02": ["garak", "promptfoo"],
    # LLM05 เพิ่ม 2026-09 (รอบเก้า) — garak เท่านั้น (web_injection, exploitation —
    # ดู owasp_mapping.py) Promptfoo ฝั่งนี้ต้องเขียน custom assertion เอง ไม่ใช่
    # plugin สำเร็จรูปเหมือนหมวดอื่น เลยยังไม่มี runner รองรับใน codebase นี้
    "LLM05": ["garak"],
    "LLM06": ["promptfoo"],              # garak ยังไม่มี probe active ตรง concept นี้
    "LLM07": ["promptmap2", "garak", "promptfoo"],
    "LLM09": ["garak", "promptfoo"],
    "LLM10": ["garak", "promptfoo"],
}

# ตัวที่เลือกให้อัตโนมัติถ้า user ไม่ได้สั่งผ่าน tool_overrides
CATEGORY_DEFAULT_TOOL = {
    "LLM01": "garak",
    "LLM02": "garak",
    "LLM05": "garak",   # ตัวเดียวที่ทำได้ตอนนี้ (ดู CATEGORY_CAPABLE_TOOLS ด้านบน)
    "LLM06": "promptfoo",
    "LLM07": "promptfoo",
    "LLM09": "garak",
    "LLM10": "promptfoo",
}

SUPPORTED_OWASP_CATEGORIES = list(CATEGORY_CAPABLE_TOOLS.keys())


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, "").strip())
    except ValueError:
        return default
    return value if value >= 1 else default


def resolve_tool_plan(
    categories: list[str],
    tool_overrides: dict[str, str] | None = None,
) -> dict[str, list[str]]:
    """ตัดสินว่าแต่ละ category (ที่ user เลือกจะทดสอบ) จะใช้ tool ไหน 1 ตัวเสมอ —
    ใช้ tool_overrides[category] ถ้า user ระบุมาและเป็นตัวเลือกที่ถูกต้องจริง
    (อยู่ใน CATEGORY_CAPABLE_TOOLS[category]) ไม่งั้น fallback ไป CATEGORY_DEFAULT_TOOL
    """
    tool_overrides = tool_overrides or {}
    tool_plan: dict[str, list[str]] = defaultdict(list)

    for cat in categories:
        capable = CATEGORY_CAPABLE_TOOLS.get(cat, [])
        if not capable:
            continue

        chosen = tool_overrides.get(cat)
        if chosen and chosen not in capable:
            print(
                f"[selector] tool_overrides['{cat}']='{chosen}' ไม่ใช่ตัวเลือกที่รองรับ "
                f"สำหรับหมวดนี้ (รองรับ: {capable}) — ใช้ default แทน"
            )
            chosen = None

        chosen = chosen or CATEGORY_DEFAULT_TOOL.get(cat) or capable[0]
        tool_plan[chosen].append(cat)

    return dict(tool_plan)


def _expand_dual_category_garak_rows(results: list[dict], categories: list[str]) -> list[dict]:
    """กรอง + duplicate ผลลัพธ์ garak ที่มาจาก probe แบบ dual-category ให้ตรงกับ
    category ที่ user ขอจริง (ดู docstring หัวไฟล์ 2026-10 รอบสิบเอ็ด สำหรับที่มาของบั๊ก
    ที่แก้ตรงนี้) — ผลที่ไม่ใช่ tool "garak" (promptmap2/promptfoo) กรองด้วย
    owasp_category ตรงๆ แบบเดิม ไม่ผ่าน logic นี้
    """
    expanded = []
    for r in results:
        if r.get("tool") != "garak":
            if r.get("owasp_category") in categories:
                expanded.append(r)
            continue

        matched_categories = [
            c for c in garak_probe_categories(r.get("probe", "")) if c in categories
        ]
        for cat in matched_categories:
            row = dict(r)
            row["owasp_category"] = cat
            expanded.append(row)

    return expanded


def run_scan(
    target_config: dict,
    owasp_categories: list[str] | None = None,
    depth: str = "deep",
    tool_overrides: dict[str, str] | None = None,
) -> tuple[list[dict], dict, str]:
    """
    Entry point หลักของ engine

    tool_overrides: เช่น {"LLM07": "garak"} — บังคับให้หมวด LLM07 ใช้ garak แทน
    promptfoo (default) รอบนี้ ไม่ต้องระบุครบทุกหมวด หมวดที่ไม่ได้ระบุใช้ default
    ตามปกติ — ค่าที่ไม่ใช่ตัวเลือกที่รองรับของหมวดนั้นจะถูกเมิน (print คำเตือน)

    คืนค่า: (results, tool_plan, scan_id)
    """
    target_type = target_config.get("type")
    if target_type != "ollama":
        raise NotImplementedError(
            f"target type '{target_type}' ยังไม่รองรับในเวอร์ชันนี้ — "
            "ตอนนี้ทำงานได้กับ 'ollama' เท่านั้น"
        )

    if depth not in ("quick", "deep"):
        depth = "deep"

    categories = owasp_categories or SUPPORTED_OWASP_CATEGORIES
    categories = [c for c in categories if c in CATEGORY_CAPABLE_TOOLS]

    safe_model = str(target_config.get("model", "unknown")).replace(":", "_").replace("/", "_")
    scan_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe_model}"
    scan_dir = RESULTS_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    # 1. ตัดสินว่าแต่ละ category ใช้ tool ไหน (default หรือ override) — 1 tool/category
    tool_plan = resolve_tool_plan(categories, tool_overrides)

    results = []

    generations = 1
    promptmap2_iterations = 1 if depth == "quick" else 5
    promptfoo_num_tests = _env_int("PROMPTFOO_QUICK_TESTS", 10) if depth == "quick" \
        else _env_int("PROMPTFOO_DEEP_TESTS", 50)
    _PROMPTFOO_GRADER_MODEL = os.environ.get("PROMPTFOO_GRADER_MODEL", "dolphin3") or None

    # 2. Garak
    if "garak" in tool_plan:
        probes = garak_probes_for_owasp(tool_plan["garak"], depth=depth)
        results.extend(run_garak_scan(
            model_name=target_config["model"],
            probes=probes,
            generations=generations,
            timeout_sec=None,
            output_dir=scan_dir,
        ))

    # 3. promptmap2
    if "promptmap2" in tool_plan:
        rule_types = promptmap2_rule_types_for_owasp(tool_plan["promptmap2"])
        results.extend(run_promptmap2_scan(
            model_name=target_config["model"],
            ollama_url=target_config.get("base_url") or "http://localhost:11434",
            iterations=promptmap2_iterations,
            system_prompt_path=target_config.get("system_prompt_path") or "system-prompt.txt",
            controller_model=target_config.get("controller_model"),
            controller_model_type=target_config.get("controller_model_type"),
            rule_types=rule_types,
            timeout_sec=None,
            output_dir=scan_dir,
        ))

    # 4. Promptfoo
    if "promptfoo" in tool_plan:
        plugins = promptfoo_plugins_for_owasp(tool_plan["promptfoo"], depth=depth)
        results.extend(run_promptfoo_scan(
            model_name=target_config["model"],
            plugins=plugins,
            ollama_url=target_config.get("base_url") or "http://localhost:11434",
            system_prompt_path=target_config.get("system_prompt_path") or "system-prompt.txt",
            num_tests=promptfoo_num_tests,
            grader_model=_PROMPTFOO_GRADER_MODEL,
            timeout_sec=None,
            output_dir=scan_dir,
        ))

    # 5. filter ผลลัพธ์สุดท้ายให้เหลือแค่ category ที่ user เลือกจริง — ใช้
    # _expand_dual_category_garak_rows() แทนการเทียบ owasp_category ตรงๆ เพราะผล
    # จาก garak บาง probe (web_injection, exploitation, divergence.Repeat) ตรง
    # concept มากกว่า 1 category พร้อมกัน (ดู docstring หัวไฟล์ 2026-10 รอบสิบเอ็ด)
    results = _expand_dual_category_garak_rows(results, categories)

    # 6. เซฟ report รวม
    try:
        save_reports(results, dict(tool_plan), scan_dir, target_config)
    except OSError as exc:
        print(f"[selector] เซฟ report ไม่สำเร็จ (ไม่กระทบผลสแกน): {exc}")

    return results, dict(tool_plan), scan_id


def summarize_by_owasp(rows: list[dict]) -> dict:
    summary = defaultdict(lambda: {"pass": 0, "total": 0})
    for r in rows:
        cat = r.get("owasp_category", "Uncategorized")
        summary[cat]["pass"] += r.get("passed") or 0
        summary[cat]["total"] += r.get("total") or 0
    return dict(summary)