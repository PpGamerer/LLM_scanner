"""
parsers/promptmap2_parser.py — แปลง promptmap2 --output results.json เป็น schema กลาง

promptmap2 output format (อ้างอิงจาก official README):

    {
        "prompt_stealer_basic": {
            "type": "prompt_stealing",
            "severity": "high",
            "passed": false,
            "pass_rate": "0/5",
            "failed_result": { "response": "...", "evaluation": "FAIL", "reason": "..." }
        },
        ...
    }

หมายเหตุ: "passed": false ใน promptmap2 หมายถึง "โดนเจาะสำเร็จ" (attack ผ่าน)
ไม่ใช่ "โมเดลป้องกันได้" — ตรงข้ามกับความหมายที่เราต้องการในตอนแรก
ต้อง invert ตอน normalize เข้า schema กลาง (schema กลางของเรานิยาม
"passed" = จำนวนที่โมเดลป้องกันได้)

ยังไม่ได้ verify กับ output จริงบนเครื่อง — ควรรันจริงก่อนเชื่อ 100%
"""

import json
from pathlib import Path
from ..owasp_mapping import promptmap2_type_to_owasp


def _parse_pass_rate(pass_rate: str) -> tuple[int, int]:
    """แปลง '3/5' -> (passed=3, total=5) — จำนวนครั้งที่ "โมเดลป้องกันได้" ต่อจำนวน
    ครั้งที่ยิง attack นี้ทั้งหมด

    เดิมทิ้งตัวเลข passed ไปเฉยๆ (ใช้แค่ total) แล้วไปเดา passed จาก boolean
    overall ของทั้ง test (all-or-nothing) ทำให้ pass rate ที่โชว์ผู้ใช้ไม่ตรงกับ
    ตัวเลขจริงที่ promptmap2 รายงานมา (เช่น '3/5' ควรได้ 60% แต่ของเดิมปัดเป็น
    0% หรือ 100% ไปเลยแล้วแต่ boolean passed)
    """
    try:
        passed_str, total_str = pass_rate.split("/")
        return int(passed_str), int(total_str)
    except (ValueError, AttributeError):
        return 0, 1  # fallback ถ้า format ไม่ตรงที่คาด


def parse_promptmap2_report(report_path: Path) -> list[dict]:
    with open(report_path, encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    for test_name, result in data.items():
        rule_type = result.get("type", "")
        passed, total = _parse_pass_rate(result.get("pass_rate", "0/1"))

        rows.append({
            "tool": "promptmap2",
            "probe": test_name,
            "owasp_category": promptmap2_type_to_owasp(rule_type),
            "passed": passed,
            "total": total,
        })
    return rows