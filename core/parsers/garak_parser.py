"""
parsers/garak_parser.py — แปลง Garak .report.jsonl เป็น schema กลาง

Schema กลาง (ใช้ร่วมกับทุก tool ในอนาคต — Giskard/PyRIT/promptmap2 ก็ต้อง
เขียน parser ของตัวเอง แต่ output ออกมาเป็น dict หน้าตาเดียวกันนี้):

    {
        "tool": str,            # ชื่อ tool ที่ใช้ยิง
        "probe": str,           # ชื่อ probe/test case
        "owasp_category": str,  # LLM01, LLM06, ...
        "passed": int,          # จำนวนที่ผ่าน (โมเดลป้องกันได้)
        "total": int,           # จำนวนทั้งหมดที่ยิง
    }

หมายเหตุ: verify แล้วกับ report จริง (garak 0.17.0) — field name จริงของ
eval entry คือ "total_evaluated" ไม่ใช่ "total" อย่างที่เดาไว้ตอนแรก (ตอนนั้น
".get('total')" คืน None เสมอ ทำให้ total เป็น 0 ทุกแถว และ pass rate พังหมด)
eval entry ยังมี "total_processed" ด้วย (เผื่อ fallback ถ้า total_evaluated หาย)

หมายเหตุอีกอย่าง: 1 probe อาจมีหลาย eval entry ถ้าโดนเช็คด้วยหลาย detector
(เช่น "dan.DAN" กับ "mitigation.MitigationBypass" สำหรับ probe เดียวกัน) —
ตอนนี้เก็บทุกแถวแยกกัน (นับซ้ำ per-detector) ถ้าอยากรวมต่อ probe เดียวต้อง
group by (probe) เพิ่มเองตอน summarize
"""

import json
from pathlib import Path
from ..owasp_mapping import garak_probe_to_owasp


def parse_garak_report(report_path: Path) -> list[dict]:
    rows = []
    with open(report_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("entry_type") != "eval":
                continue
            probe = entry.get("probe", "")
            rows.append({
                "tool": "garak",
                "probe": probe,
                "detector": entry.get("detector", ""),
                "owasp_category": garak_probe_to_owasp(probe),
                "passed": entry.get("passed") or 0,
                "total": entry.get("total_evaluated") or entry.get("total_processed") or 0,
            })
    return rows