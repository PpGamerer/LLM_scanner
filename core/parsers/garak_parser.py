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
        "failures": list[dict], # (optional) ตัวอย่างที่ "พัง" — prompt/response/เหตุผล
    }

หมายเหตุ: verify แล้วกับ report จริง (garak 0.17.0) — field name จริงของ
eval entry คือ "total_evaluated" ไม่ใช่ "total" อย่างที่เดาไว้ตอนแรก (ตอนนั้น
".get('total')" คืน None เสมอ ทำให้ total เป็น 0 ทุกแถว และ pass rate พังหมด)
eval entry ยังมี "total_processed" ด้วย (เผื่อ fallback ถ้า total_evaluated หาย)

หมายเหตุอีกอย่าง: 1 probe อาจมีหลาย eval entry ถ้าโดนเช็คด้วยหลาย detector
(เช่น "dan.DAN" กับ "mitigation.MitigationBypass" สำหรับ probe เดียวกัน) —
ตอนนี้เก็บทุกแถวแยกกัน (นับซ้ำ per-detector) ถ้าอยากรวมต่อ probe เดียวต้อง
group by (probe) เพิ่มเองตอน summarize

2026-10 (รอบ hitlog parity): เดิม parser นี้ดึงแค่ entry_type=="eval" (ตัวเลข
pass/total ล้วนๆ) ไม่เคยดึงตัวอย่าง prompt/response ที่ "พัง" เลยสักแถว ต่างจาก
promptfoo_parser.py ที่เก็บ failures ไว้ด้วย (ไม่เกิน MAX_EXAMPLES_PER_PLUGIN ต่อ
plugin) — ทำให้ unified report.py โชว์ปุ่ม "ดูตัวอย่างที่พัง" เฉพาะแถวของ promptfoo
เท่านั้น ส่วนแถว garak มีแต่ตัวเลข ทั้งที่ข้อมูลมีอยู่จริง garak เขียนไฟล์
"<report_prefix>.hitlog.jsonl" คู่กับ ".report.jsonl" เสมอโดยอัตโนมัติ (ไม่ต้องสั่ง
flag เพิ่ม — verify จากไฟล์ hitlog จริงที่ได้จากสแกน llama3.2:1b) เก็บเฉพาะ attempt
ที่ "hit" จริง (= โจมตีสำเร็จ = โมเดลป้องกันไม่ได้ ตรงกับนิยาม "failures" ที่
promptfoo_parser.py ใช้) พร้อม prompt/output/triggers ต่อ (probe, detector) —

เลยเพิ่ม _load_hit_examples() อ่าน hitlog.jsonl (ถ้ามี) group ตาม (probe, detector)
cap ไว้ไม่เกิน MAX_EXAMPLES_PER_PROBE ต่อคู่ (ใช้ค่าเดียวกับ promptfoo_parser.py
เพื่อให้รายงานรวมมีความละเอียดระดับเดียวกันทั้ง 2 tool) แล้วแนบเป็น row["failures"]
เฉพาะแถวที่มี hit จริง (แถวที่โมเดลป้องกันได้หมด ไม่มี hit เลย จะไม่มี key "failures"
เหมือนเดิม — รายงานฝั่ง report.py เช็ค `r.get("failures") or []` อยู่แล้ว ไม่กระทบ)

ถ้าหาไฟล์ hitlog ไม่เจอ (เช่น garak เวอร์ชันเก่าไม่เขียนไฟล์นี้ หรือโมเดลป้องกันได้
หมดจนไม่มี hit เลยสักครั้ง) ฟังก์ชันคืน dict ว่างเฉยๆ ไม่ raise — ต่างจาก
promptfoo_parser.py ที่ raise ถ้าหา results list ไม่เจอเลย เพราะกรณีนั้นคือ schema
เปลี่ยนจริงต้องรู้ทันที แต่ไฟล์ hitlog หายไปได้ด้วยเหตุผลปกติ (ไม่มี hit จริงๆ) ไม่ควร
ทำให้การ parse ผลหลักทั้งหมดพังไปด้วย
"""

import json
from pathlib import Path
from ..owasp_mapping import garak_probe_to_owasp

MAX_EXAMPLES_PER_PROBE = 3


def _hitlog_path_for(report_path: Path) -> Path:
    """garak เขียน "<prefix>.hitlog.jsonl" คู่กับ "<prefix>.report.jsonl" เสมอ
    (อัตโนมัติ ไม่ต้องสั่ง flag เพิ่ม) — ตัด suffix ".report.jsonl" ออกแล้วต่อ
    ".hitlog.jsonl" แทน ถ้าชื่อไฟล์ไม่ตรง pattern นี้ (เผื่อ garak เปลี่ยนในอนาคต)
    fallback ไปใช้ .stem ต่อ ".hitlog.jsonl" แทน (เดากันพังเฉยๆ ไม่ raise เพราะแค่
    หาตัวอย่างประกอบไม่เจอ ไม่ใช่ error ของผลหลัก)
    """
    name = report_path.name
    if name.endswith(".report.jsonl"):
        hit_name = name[: -len(".report.jsonl")] + ".hitlog.jsonl"
    else:
        hit_name = report_path.stem + ".hitlog.jsonl"
    return report_path.with_name(hit_name)


def _extract_hit_prompt_text(turns: list) -> str:
    """ดึงข้อความจาก turns[0].content.text ของ hitlog entry — เอาแค่ turn แรก
    (ข้อความที่ user/probe ส่งไป) พอ ไม่ประกอบ multi-turn conversation เต็ม
    (เกินจำเป็นสำหรับโชว์เป็นตัวอย่างประกอบรายงาน ไม่ใช่ transcript เต็ม)"""
    if not turns:
        return ""
    first = turns[0] or {}
    content = first.get("content") or {}
    return content.get("text", "") or ""


def _load_hit_examples(hitlog_path: Path) -> dict[tuple[str, str], list[dict]]:
    """อ่าน hitlog.jsonl (มีแต่ attempt ที่ "hit" จริง = โจมตีสำเร็จ = โมเดลป้องกัน
    ไม่ได้) group ตาม (probe, detector) เก็บไม่เกิน MAX_EXAMPLES_PER_PROBE ต่อคู่ —
    เทียบเท่า promptfoo_parser.py ทำกับ MAX_EXAMPLES_PER_PLUGIN ให้รายงานรวมมี
    ความละเอียดระดับเดียวกันทั้ง 2 tool
    """
    examples: dict[tuple[str, str], list[dict]] = {}
    if not hitlog_path.exists():
        return examples

    with open(hitlog_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            probe = entry.get("probe", "")
            detector = entry.get("detector", "")
            key = (probe, detector)
            bucket = examples.setdefault(key, [])
            if len(bucket) >= MAX_EXAMPLES_PER_PROBE:
                continue

            prompt_turns = (entry.get("prompt") or {}).get("turns") or []
            prompt_text = _extract_hit_prompt_text(prompt_turns)
            response_text = (entry.get("output") or {}).get("text", "") or ""
            triggers = entry.get("triggers") or []
            reason = (
                "ตรวจพบคำ/รูปแบบที่ probe นี้เฝ้าระวัง: "
                + ", ".join(str(t) for t in triggers)
                if triggers
                else "ตรงเงื่อนไขที่ detector ของ probe นี้ตั้งไว้ว่าเป็นการโจมตีสำเร็จ"
            )

            bucket.append({
                "prompt": prompt_text,
                "response": response_text,
                "reason": reason,
            })

    return examples


def parse_garak_report(report_path: Path) -> list[dict]:
    report_path = Path(report_path)
    hit_examples = _load_hit_examples(_hitlog_path_for(report_path))

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
            detector = entry.get("detector", "")
            row = {
                "tool": "garak",
                "probe": probe,
                "detector": detector,
                "owasp_category": garak_probe_to_owasp(probe),
                "passed": entry.get("passed") or 0,
                "total": entry.get("total_evaluated") or entry.get("total_processed") or 0,
            }
            failures = hit_examples.get((probe, detector))
            if failures:
                row["failures"] = failures
            rows.append(row)
    return rows