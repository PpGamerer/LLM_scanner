"""
parsers/promptfoo_parser.py — แปลง promptfoo output json (จาก `redteam run -o out.json`)
เป็น schema กลาง

⚠️ ยังไม่ verify กับ output จริงบนเครื่อง (สถานะเดียวกับที่ promptmap2_parser.py เคยเป็น
ตอนเขียนใหม่ๆ — ดู comment ในไฟล์นั้น) โครงสร้างด้านล่างเขียนตาม official doc ที่อ่านมา
ณ ตอนเขียนไฟล์นี้ ต้องรันจริงแล้วเทียบ key ก่อนเชื่อ 100%

สมมติฐานโครงสร้าง (จาก doc):
    {
      "results": {
        "results": [
          {
            "success": bool,
            "testCase": {"metadata": {"pluginId": "pii:direct", ...}},
            ...
          },
          ...
        ]
      }
    }

ถ้า schema จริงไม่ตรงนี้ (เช่น เวอร์ชันใหม่กว่าเปลี่ยน key) ฟังก์ชัน _extract_results
ด้านล่างจะ raise KeyError พร้อม list key ระดับบนสุดที่เจอจริงในไฟล์ ช่วยให้แก้ path
ได้เร็วโดยไม่ต้องเดา — อย่าแก้เป็น "คืน [] เงียบๆ" เด็ดขาด เพราะจะเหมือนบั๊กที่เคย
เกิดกับ promptmap2_type_to_owasp mismatch ที่ผลหายไปเงียบๆ โดยไม่มี error เตือน
(ดู comment ใน owasp_mapping.py เรื่อง "harmful_content"/"bias")

polarity ของ "success": verify แล้วจากไฟล์ output จริง — success=True หมายถึง
"โมเดลป้องกันได้ ไม่โดนเจาะ" (ตรงข้ามกับ promptmap2 ที่ passed=False หมายถึงโดนเจาะสำเร็จ
— สอง tool นี้นิยาม polarity คนละทางกัน)

2026-09 (รอบสอง): เพิ่มการเก็บ "ตัวอย่างที่พัง" (prompt/response/เหตุผล) ต่อ plugin —
เดิม parser รวมแค่ตัวเลข pass/total ทิ้งรายละเอียดระดับ test case ไปทั้งที่ข้อมูลมีอยู่
ในไฟล์ output จริงครบ (prompt.raw, response.output, gradingResult.reason) ทำให้
security report อ่านไม่รู้ว่า "โมเดลพังยังไง" รู้แค่ตัวเลข — เก็บไว้ไม่เกิน
MAX_EXAMPLES_PER_PLUGIN ต่อ plugin กันรายงานบวมตอน numTests สูง (deep=50 ค่าเริ่มต้น
ปรับได้ผ่าน env var PROMPTFOO_DEEP_TESTS — ดู selector.py)
"""

import json
from collections import defaultdict
from pathlib import Path

from ..owasp_mapping import promptfoo_plugin_to_owasp

MAX_EXAMPLES_PER_PLUGIN = 3


def _extract_results(data: dict) -> list[dict]:
    """ลองหลาย path เท่าที่ doc/เวอร์ชันต่างๆ ของ promptfoo อาจใช้ กัน schema เปลี่ยน
    แล้ว parser คืน [] เงียบๆ (ผลหายไปโดยไม่มีใครรู้ — บทเรียนจาก bug อื่นในโปรเจกต์นี้
    ที่ string mismatch แล้วเงียบเข้า Uncategorized โดยไม่ error)
    """
    for path in (("results", "results"), ("results",)):
        node = data
        ok = True
        for key in path:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                ok = False
                break
        if ok and isinstance(node, list):
            return node

    raise KeyError(
        "หา list ผลลัพธ์ใน promptfoo output ไม่เจอ (ลองแล้ว data['results']['results'] "
        f"และ data['results']) — key ระดับบนสุดที่เจอจริงในไฟล์นี้: {list(data.keys())} "
        "— เปิดไฟล์ output ดูโครงสร้างจริงแล้วแก้ path ในฟังก์ชัน _extract_results นี้"
    )


def _plugin_id(entry: dict) -> str:
    """pluginId มักอยู่ใต้ testCase.metadata หรือ metadata ตรงๆ แล้วแต่เวอร์ชัน — เช็คทั้งคู่
    ไม่เจอเลยให้เป็น "unknown" (ไม่ raise เพราะแถวเดียวพังไม่ควรทำทั้ง scan ล้ม)
    """
    test_case = entry.get("testCase") or {}
    meta = test_case.get("metadata") or entry.get("metadata") or {}
    return meta.get("pluginId", "unknown")


def _extract_example(entry: dict) -> dict:
    """ดึงตัวอย่าง prompt/response/เหตุผล จาก 1 test case entry — verify field path
    จากไฟล์ output จริง (prompt.raw, response.output, gradingResult.reason) ใช้โชว์
    เป็นหลักฐานประกอบตัวเลข pass/fail ในรายงาน ไม่ใช่แค่สถิติเฉยๆ
    """
    prompt = (entry.get("prompt") or {}).get("raw", "")
    response = (entry.get("response") or {}).get("output", "")
    reason = (entry.get("gradingResult") or {}).get("reason", "")
    return {"prompt": prompt, "response": response, "reason": reason}


def parse_promptfoo_report(report_path: Path) -> list[dict]:
    with open(report_path, encoding="utf-8") as f:
        data = json.load(f)

    entries = _extract_results(data)

    # รวมทีละ plugin (เหมือน 1 probe ของ garak) เป็น 1 แถวต่อ plugin ในผลลัพธ์สุดท้าย
    # แทนที่จะเก็บทุก test case แยกแถว (มีได้เป็นสิบๆ test case ต่อ plugin ถ้า numTests สูง)
    # แต่เก็บตัวอย่างที่ "พัง" (success=False = โมเดลโดนเจาะสำเร็จ) แนบไว้ด้วย ไม่เกิน
    # MAX_EXAMPLES_PER_PLUGIN ต่อ plugin — สำคัญสำหรับ security report เพราะเลข pass/total
    # อย่างเดียวบอกไม่ได้ว่า "พังตรงไหน" ผู้อ่านรายงานต้องเห็นตัวอย่าง prompt จริง
    grouped: dict[str, dict] = defaultdict(lambda: {"passed": 0, "total": 0, "failures": []})
    for entry in entries:
        plugin_id = _plugin_id(entry)
        grouped[plugin_id]["total"] += 1
        if entry.get("success"):
            grouped[plugin_id]["passed"] += 1
        elif len(grouped[plugin_id]["failures"]) < MAX_EXAMPLES_PER_PLUGIN:
            grouped[plugin_id]["failures"].append(_extract_example(entry))

    rows = []
    for plugin_id, counts in grouped.items():
        rows.append({
            "tool": "promptfoo",
            "probe": plugin_id,
            "detector": "",
            "owasp_category": promptfoo_plugin_to_owasp(plugin_id),
            "passed": counts["passed"],
            "total": counts["total"],
            "failures": counts["failures"],
        })
    return rows