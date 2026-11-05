"""
report.py — สร้าง unified report รวมผลจากทุก tool (garak, promptmap2, ...) เป็นไฟล์เดียว
จัดกลุ่มตาม OWASP category

ไม่มี dependency ภายนอก (ไม่ใช้ Jinja2/matplotlib ฯลฯ) — string-based HTML + inline SVG
เปิดตรงๆ ในเบราว์เซอร์ได้เลย ไม่ต้องรัน server ก็ดูได้ (กราฟก็เป็น SVG ธรรมดา ไม่พึ่ง JS
library ภายนอกเลย ให้ตรงกับหลักการเดิมของไฟล์นี้) — ยกเว้น tool-filter ใน section
รายละเอียดต่อ category ที่ใช้ vanilla JS ล้วนๆ (ไม่มี framework/CDN) เพื่อให้กดสลับดูผล
แยกต่อ tool ได้โดยไม่ต้องโหลดหน้าใหม่

ใช้จาก 2 ที่:
  - selector.py -> save_reports()   เซฟ .html + .json + .csv ลงโฟลเดอร์ของแต่ละสแกน
  - ui/app.py   -> build_report_html() / build_report_csv()  โชว์ inline ใน Streamlit
                   + ให้ดาวน์โหลด

หมายเหตุ: ห้าม import จาก .selector ในไฟล์นี้ — selector.py import จากไฟล์นี้อยู่แล้ว
(import ย้อนกลับจะเกิด circular import) ฟังก์ชัน summarize/group ด้านล่างเลยเขียนแยก
เป็นของตัวเอง ไม่ใช้ร่วมกับ selector.summarize_by_owasp แม้ logic จะคล้ายกันก็ตาม

2026-09 (รอบ 3): เพิ่ม 3 อย่างตามที่ขอ —
  1. กราฟเปรียบเทียบ pass rate แยกต่อ tool ต่อ category (ไม่ใช่แค่ผลรวมปนกันแบบเดิม)
     สำคัญตอนที่ category หนึ่งมีมากกว่า 1 tool (cross-check) เพราะตารางสรุปเดิม
     บวก pass/total ของทุก tool เข้าด้วยกัน ทำให้ดูไม่ออกว่า tool ไหนดีกว่าตัวไหน
  2. สารบัญ (TOC) พร้อม anchor link — รายงานยาวขึ้นจากการเพิ่มกราฟ/ข้อแนะนำ
  3. ข้อแนะนำอัตโนมัติต่อ category — ผูก OWASP_MITIGATIONS (ความรู้ทั่วไปตาม OWASP LLM
     Top 10) เข้ากับ pass rate จริงที่สแกนได้ ถ้าต่ำกว่า threshold จะ flag ว่า
     "ควรแก้ไขเร่งด่วน" พร้อม bullet ข้อแนะนำเบื้องต้น (ไม่ใช่คำแนะนำเจาะจงกับโมเดล
     ที่สแกน แค่แนวทางทั่วไปตาม category — ผู้เขียนเล่มควรตีความเพิ่มเติมเอง)

2026-09 (fix): แก้ 2 จุด —
  1. TOC เดิมมี <a> ซ้อนใน <a> (ลิงก์ "รายละเอียดต่อ Category" ครอบ <ul> ของ cat_links
     ที่เป็น <a> อยู่แล้ว) ผิด HTML spec เบราว์เซอร์จะ auto-close ตัวนอกก่อนกำหนด
     ทำให้ลิงก์กดไม่ตรงตามที่ตั้งใจ — แยก <a> ตัวนอกออกจาก <ul> ไม่ให้ซ้อนกันแล้ว
  2. r.get("passed", 0) ไม่กันกรณี key มีอยู่จริงแต่ค่าเป็น None (parser บาง tool
     parse ไม่สำเร็จแล้วส่ง None มา) เปลี่ยนเป็น r.get("passed") or 0 ทุกจุดที่รวมผล
     กันพัง TypeError ตอนบวกเลข

2026-10 (รอบ formal): ผู้ใช้ขอรูปแบบที่ "ทางการกว่าเดิม ดูไม่เหมือน AI สร้าง" —
  ปรับเฉพาะ "หน้าตา" ไม่แตะ logic การคำนวณ/การ dedupe/การ expand dual-category ใดๆ:
    - เลิกใช้ emoji ในหัวข้อ, เลิกใช้ badge ทรงเม็ดยา (pill) สีสด → ใช้ tag ขอบซ้าย
      เป็นตัวหนังสือธรรมดาแทน (verdict อ่านเป็นคำ ไม่ต้องตีความจากสี)
    - เลิก card มุมโค้ง+shadow แบบ SaaS dashboard → ใช้กรอบเส้นบาง (hairline) ธรรมดา
      ไม่มีมุมโค้ง ไม่มีเงา ให้ดูเป็นเอกสารที่พิมพ์ได้จริงมากกว่าหน้าเว็บแอป
    - จัดโครงหน้าใหม่เป็นเอกสารมีเลขหัวข้อ (1. บทสรุปผู้บริหาร, 2. สรุปตาม OWASP ฯลฯ)
      แทนหัวข้อลอยๆ แบบ dashboard widget
    - เพิ่มช่อง "กรองตาม Tool" ในส่วนรายละเอียดต่อ category (ปุ่มกดสลับ ไม่ reload
      หน้า ใช้ vanilla JS ผูกกับ data-tool attribute บนแต่ละแถว) ตอบโจทย์ที่อยากได้
      เวอร์ชันกดดูผลแยกแต่ละ tool ได้ โดยไม่ต้องแยกเป็นหลายไฟล์/หลายหน้า
  เนื้อหา/คำเตือน/ตัวเลขทั้งหมด (_CATEGORY_NOTES, overall score caveat, tool plan,
  กราฟเปรียบเทียบ) ยังอยู่ครบ ย้ายตำแหน่งเข้าโครงเอกสารใหม่เท่านั้น

2026-10 (รอบอ้างอิงไฟล์ต้นฉบับ): unified report นี้เป็น "สรุปข้ามเครื่องมือ" เท่านั้น —
  จำกัดจำนวนตัวอย่างที่พัง (MAX_EXAMPLES_PER_PROBE/PLUGIN ใน parser แต่ละตัว) ไม่ใช่
  ตัวแทนแบบเต็มของ native report ของแต่ละ tool (garak's own interactive report,
  promptfoo's own eval dashboard มีทุก attempt/test case จริง) — เพิ่ม section ท้ายรายงาน
  ชี้กลับไปไฟล์ต้นฉบับ/ไฟล์ดิบของแต่ละ tool ที่ถูกเรียกใช้จริง (ตาม tool_plan) ให้คนอ่าน
  ไปไล่ดูรายละเอียดเต็มได้เอง ไม่กระทบ logic การคำนวณใดๆ เป็นแค่ลิงก์เพิ่ม — ลิงก์เป็น
  relative path (ไฟล์ชื่อเฉยๆ ไม่มี path นำหน้า) เพราะไฟล์พวกนี้ถูกเซฟไว้โฟลเดอร์เดียวกับ
  report.html เสมอ (ดู runner แต่ละตัว: garak_runner.py/promptfoo_runner.py/
  promptmap2_runner.py ใช้ output_dir เดียวกับที่ save_reports() ใช้) — ถ้า build_report_html()
  ถูกเรียกพร้อม output_dir (เช่นจาก save_reports()) จะเช็คว่าไฟล์มีอยู่จริงก่อนโชว์ลิงก์
  ด้วย ถ้าไม่ได้ส่ง output_dir มา (เช่น ui/app.py โชว์ inline ก่อนเซฟไฟล์จริง) จะโชว์ลิงก์
  เฉยๆ โดยไม่เช็ค (optimistic) — ชื่อไฟล์คำนวณจาก safe_model slug เดียวกับที่ runner แต่ละ
  ตัวใช้ (replace ":" "/" "\\" เป็น "_") ถ้า runner เปลี่ยน naming pattern ต้องแก้คู่กันที่นี่ด้วย
"""

import csv
import html
import io
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .owasp_mapping import owasp_label

# ============================================================================
# ข้อแนะนำทั่วไปต่อ OWASP category — ความรู้มาตรฐานตาม OWASP LLM Top 10 (2025)
# ไม่ใช่คำแนะนำที่วิเคราะห์เฉพาะผลสแกนจริง แค่แนวทางเริ่มต้นให้ผู้อ่านรายงานเอาไปต่อยอด
# ============================================================================
OWASP_MITIGATIONS = {
    "LLM01": [
        "กำหนดขอบเขต system prompt ให้ชัดเจน พร้อมตัวอย่างการปฏิเสธคำสั่งนอกขอบเขต",
        "แยก user input กับ instruction ด้วย delimiter หรือ structured format ไม่ปนกัน",
        "ตรวจสอบ output ก่อนส่งกลับ user ด้วย canary/leak detector อีกชั้น",
        "พิจารณา guardrail แยกชั้นจริง ไม่พึ่งแค่ safety alignment ที่ฝังมากับตัวโมเดล",
    ],
    "LLM02": [
        "Redact/mask ข้อมูลอ่อนไหวก่อนป้อนเข้า context หรือบันทึก log",
        "จำกัดขอบเขตข้อมูลที่ retrieval/RAG ดึงมาได้ต่อ session/ต่อ user",
        "ตรวจ output ด้วย PII detector ก่อนส่งกลับเสมอ",
        "แยกมองคนละมุม: ข้อมูลที่โมเดล \"จำ\" จาก training กับข้อมูลที่ \"รั่ว\" จาก runtime "
        "context ต้องแก้คนละวิธี",
    ],
    "LLM06": [
        "จำกัด permission ของ tool/action ที่ agent เรียกได้ตามหลัก least privilege",
        "ต้องมี human-in-the-loop ก่อน action ที่ irreversible (ลบไฟล์ ส่งอีเมล โอนเงิน ฯลฯ)",
        "Log ทุก tool call พร้อมเหตุผลประกอบ ให้ audit ย้อนหลังได้จริง",
    ],
    "LLM07": [
        "อย่าฝัง secret (API key, internal logic) ไว้ใน system prompt ตรงๆ",
        "ใส่ canary phrase ใน system prompt เพื่อตรวจว่าหลุดออกมาไหม",
        "ย้าย secret ที่จำเป็นไปเก็บฝั่ง server เท่านั้น ไม่ส่งเข้า context ที่โมเดลเห็นได้",
    ],
    "LLM09": [
        "ใช้ RAG อ้างอิงแหล่งข้อมูลที่ verify ได้ แทนการให้โมเดลตอบจาก parametric knowledge ล้วนๆ",
        "ใส่ confidence/uncertainty indicator ในคำตอบที่มีความเสี่ยงข้อมูลผิดสูง",
        "ให้คนตรวจทานคำตอบก่อนใช้จริงในบริบทสำคัญ (การแพทย์ กฎหมาย การเงิน)",
    ],
    "LLM05": [
        "Sanitize/escape output ก่อนส่งให้ client render เสมอ (โดยเฉพาะ markdown/HTML ที่ฝัง"
        " link หรือ image)",
        "ตั้ง Content-Security-Policy กัน script/exfil ผ่าน markdown image ที่ชี้ออกนอกโดเมน",
        "ห้าม eval/exec output ของโมเดลตรงๆ (SQL, shell, template engine เช่น Jinja) ต้องผ่าน"
        " parameterized query/sandbox เสมอ",
        "ตรวจ output ก่อน render ด้วย allowlist ของ tag/attribute ที่อนุญาต ไม่ใช่ blocklist",
    ],
}

# threshold ตัดสิน verdict ต่อ category — ใช้ค่าเดียวกับ _rate_color ด้านล่างเพื่อให้
# tag สีตรงกับสีในกราฟ/ตารางเป๊ะ ไม่ต้องคิดเลข threshold แยกอีกชุด
_VERDICT_GOOD = "ป้องกันได้ดี ยังควรสุ่มตรวจซ้ำเป็นระยะ"
_VERDICT_MID = "ปานกลาง ควรติดตามและพิจารณาแก้ไขเพิ่มเติม"
_VERDICT_BAD = "ควรแก้ไขเร่งด่วน pass rate ต่ำกว่าเกณฑ์ที่ยอมรับได้"


def _dedupe_probe_stats(results: list[dict]) -> list[dict]:
    """ใช้เฉพาะตอนคำนวณสรุป — ไม่กระทบตาราง detail
    (คำอธิบายเต็มดูจากที่ผมส่งให้รอบก่อน)"""
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for r in results:
        key = (
            r.get("tool") or "unknown",
            r.get("owasp_category") or "Uncategorized",
            r.get("probe") or "",
        )
        grouped[key].append(r)

    deduped = []
    for (tool, cat, probe), rows in grouped.items():
        totals = [r.get("total") or 0 for r in rows]
        passeds = [r.get("passed") or 0 for r in rows]
        total = max(totals) if totals else 0
        passed = round(sum(passeds) / len(passeds)) if passeds else 0
        deduped.append({
            "tool": tool,
            "owasp_category": cat,
            "probe": probe,
            "passed": passed,
            "total": total,
        })
    return deduped


def _summarize_by_owasp(results: list[dict]) -> dict[str, dict]:
    """ผลรวมทุก tool ปนกันต่อ category — ใช้โชว์ headline score รวมเท่านั้น
    ห้ามใช้ตัวเลขจากตรงนี้มาสรุปว่า tool ไหนดีกว่าตัวไหน (ดู
    _summarize_by_category_tool ด้านล่างสำหรับอันนั้น)"""
    results = _dedupe_probe_stats(results)
    summary = defaultdict(lambda: {"pass": 0, "total": 0})
    for r in results:
        cat = r.get("owasp_category") or "Uncategorized"
        # ใช้ `or 0` แทน .get(key, 0) เพราะ .get แค่กัน key หาย ไม่กันกรณี key มีอยู่
        # แต่ค่าเป็น None (parser บาง tool parse ไม่สำเร็จแล้วส่ง None มาจริงๆ)
        summary[cat]["pass"] += r.get("passed") or 0
        summary[cat]["total"] += r.get("total") or 0
    return dict(summary)


def _summarize_by_category_tool(results: list[dict]) -> dict[str, dict[str, dict]]:
    """เหมือน _summarize_by_owasp แต่แยกต่อ tool ด้วย — ใช้วาดกราฟเปรียบเทียบ
    tool ต่อ tool ภายใน category เดียวกัน (ตอบโจทย์ cross-check ที่ตารางสรุปเดิม
    บวกปนกันจนดูไม่ออก)"""
    results = _dedupe_probe_stats(results)
    summary: dict[str, dict[str, dict]] = defaultdict(lambda: defaultdict(lambda: {"pass": 0, "total": 0}))
    for r in results:
        cat = r.get("owasp_category") or "Uncategorized"
        tool = r.get("tool") or "unknown"
        summary[cat][tool]["pass"] += r.get("passed") or 0
        summary[cat][tool]["total"] += r.get("total") or 0
    return {cat: dict(tools) for cat, tools in summary.items()}


def _group_by_owasp(results: list[dict]) -> dict[str, list[dict]]:
    grouped = defaultdict(list)
    for r in results:
        cat = r.get("owasp_category") or "Uncategorized"
        grouped[cat].append(r)
    return dict(grouped)


def _pass_rate(passed: int, total: int) -> float:
    return round(passed / total * 100, 1) if total else 0.0


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _rate_color(rate: float) -> str:
    if rate >= 70:
        return "#2F6F4E"  # เขียวเอกสาร — ป้องกันได้ดี
    if rate >= 40:
        return "#8A5A12"  # น้ำตาลอำพัน — กลางๆ
    return "#9E2F2A"      # แดงอิฐ — ป้องกันไม่ค่อยได้


def _rate_verdict(rate: float) -> str:
    if rate >= 70:
        return _VERDICT_GOOD
    if rate >= 40:
        return _VERDICT_MID
    return _VERDICT_BAD


def _rate_bar(rate: float) -> str:
    """bar บอก pass rate — คงรูปแบบ bar ไว้ (อ่านไวกว่าตัวเลขล้วนๆ) แต่เปลี่ยนจาก
    bar กลมมน สีสด ให้เป็นแท่งเหลี่ยม เส้นขอบบาง ให้เข้ากับโทนเอกสารทางการ"""
    color = _rate_color(rate)
    width = max(rate, 2)  # กัน bar หายไปเลยตอน 0%
    return (
        '<span class="bar-wrap">'
        '<span class="bar-track">'
        f'<span class="bar-fill" style="width:{width}%; background:{color};"></span>'
        "</span>"
        f'<span class="bar-label">{rate}%</span>'
        "</span>"
    )


def _verdict_class(rate: float) -> str:
    return "good" if rate >= 70 else ("mid" if rate >= 40 else "bad")


def _verdict_tag_label(rate: float) -> str:
    return "ผ่านเกณฑ์" if rate >= 70 else ("เฝ้าระวัง" if rate >= 40 else "เร่งด่วน")


def _wrap_table(table_html: str) -> str:
    """ครอบ <table> ด้วย div ที่ scroll แนวนอนได้เฉพาะตัวตาราง — กันตารางหลายคอลัมน์
    (เช่น ตารางรายละเอียดที่มี 6 คอลัมน์) ดันทั้งหน้า overflow แนวนอนตอนเปิดบนจอมือถือ
    (ถ้าไม่ครอบ ตัวหน้าทั้งหน้าจะเลื่อนขวาได้ คอลัมน์ขวาสุดเช่น Pass Rate จะหลุดจอไปเลย
    แทนที่จะแค่ scroll ในกรอบตาราง)"""
    return f'<div class="table-scroll">{table_html}</div>'


def _verdict_tag(rate: float) -> str:
    """tag ข้อความล้วน ขอบซ้ายสี แทน pill badge สีพื้นเต็ม — อ่านได้แม้พิมพ์ขาวดำ
    (สีเป็นตัวช่วย ไม่ใช่ช่องทางเดียวในการสื่อความหมาย)"""
    cls = _verdict_class(rate)
    label = _verdict_tag_label(rate)
    return f'<span class="tag {cls}">{label}</span>'


# ============================================================================
# CSS — โทนเอกสารทางการ: ตัวอักษร serif สำหรับหัวเรื่อง/เลขหัวข้อ, sans สำหรับเนื้อหา
# (เนื้อหาส่วนใหญ่เป็นภาษาไทย ฟอนต์ serif ระบบส่วนใหญ่ไม่มี glyph ไทยครบ จึงใช้ serif
# เฉพาะโครงเอกสาร/ตัวเลข/คำอังกฤษ ส่วนข้อความไทยทั้งหมดใช้ sans เพื่อให้เรนเดอร์ถูกต้อง
# ทุกเครื่อง) ไม่มีมุมโค้ง ไม่มีเงา ไม่มี badge ทรงเม็ดยา ไม่มี emoji — ให้ตรงข้ามกับ
# หน้าตา "SaaS dashboard" เดิม
# ============================================================================
_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
html { overflow-x: hidden; }
body {
  font-family: "Segoe UI", -apple-system, "Noto Sans Thai", "Leelawadee UI", Tahoma, sans-serif;
  max-width: 900px; margin: 0 auto; padding: 3rem 1.5rem 5rem;
  color: #1C2B38; line-height: 1.6; background: #FFFFFF;
  font-variant-numeric: tabular-nums;
  overflow-x: hidden;
}

/* ---- Table scroll container: ตารางกว้างเกินจอ (มือถือ) ให้ scroll แนวนอนเฉพาะ
   กรอบตาราง ไม่ดันทั้งหน้าให้ scroll ขวา (คอลัมน์ขวาสุดจะได้ไม่หลุดจอไปเลย) ---- */
.table-scroll {
  overflow-x: auto; -webkit-overflow-scrolling: touch; margin: 0.8rem 0 1.2rem;
  /* เงาจางที่ขอบขวา บอกเป็นนัยว่า scroll ต่อได้ (เฉพาะตอนยังไม่เลื่อนสุด) ไม่ใช้ JS
     ใช้ trick background-attachment: local วาง 2 ชั้นคู่กับพื้นหลังตาราง */
  background:
    linear-gradient(to right, #FFFFFF 30%, rgba(255,255,255,0)) 0 0,
    linear-gradient(to right, rgba(255,255,255,0), #FFFFFF 70%) 100% 0,
    linear-gradient(to right, rgba(28,43,56,0.12), rgba(28,43,56,0)) 0 0,
    linear-gradient(to right, rgba(28,43,56,0), rgba(28,43,56,0.12)) 100% 0;
  background-repeat: no-repeat;
  background-size: 40px 100%, 40px 100%, 14px 100%, 14px 100%;
  background-attachment: local, local, scroll, scroll;
}
.table-scroll table { margin: 0; min-width: 480px; }

/* ---- Cover block ---- */
.cover { border-bottom: 2px solid #1C2B38; padding-bottom: 1.4rem; margin-bottom: 2rem; }
.cover .doc-kind { font-size: 0.82rem; color: #4A5565; margin: 0 0 0.3rem; }
.cover h1 {
  font-family: Georgia, "Times New Roman", serif; font-weight: 700;
  font-size: 1.9rem; margin: 0 0 0.6rem; color: #1C2B38;
}
.cover .meta { color: #4A5565; font-size: 0.9rem; margin: 0; }

/* ---- Section headings: numbered, serif numeral + sans label ---- */
h2.section {
  font-size: 1.25rem; margin: 2.6rem 0 1rem; padding-bottom: 0.4rem;
  border-bottom: 1px solid #D7DBE1; color: #1C2B38; font-weight: 600;
}
h2.section .num { font-family: Georgia, "Times New Roman", serif; color: #4A5565;
                   font-weight: 700; margin-right: 0.5rem; }
h3 { font-size: 1.02rem; margin: 1.4rem 0 0.6rem; color: #1C2B38; font-weight: 600; }
h4 { font-size: 0.95rem; margin: 1rem 0 0.5rem; color: #1C2B38; font-weight: 600; }

p { margin: 0.6rem 0; }
.meta { color: #4A5565; font-size: 0.88rem; }
.empty { color: #4A5565; font-style: italic; }

/* ---- Target / cover info list ---- */
ul.target-info { list-style: none; margin: 0; padding: 0; border: 1px solid #D7DBE1; }
ul.target-info li {
  padding: 0.5rem 0.9rem; border-bottom: 1px solid #D7DBE1; font-size: 0.92rem;
}
ul.target-info li:last-child { border-bottom: none; }
ul.target-info strong { color: #1C2B38; display: inline-block; min-width: 110px; }

/* ---- Tables: hairline borders, no rounding, no shadow ---- */
table { width: 100%; border-collapse: collapse; margin: 0.8rem 0 1.2rem; font-size: 0.92rem; }
caption { text-align: left; font-size: 0.85rem; color: #4A5565; padding-bottom: 0.4rem; }
th, td { text-align: left; padding: 0.55rem 0.7rem; border: 1px solid #D7DBE1; vertical-align: top; }
th { background: #F6F7F9; font-weight: 600; color: #1C2B38; }
tbody tr:nth-child(even) td { background: #FBFBFC; }

/* ---- Progress bar: square, hairline, inline with label ---- */
.bar-wrap { display: inline-flex; align-items: center; white-space: nowrap; }
.bar-track {
  position: relative; display: inline-block; vertical-align: middle;
  background: #EDEFF2; border: 1px solid #D7DBE1; height: 12px; width: 120px;
  overflow: hidden; margin-right: 0.5rem; flex: none;
}
.bar-fill { display: block; height: 100%; }
.bar-label { font-size: 0.85rem; color: #1C2B38; }

/* ---- Overall score block ---- */
.overall {
  border: 1px solid #D7DBE1; border-left: 4px solid #1C2B38; padding: 1rem 1.3rem;
  margin: 0.4rem 0 1.4rem; display: flex; align-items: baseline; gap: 0.9rem; flex-wrap: wrap;
}
.overall .score {
  font-family: Georgia, "Times New Roman", serif; font-size: 2.1rem; font-weight: 700;
}
.overall .label { color: #4A5565; font-size: 0.92rem; }
.note {
  border: 1px solid #D7DBE1; background: #F6F7F9; padding: 0.7rem 1rem;
  margin: 0.6rem 0 1rem; font-size: 0.87rem; color: #1C2B38;
}
.note .note-label { font-weight: 600; margin-right: 0.25rem; }

/* ---- Table of contents ---- */
.toc { border: 1px solid #D7DBE1; padding: 1rem 1.3rem; margin: 1.2rem 0 2rem; }
.toc .toc-title {
  font-weight: 600; font-size: 0.85rem; letter-spacing: 0.02em; color: #1C2B38;
  margin-bottom: 0.5rem; display: block;
}
.toc ol { margin: 0; padding-left: 1.3rem; }
.toc ol ol { padding-left: 1.3rem; margin: 0.2rem 0; }
.toc li { margin: 0.2rem 0; }
.toc a { color: #2B4A6B; text-decoration: none; }
.toc a:hover { text-decoration: underline; }

/* ---- Comparison chart block ---- */
.chart-block { border: 1px solid #D7DBE1; padding: 0.9rem 1.2rem; margin: 0.9rem 0; }
.chart-block h4 { margin: 0 0 0.6rem; }
.chart-block svg { width: 100%; height: auto; display: block; }

/* ---- Recommendation blocks ---- */
.rec-card {
  border: 1px solid #D7DBE1; border-left: 4px solid #D7DBE1;
  padding: 0.9rem 1.2rem; margin: 0.9rem 0;
}
.rec-card.good { border-left-color: #2F6F4E; }
.rec-card.mid  { border-left-color: #8A5A12; }
.rec-card.bad  { border-left-color: #9E2F2A; }
.rec-card .verdict-line {
  font-weight: 600; margin-bottom: 0.3rem; display: flex; align-items: center;
  gap: 0.6rem; flex-wrap: wrap;
}
.rec-card ul { margin: 0.5rem 0 0; padding-left: 1.3rem; }
.rec-card li { margin: 0.2rem 0; }

/* ---- Verdict tag: text + left rule, not a pill ---- */
.tag {
  font-size: 0.78rem; font-weight: 600; padding: 0.08rem 0.5rem 0.08rem 0.55rem;
  border-left: 3px solid #4A5565; color: #1C2B38;
}
.tag.good { border-left-color: #2F6F4E; }
.tag.mid  { border-left-color: #8A5A12; }
.tag.bad  { border-left-color: #9E2F2A; }

/* ---- Category detail ---- */
.category-block { margin: 1.4rem 0; }
.category-block .cat-head {
  display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap;
  gap: 0.5rem; border-bottom: 1px solid #1C2B38; padding-bottom: 0.4rem; margin-bottom: 0.6rem;
}
.category-block .cat-head h3 { margin: 0; border: none; }
.category-block .count { font-weight: 400; color: #4A5565; font-size: 0.85rem; }

/* ---- Tool filter control (vanilla JS, no reload) ---- */
.tool-filter {
  display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem;
  margin: 0.6rem 0 1rem; font-size: 0.85rem;
}
.tool-filter .filter-label { color: #4A5565; margin-right: 0.2rem; }
.tool-filter button {
  font: inherit; font-size: 0.85rem; background: #FFFFFF; color: #1C2B38;
  border: 1px solid #D7DBE1; padding: 0.3rem 0.8rem; cursor: pointer;
}
.tool-filter button:hover { background: #F6F7F9; }
.tool-filter button.active { background: #1C2B38; color: #FFFFFF; border-color: #1C2B38; }
tr[data-tool] { transition: none; }
tr.tool-row-hidden { display: none; }

/* ---- Reference file list: filename + description on its own line (ไม่ใช้
   em dash คั่น ให้สองส่วนแยกกันด้วย layout แทน) ---- */
.ref-desc { display: inline-block; margin-top: 0.15rem; color: #4A5565; font-size: 0.85rem; }

/* ---- Failure examples (collapsible) ---- */
.examples { margin: 0.4rem 0 0; }
.examples summary {
  cursor: pointer; color: #2B4A6B; font-size: 0.85rem; font-weight: 600;
}
.example {
  border: 1px solid #D7DBE1; border-left: 3px solid #9E2F2A;
  padding: 0.6rem 0.9rem; margin: 0.5rem 0; font-size: 0.85rem; background: #FBFBFC;
}
.example p { margin: 0.25rem 0; white-space: pre-wrap; word-break: break-word; }
.example .field-label { font-weight: 600; color: #4A5565; }

details > summary { cursor: pointer; }
footer.doc-footer {
  margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #D7DBE1;
  font-size: 0.8rem; color: #4A5565;
}
"""

_JS = """
(function () {
  function setupFilter(filterEl) {
    var targetId = filterEl.getAttribute('data-target');
    var table = document.getElementById(targetId);
    if (!table) return;
    var rows = table.querySelectorAll('tr[data-tool]');
    var buttons = filterEl.querySelectorAll('button[data-tool-value]');
    buttons.forEach(function (btn) {
      btn.addEventListener('click', function () {
        var value = btn.getAttribute('data-tool-value');
        buttons.forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
        rows.forEach(function (row) {
          var rowTool = row.getAttribute('data-tool');
          var show = value === '__all__' || rowTool === value;
          row.classList.toggle('tool-row-hidden', !show);
        });
      });
    });
  }
  document.querySelectorAll('.tool-filter').forEach(setupFilter);
})();
"""


def _render_toc(sections: list[tuple[str, str]], categories: list[str]) -> str:
    """sections: [(anchor_id, label), ...] ตามลำดับหัวข้อหลักที่มีจริงในรายงานนี้
    (ข้ามหัวข้อที่ไม่มีเนื้อหา เช่น ไม่มีผลเปรียบเทียบ tool ก็ไม่โชว์ลิงก์)"""
    items = []
    for i, (anchor, label) in enumerate(sections, start=1):
        if anchor == "category-detail":
            cat_items = "".join(
                f'<li><a href="#cat-{_esc(cat)}">{_esc(owasp_label(cat))}</a></li>'
                for cat in categories
            ) or '<li class="empty">ไม่มีผลลัพธ์</li>'
            items.append(
                f'<li><a href="#{anchor}">{_esc(label)}</a>'
                f'<ol type="a">{cat_items}</ol></li>'
            )
        else:
            items.append(f'<li><a href="#{anchor}">{_esc(label)}</a></li>')
    return f"""
    <nav class="toc">
      <span class="toc-title">สารบัญ</span>
      <ol>{''.join(items)}</ol>
    </nav>
    """


def _render_summary_table(summary: dict) -> str:
    if not summary:
        return '<p class="empty">ไม่มีผลลัพธ์</p>'
    rows = []
    for cat in sorted(summary):
        s = summary[cat]
        rate = _pass_rate(s["pass"], s["total"])
        rows.append(
            f"<tr><td>{_esc(owasp_label(cat))}</td><td>{s['pass']}</td>"
            f"<td>{s['total']}</td><td>{_rate_bar(rate)}</td></tr>"
        )
    table_html = (
        '<table><caption>ตาราง 2.1: สรุปผลตาม OWASP category '
        "(รวมทุก tool ที่ทดสอบ category นั้น)</caption>"
        "<thead><tr><th>OWASP Category</th><th>Pass (โดยประมาณ)</th>"
        "<th>Total (นับต่อ probe แล้ว)</th><th>Pass Rate โดยประมาณ</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )
    return (
        f"{_wrap_table(table_html)}"
        '<p class="meta">Pass/Total dedup ต่อ probe แล้ว probe ที่เช็คด้วยหลาย detector'
        " นับ total แค่ครั้งเดียว ไม่บวกซ้ำ Pass เป็นค่าเฉลี่ยจากทุก detector ของ probe"
        " นั้น เป็นค่าประมาณ ไม่ใช่ตัวเลขวัดตรงระดับ prompt รายตัว</p>"
    )


def _overall_score(summary: dict) -> str:
    """headline number รวมทุก category — เผื่ออยากดูภาพรวมไวๆ ก่อนลงรายละเอียด"""
    total_pass = sum(s["pass"] for s in summary.values())
    total_all = sum(s["total"] for s in summary.values())
    rate = _pass_rate(total_pass, total_all)
    color = _rate_color(rate)
    return (
        '<div class="overall">'
        f'<span class="score" style="color:{color};">{rate}%</span>'
        f'<span class="label">Overall pass rate โดยประมาณ ({total_pass}/{total_all} probe'
        " หลัง dedup ต่อ detector)</span>"
        "</div>"
        '<div class="note"><span class="note-label">หมายเหตุ:</span>'
        "ถ้าเลือกหลาย OWASP category พร้อมกัน ตัวเลขนี้อาจนับ probe"
        " ที่ตรงมากกว่า 1 category ซ้ำได้ (เช่น web_injection/exploitation ที่นับทั้ง"
        " LLM05 และ LLM02, divergence.Repeat ที่นับทั้ง LLM02 และ LLM10) เพราะ probe"
        " เดียวกันถูก duplicate ไปอยู่หลาย category ตาม concept ที่ตรงจริง"
        " ต้องการตัวเลขที่แม่นยำกว่านี้ ให้ดูรายละเอียดต่อ category ด้านล่างแทน</div>"
    )


def _render_tool_plan_table(tool_plan: dict) -> str:
    if not tool_plan:
        return '<p class="empty">ไม่มีข้อมูล tool plan</p>'
    rows = []
    for tool, cats in tool_plan.items():
        cat_labels = ", ".join(owasp_label(c) for c in cats)
        rows.append(f"<tr><td>{_esc(tool)}</td><td>{_esc(cat_labels)}</td></tr>")
    return _wrap_table(
        "<table><thead><tr><th>Tool</th><th>ทดสอบหมวด</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _svg_comparison_chart(tool_rates: dict[str, dict], chart_w: int = 680) -> str:
    """วาด bar chart แนวนอน 1 แถวต่อ tool ภายใน category เดียว — ให้เห็นชัดว่า
    tool ไหน detection/pass rate สูง/ต่ำกว่ากันเท่าไหร่ ไม่ต้องไล่อ่านตัวเลขในตาราง detail
    เอง (แก้ปัญหาที่ตารางสรุปเดิมบวก pass/total ของทุก tool ปนกันจนดูไม่ออก)

    tool_rates: {"garak": {"pass": 8, "total": 10}, "promptfoo": {"pass": 1, "total": 6}}
    """
    tools = sorted(tool_rates)
    row_h = 32
    label_w = 120
    bar_area_w = chart_w - label_w - 90
    height = row_h * len(tools) + 6

    rows_svg = []
    for i, tool in enumerate(tools):
        s = tool_rates[tool]
        rate = _pass_rate(s["pass"], s["total"])
        # clamp กัน bar ล้นกรอบถ้าข้อมูลต้นทางผิดปกติจน passed > total (rate > 100)
        rate_clamped = min(rate, 100.0)
        color = _rate_color(rate)
        y = i * row_h + 6
        bar_w = max(rate_clamped / 100 * bar_area_w, 1)
        rows_svg.append(f"""
        <text x="0" y="{y + 15}" font-size="12.5" fill="#1C2B38"
              font-family="Segoe UI, -apple-system, sans-serif">{_esc(tool)}</text>
        <rect x="{label_w}" y="{y}" width="{bar_area_w}" height="18"
              fill="#EDEFF2" stroke="#D7DBE1" stroke-width="1" />
        <rect x="{label_w}" y="{y}" width="{bar_w}" height="18" fill="{color}" />
        <text x="{label_w + bar_area_w + 8}" y="{y + 14}" font-size="12" fill="#1C2B38"
              font-family="Segoe UI, -apple-system, sans-serif">
          {rate}% ({s['pass']}/{s['total']})
        </text>
        """)

    return f"""
    <svg viewBox="0 0 {chart_w} {height}" xmlns="http://www.w3.org/2000/svg">
      {''.join(rows_svg)}
    </svg>
    """


def _render_tool_comparison(cat_tool_summary: dict[str, dict[str, dict]]) -> str:
    """เปรียบเทียบ pass rate ต่อ tool แยกตาม category — ใช้แค่ตอน category
    นั้นมีมากกว่า 1 tool cross-check กัน (category ที่มี tool เดียวข้ามไป ไม่มีอะไรให้เทียบ)"""
    multi_tool_cats = {
        cat: tools for cat, tools in cat_tool_summary.items() if len(tools) > 1
    }
    if not multi_tool_cats:
        return ""

    blocks = []
    for cat in sorted(multi_tool_cats):
        chart = _svg_comparison_chart(multi_tool_cats[cat])
        blocks.append(
            f'<div class="chart-block"><h4>{_esc(owasp_label(cat))}</h4>{chart}</div>'
        )

    return (
        '<p class="meta">เฉพาะ category ที่มีมากกว่า 1 tool ยิงคู่กัน (cross-check) '
        "pass rate ต่อ tool ในตารางนี้แยกเป็นรายตัว ต่างจากตาราง 2.1 ด้านบนที่บวกทุก tool "
        "ปนกันเป็นก้อนเดียว</p>" + "".join(blocks)
    )


def _render_recommendations(summary: dict) -> str:
    if not summary:
        return ""

    cards = []
    for cat in sorted(summary):
        s = summary[cat]
        rate = _pass_rate(s["pass"], s["total"])
        verdict = _rate_verdict(rate)
        css_class = _verdict_class(rate)

        mitigations = OWASP_MITIGATIONS.get(cat)
        mitigation_html = (
            "<ul>" + "".join(f"<li>{_esc(m)}</li>" for m in mitigations) + "</ul>"
            if mitigations
            else '<p class="empty">ยังไม่มีข้อแนะนำมาตรฐานสำหรับหมวดนี้ในระบบ</p>'
        )

        cards.append(f"""
        <div class="rec-card {css_class}">
          <div class="verdict-line">
            {_esc(owasp_label(cat))}
            {_verdict_tag(rate)}
          </div>
          <p>{_esc(verdict)} (pass rate {rate}%, {s['pass']}/{s['total']})</p>
          {mitigation_html}
        </div>
        """)

    return (
        '<p class="meta">แนวทางทั่วไปตาม OWASP LLM Top 10 อิงจาก pass rate รวมของแต่ละ '
        "category เป็นจุดเริ่มต้นเท่านั้น ไม่ใช่บทวิเคราะห์เจาะจงโมเดลหรือระบบที่สแกน "
        "ผู้เขียนรายงานควรตีความเพิ่มเติมประกอบผลดิบในหัวข้อถัดไป</p>"
        + "".join(cards)
    )


# หมายเหตุเตือนผู้อ่านรายงานที่เคยอยู่แค่ใน comment ของ owasp_mapping.py/แผนเทียบ tool
# ของทีม เอามาโชว์ในรายงานจริงด้วย (2026-09 รอบเก้า) กันคนอ่านรวมตัวเลขผิดวิธี —
# ต่อ 1 category เท่านั้น (ไม่ผูกกับ tool/probe ตัวใดตัวหนึ่ง)
_CATEGORY_NOTES = {
    "LLM02": (
        "ตารางนี้รวมหลาย concept ที่ไม่ใช่เมตริกเดียวกัน leakreplay วัด memorization "
        "(ข้อมูลที่โมเดลจำจาก training) ส่วน pii:*/web_injection.*/exploitation วัด "
        "runtime leakage (ข้อมูลที่รั่วจาก context หรือ output ตอนใช้งานจริง ผ่านการ "
        "render markdown/image หรือผ่านโค้ดที่ execute ได้) web_injection และ "
        "exploitation ทั้งคู่ถูกนับซ้ำกับ LLM05 ด้วย เพราะเป็น probe เดียวกันที่ตรง "
        "concept ทั้งสองหมวด (ดูโน้ต LLM05 ด้านล่างประกอบ) ควรดูแยกเป็นแถวต่อ probe "
        "ด้านล่าง ไม่ควรตีความ pass rate รวมเป็นตัวเดียว"
    ),
    "LLM05": (
        "web_injection และ exploitation ที่โผล่ในตารางนี้คือ probe เดียวกันกับที่ "
        "นับใน LLM02 ด้วย (verify จาก garak tag metadata แล้วว่าทุก subclass ของทั้ง 2 "
        "family ตรง concept ทั้ง LLM05 \"Improper Output Handling\" และ LLM02 "
        "\"Sensitive Info Disclosure\" พร้อมกัน แยกเป็น LLM05 ล้วนไม่ได้) ถ้าสแกนทั้ง "
        "LLM05 และ LLM02 พร้อมกัน probe เหล่านี้จะถูกนับ 2 ครั้งใน Overall score "
        "ด้านบนเพจ (ดูคำเตือนใต้ Overall score ประกอบ) นี่ไม่ใช่บั๊ก แต่เป็นธรรมชาติของ "
        "probe ที่ตรงมากกว่า 1 OWASP category จริง"
    ),
    "LLM06": (
        "ตารางนี้อาจรวมได้ถึง 5 plugin (excessive-agency, overreliance, imitation, "
        "hijacking, rbac) แต่แผนเปรียบเทียบ Garak กับ Promptfoo/PyRIT ของทีมใช้แค่ "
        "excessive-agency เป็นคู่เทียบหลัก ถ้าจะรายงานตัวเลขลงเล่ม ให้ดูแถว "
        "excessive-agency แยกด้านล่าง ไม่ใช่ผลรวมทั้งตาราง"
    ),
    "LLM10": (
        "divergence.RepeatedToken (Denial-of-Service/resource exhaustion) กับ "
        "divergence.Repeat/divergent-repetition (data-leak/model-theft) เป็นคนละ concept "
        "ที่ถูกรวมในเลข OWASP เดียวกัน เพราะฉบับ 2025 ยุบ 2 หมวดเก่าเข้าด้วยกัน "
        "ต้องรายงานแยก 2 เมตริก ห้ามรวมเป็นตัวเดียว (ดูแถวต่อ probe ด้านล่าง)"
    ),
}


def _render_category_detail(cat: str, rows: list[dict], idx: int) -> str:
    table_id = f"detail-table-{_esc(cat)}"
    tools_in_cat = sorted({r.get("tool") or "unknown" for r in rows})

    body_rows = []
    for r in rows:
        tool = r.get("tool") or "unknown"
        rate = _pass_rate(r.get("passed") or 0, r.get("total") or 0)
        body_rows.append(
            f'<tr data-tool="{_esc(tool)}"><td>{_esc(tool)}</td><td>{_esc(r.get("probe"))}</td>'
            f'<td>{_esc(r.get("detector") or "-")}</td><td>{r.get("passed") or 0}</td>'
            f'<td>{r.get("total") or 0}</td><td>{rate}%</td></tr>'
        )
        # แถวตัวอย่างที่พัง (ถ้ามี) — วางต่อท้ายแถวผลรวมทันที ใช้ colspan คลุมทั้งตาราง
        # ใส่ data-tool เดียวกับแถวผลรวม ให้ซ่อน/โชว์พร้อมกันตอนกรอง
        examples_html = _render_examples(r.get("failures") or [])
        if examples_html:
            body_rows.append(
                f'<tr data-tool="{_esc(tool)}"><td colspan="6">{examples_html}</td></tr>'
            )

    note_html = (
        f'<div class="note"><span class="note-label">หมายเหตุ:</span>{_esc(_CATEGORY_NOTES[cat])}</div>'
        if cat in _CATEGORY_NOTES
        else ""
    )

    filter_html = ""
    if len(tools_in_cat) > 1:
        buttons = ['<button type="button" data-tool-value="__all__" class="active">ทั้งหมด</button>']
        buttons += [
            f'<button type="button" data-tool-value="{_esc(t)}">{_esc(t)}</button>'
            for t in tools_in_cat
        ]
        filter_html = (
            f'<div class="tool-filter" data-target="{table_id}">'
            '<span class="filter-label">ดูเฉพาะ tool:</span>'
            f"{''.join(buttons)}</div>"
        )

    detail_table_html = (
        f'<table id="{table_id}"><thead><tr><th>Tool</th><th>Probe / Test</th>'
        "<th>Detector</th><th>Pass</th><th>Total</th><th>Rate</th></tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table>"
    )

    return (
        f'<div class="category-block" id="cat-{_esc(cat)}">'
        f'<div class="cat-head"><h3>{chr(ord("a") + idx)}. {_esc(owasp_label(cat))}'
        f'<span class="count"> ({len(rows)} รายการ)</span></h3></div>'
        f"{note_html}{filter_html}"
        f"{_wrap_table(detail_table_html)}"
        "</div>"
    )


def _truncate(text: str, limit: int = 600) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "…"


def _render_examples(failures: list[dict]) -> str:
    """โชว์ตัวอย่าง prompt/response/เหตุผลที่ "พัง" แบบ collapsible ใต้แถวผลรวม —
    ไม่บังคับเปิดอัตโนมัติ (details ไม่มี open) กันรายงานยาวเกินไปตอนเปิดครั้งแรก
    ถ้า row ไหนไม่มี failures (เช่น garak ที่ยังไม่ได้เก็บตัวอย่าง) จะคืน "" เฉยๆ
    ไม่กระทบของเดิม"""
    if not failures:
        return ""
    items = []
    for f in failures:
        prompt = _esc(_truncate(f.get("prompt", "")))
        response = _esc(_truncate(f.get("response", "")))
        reason = _esc(_truncate(f.get("reason", "")))
        reason_html = (
            f'<p><span class="field-label">เหตุผล:</span> {reason}</p>' if reason else ""
        )
        items.append(f"""
        <div class="example">
          <p><span class="field-label">Prompt:</span> {prompt}</p>
          <p><span class="field-label">Response:</span> {response}</p>
          {reason_html}
        </div>
        """)
    return (
        f'<details class="examples"><summary>ดูตัวอย่างที่พัง ({len(failures)} รายการ)'
        f"</summary>{''.join(items)}</details>"
    )


def _safe_model_slug(model) -> str:
    """ต้องตรงกับ sanitize pattern ที่ garak_runner.py/promptfoo_runner.py/
    promptmap2_runner.py ใช้ตั้งชื่อไฟล์ output จริง (replace ":" "/" "\\" เป็น "_")
    ถ้า runner ไหนเปลี่ยน pattern ต้องแก้ตรงนี้คู่กันด้วย ไม่งั้นลิงก์อ้างอิงจะชี้ผิดไฟล์"""
    return str(model or "").replace(":", "_").replace("/", "_").replace("\\", "_")


# ชื่อไฟล์ต้นฉบับ/ไฟล์ดิบที่ runner แต่ละตัวเซฟไว้จริง (verify จาก garak_runner.py,
# promptfoo_runner.py, promptmap2_runner.py) — {m} แทน safe_model slug คำอธิบายสั้นๆ
# บอกว่าไฟล์นี้ต่างจากตารางในรายงานรวมตรงไหน (ทำไมถึงต้องไปเปิดดูเพิ่ม)
_NATIVE_REFERENCE_FILES = {
    "garak": [
        ("garak_scan_{m}.report.html", "รายงานต้นฉบับของ Garak (interactive, ไล่ดูทุก attempt ได้)"),
        ("garak_scan_{m}.report.jsonl", "ผลดิบทุกบรรทัดจาก Garak (.jsonl)"),
        ("garak_scan_{m}.hitlog.jsonl", "เฉพาะ attempt ที่โจมตีสำเร็จ (hit log) ใช้ดูตัวอย่างแบบเต็ม เพราะ unified report ด้านบน cap ไว้ไม่เกิน 3 ตัวอย่างต่อ probe/detector เท่านั้น"),
    ],
    "promptfoo": [
        ("promptfoo_scan_{m}.html", "รายงานต้นฉบับของ Promptfoo (ไล่ดูทุก test case ได้ ทั้ง pass และ fail)"),
        ("promptfoo_scan_{m}.json", "ผลดิบจาก Promptfoo (.json) ใช้ดูตัวอย่างแบบเต็ม เพราะ unified report ด้านบน cap ตัวอย่างที่พังไว้ไม่เกิน 3 ต่อ plugin เท่านั้น"),
        ("promptfoo_redteam_{m}.yaml", "ชุด test case ที่ Promptfoo generate ขึ้นจริงสำหรับสแกนรอบนี้"),
    ],
    "promptmap2": [
        ("promptmap2_scan_{m}.json", "ผลดิบจาก promptmap2 (.json)"),
    ],
}


def _render_reference_links(tool_plan: dict, target_config: dict, output_dir) -> str:
    """ลิงก์ท้ายรายงานชี้กลับไปไฟล์ต้นฉบับ/ไฟล์ดิบของแต่ละ tool ที่ถูกเรียกใช้จริง —
    unified report นี้เป็นสรุปข้ามเครื่องมือระดับ probe/plugin เท่านั้น (cap จำนวน
    ตัวอย่างที่พังไว้) ถ้าต้องไล่ดูทุก prompt/attempt แบบเต็มต้องเปิดไฟล์พวกนี้แทน

    output_dir: ถ้าส่งมา (เช่นจาก save_reports() ที่รู้ output_dir จริง) จะเช็คว่าไฟล์มี
    อยู่จริงในโฟลเดอร์นั้นก่อนโชว์ลิงก์ — กันลิงก์ตายตอนไฟล์หาย/ยังไม่ถูกเซฟ ถ้าไม่ส่งมา
    (None) จะโชว์ลิงก์เฉยๆ แบบ optimistic ไม่เช็ค (เช่นตอนโชว์ inline ก่อนเซฟไฟล์จริง)
    """
    tools_used = sorted(tool_plan.keys())
    if not tools_used:
        return ""

    slug = _safe_model_slug(target_config.get("model"))
    blocks = []
    for tool in tools_used:
        entries = _NATIVE_REFERENCE_FILES.get(tool)
        if not entries:
            continue
        items = []
        for pattern, desc in entries:
            fname = pattern.format(m=slug)
            exists = True
            if output_dir is not None:
                exists = (Path(output_dir) / fname).exists()
            if exists:
                items.append(
                    f'<li><a href="{_esc(fname)}">{_esc(fname)}</a>'
                    f'<br><span class="ref-desc">{_esc(desc)}</span></li>'
                )
            else:
                items.append(
                    f'<li class="empty">{_esc(fname)}'
                    f'<br><span class="ref-desc">{_esc(desc)} '
                    "ไม่พบไฟล์นี้ในโฟลเดอร์เดียวกับรายงาน</span></li>"
                )
        if items:
            blocks.append(f"<h3>{_esc(tool)}</h3><ul>{''.join(items)}</ul>")

    if not blocks:
        return ""

    return (
        '<p class="meta">รายงานนี้เป็นสรุปข้ามเครื่องมือระดับ probe/plugin เท่านั้น '
        "(cap จำนวนตัวอย่างที่พังไว้ต่อแถว) ถ้าต้องไล่ดูทุก prompt และ attempt แบบเต็ม "
        "เปิดไฟล์ต้นฉบับหรือไฟล์ดิบของแต่ละ tool ด้านล่าง (อยู่โฟลเดอร์เดียวกับรายงานนี้)</p>"
        + "".join(blocks)
    )


def build_report_html(
    results: list[dict],
    tool_plan: dict,
    target_config: dict,
    output_dir=None,
) -> str:
    """สร้าง HTML report เดียวรวมผลทุก tool ที่ถูกเรียกในสแกนรอบนี้

    ใช้ได้ทั้งโชว์ inline ผ่าน st.components.v1.html() และเซฟเป็นไฟล์ .html
    เปิดตรงๆ ในเบราว์เซอร์ได้เลย (self-contained ไม่มี external asset รวมถึงกราฟที่เป็น
    inline SVG และปุ่มกรอง tool ที่เป็น vanilla JS ล้วนๆ ไม่พึ่ง library ภายนอก)
    """
    summary = _summarize_by_owasp(results)
    cat_tool_summary = _summarize_by_category_tool(results)
    grouped = _group_by_owasp(results)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    target_lines = [
        f"<li><strong>ประเภท:</strong> {_esc(target_config.get('type'))}</li>",
        f"<li><strong>โมเดล:</strong> {_esc(target_config.get('model'))}</li>",
    ]
    if target_config.get("base_url"):
        target_lines.append(f"<li><strong>Base URL:</strong> {_esc(target_config['base_url'])}</li>")

    comparison_html = _render_tool_comparison(cat_tool_summary)
    recommendations_html = _render_recommendations(summary)
    reference_html = _render_reference_links(tool_plan, target_config, output_dir)

    sections = [("summary", "สรุปตาม OWASP Category")]
    if comparison_html:
        sections.append(("tool-comparison", "เปรียบเทียบ Tool ต่อ Category"))
    if recommendations_html:
        sections.append(("recommendations", "ข้อแนะนำ"))
    sections.append(("tool-plan", "Tool ที่ระบบเลือกใช้"))
    sections.append(("category-detail", "รายละเอียดต่อ Category"))
    if reference_html:
        sections.append(("reference-files", "ไฟล์ต้นฉบับของแต่ละ Tool"))

    toc_html = _render_toc(sections, categories=sorted(grouped))

    # เลขหัวข้อขยับตาม sections ที่มีจริง (บาง scan ไม่มี comparison/recommendations)
    section_num = {anchor: i for i, (anchor, _label) in enumerate(sections, start=1)}

    category_sections = "".join(
        _render_category_detail(cat, grouped[cat], idx)
        for idx, cat in enumerate(sorted(grouped))
    ) or '<p class="empty">ไม่มีผลลัพธ์</p>'

    comparison_section = ""
    if comparison_html:
        comparison_section = f"""
        <h2 class="section" id="tool-comparison">
          <span class="num">{section_num['tool-comparison']}.</span>เปรียบเทียบ Tool ต่อ Category
        </h2>
        {comparison_html}
        """

    recommendations_section = ""
    if recommendations_html:
        recommendations_section = f"""
        <h2 class="section" id="recommendations">
          <span class="num">{section_num['recommendations']}.</span>ข้อแนะนำ
        </h2>
        {recommendations_html}
        """

    reference_section = ""
    if reference_html:
        reference_section = f"""
        <h2 class="section" id="reference-files">
          <span class="num">{section_num['reference-files']}.</span>ไฟล์ต้นฉบับของแต่ละ Tool
        </h2>
        {reference_html}
        """

    return f"""<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LLM Security Scan Report</title>
<style>{_CSS}</style>
</head>
<body>
  <div class="cover">
    <p class="doc-kind">รายงานผลการทดสอบความปลอดภัย LLM</p>
    <h1>LLM Security Scan Report</h1>
    <p class="meta">จัดทำ (generated): {generated_at}</p>
  </div>

  {_overall_score(summary)}

  <ul class="target-info">{''.join(target_lines)}</ul>

  {toc_html}

  <h2 class="section" id="summary">
    <span class="num">{section_num['summary']}.</span>สรุปตาม OWASP Category
  </h2>
  {_render_summary_table(summary)}

  {comparison_section}

  {recommendations_section}

  <h2 class="section" id="tool-plan">
    <span class="num">{section_num['tool-plan']}.</span>Tool ที่ระบบเลือกใช้
  </h2>
  <p class="meta">ตารางนี้แสดง tool ที่ถูกเลือกใช้ทดสอบแต่ละ category เพื่อความโปร่งใสของ decision logic</p>
  {_render_tool_plan_table(tool_plan)}

  <h2 class="section" id="category-detail">
    <span class="num">{section_num['category-detail']}.</span>รายละเอียดต่อ Category
  </h2>
  <p class="meta">ถ้า category ใดทดสอบด้วยหลาย tool จะมีช่องกรองให้กดดูผลแยกเฉพาะ tool
  นั้นได้ (ไม่ต้องโหลดหน้าใหม่)</p>
  {category_sections}

  {reference_section}

  <footer class="doc-footer">
    อ้างอิงตาม OWASP LLM Top 10 (2025) รายงานนี้สร้างโดยอัตโนมัติจากผลการสแกนจริง
    ไม่ใช่การประเมินโดยผู้เชี่ยวชาญ
  </footer>

  <script>{_JS}</script>
</body>
</html>"""


def build_report_csv(results: list[dict]) -> str:
    """CSV แบบแบน (1 แถว = 1 ผล test) เปิดด้วย Excel/Google Sheets ได้เลย
    คอลัมน์: owasp_category, tool, probe, detector, passed, total, pass_rate
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["owasp_category", "tool", "probe", "detector", "passed", "total", "pass_rate"])
    for r in sorted(results, key=lambda row: (row.get("owasp_category") or "", row.get("tool") or "")):
        rate = _pass_rate(r.get("passed") or 0, r.get("total") or 0)
        writer.writerow([
            r.get("owasp_category") or "Uncategorized",
            r.get("tool", ""),
            r.get("probe", ""),
            r.get("detector") or "",
            r.get("passed") or 0,
            r.get("total") or 0,
            rate,
        ])
    return buf.getvalue()


def save_reports(
    results: list[dict],
    tool_plan: dict,
    output_dir: Path,
    target_config: dict,
) -> dict[str, Path]:
    """เซฟ .html (unified report), .json (raw + summary) และ .csv (แบนๆ เปิดใน Excel
    ได้) ลง output_dir ของสแกนรอบนี้ (เช่น results/<scan_id>/) — เรียกจาก selector.run_scan()

    คืนค่า dict path ของไฟล์ที่เซฟ เผื่ออยาก link/แสดงต่อ (ตอนนี้ selector.py
    ไม่ได้ใช้ return value นี้ แค่เรียกเฉยๆ แต่เผื่อ caller อื่นในอนาคต)
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    html_path = output_dir / "report.html"
    html_path.write_text(
        build_report_html(results, tool_plan, target_config, output_dir=output_dir),
        encoding="utf-8",
    )

    json_path = output_dir / "report.json"
    json_path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "target": target_config,
                "tool_plan": tool_plan,
                "summary": _summarize_by_owasp(results),
                "summary_by_tool": _summarize_by_category_tool(results),
                "raw": results,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    csv_path = output_dir / "report.csv"
    csv_path.write_text(build_report_csv(results), encoding="utf-8")

    return {"html": html_path, "json": json_path, "csv": csv_path}