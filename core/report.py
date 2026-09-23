"""
report.py — สร้าง unified report รวมผลจากทุก tool (garak, promptmap2, ...) เป็นไฟล์เดียว
จัดกลุ่มตาม OWASP category

ไม่มี dependency ภายนอก (ไม่ใช้ Jinja2/matplotlib ฯลฯ) — string-based HTML ธรรมดา
เปิดตรงๆ ในเบราว์เซอร์ได้เลย ไม่ต้องรัน server ก็ดูได้

ใช้จาก 2 ที่:
  - selector.py -> save_reports()   เซฟ .html + .json + .csv ลงโฟลเดอร์ของแต่ละสแกน
  - ui/app.py   -> build_report_html() / build_report_csv()  โชว์ inline ใน Streamlit
                   + ให้ดาวน์โหลด

หน้าตา HTML ตั้งใจให้ดูง่ายแบบ garak native report (มี pass-rate bar สีเขียว/
เหลือง/แดงต่อ category + overall score บนสุด) แต่ตัด SPA/JS bundle ทิ้งหมด
เหลือแค่ HTML/CSS เพลนๆ ไฟล์เดียว เปิดได้ทุกที่ไม่ต้อง build

หมายเหตุ: ห้าม import จาก .selector ในไฟล์นี้ — selector.py import จากไฟล์นี้อยู่แล้ว
(import ย้อนกลับจะเกิด circular import) ฟังก์ชัน summarize/group ด้านล่างเลยเขียนแยก
เป็นของตัวเอง ไม่ใช้ร่วมกับ selector.summarize_by_owasp แม้ logic จะคล้ายกันก็ตาม
"""

import csv
import html
import io
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .owasp_mapping import owasp_label


def _summarize_by_owasp(results: list[dict]) -> dict[str, dict]:
    summary = defaultdict(lambda: {"pass": 0, "total": 0})
    for r in results:
        cat = r.get("owasp_category") or "Uncategorized"
        summary[cat]["pass"] += r.get("passed", 0)
        summary[cat]["total"] += r.get("total", 0)
    return dict(summary)


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
        return "#1a7f37"  # green — ป้องกันได้ดี
    if rate >= 40:
        return "#9a6700"  # เหลือง — กลางๆ
    return "#cf222e"      # แดง — ป้องกันไม่ค่อยได้


def _rate_bar(rate: float) -> str:
    """bar สีตาม pass rate แนว garak native report — อ่านง่ายกว่าตัวเลขล้วนๆ"""
    color = _rate_color(rate)
    width = max(rate, 2)  # กัน bar หายไปเลยตอน 0%
    return (
        '<div class="bar-track">'
        f'<div class="bar-fill" style="width:{width}%; background:{color};"></div>'
        f'<span class="bar-label">{rate}%</span>'
        "</div>"
    )


_CSS = """
:root { color-scheme: light; }
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 960px;
       margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
h1 { margin-bottom: 0.2rem; }
h2 { margin-top: 2rem; border-bottom: 2px solid #eee; padding-bottom: 0.3rem; }
.meta { color: #666; font-size: 0.9rem; margin-top: 0; }
.target-info { background: #f7f7f9; border-radius: 8px; padding: 0.8rem 1.2rem;
               list-style: none; margin: 0; }
.target-info li { padding: 0.15rem 0; }
table { width: 100%; border-collapse: collapse; margin: 0.8rem 0; }
th, td { text-align: left; padding: 0.5rem 0.7rem; border-bottom: 1px solid #e5e5e5; }
th { background: #f0f0f3; font-weight: 600; }
tr:hover td { background: #fafafa; }
.rate-good { color: #1a7f37; font-weight: 600; }
.rate-mid  { color: #9a6700; font-weight: 600; }
.rate-bad  { color: #cf222e; font-weight: 600; }
.category-block { margin: 0.8rem 0; border: 1px solid #e5e5e5; border-radius: 8px;
                   padding: 0.6rem 1rem; }
.category-block summary { cursor: pointer; font-weight: 600; font-size: 1.05rem; }
.category-block .count { font-weight: 400; color: #666; font-size: 0.9rem; }
.empty { color: #888; font-style: italic; }
.overall { display: flex; align-items: baseline; gap: 0.6rem; margin: 0.4rem 0 1.2rem; }
.overall .score { font-size: 2.4rem; font-weight: 700; }
.overall .label { color: #666; }
.bar-track { position: relative; background: #eee; border-radius: 6px; height: 20px;
             min-width: 140px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 6px; transition: width 0.2s ease; }
.bar-label { position: absolute; right: 6px; top: 0; line-height: 20px; font-size: 0.78rem;
             font-weight: 600; color: #1a1a1a; }
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
    return (
        "<table><thead><tr><th>OWASP Category</th><th>Pass</th><th>Total</th>"
        f"<th>Pass Rate</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
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
        f'<span class="label">Overall pass rate ({total_pass}/{total_all} การทดสอบ)</span>'
        "</div>"
    )


def _render_tool_plan_table(tool_plan: dict) -> str:
    if not tool_plan:
        return '<p class="empty">ไม่มีข้อมูล tool plan</p>'
    rows = []
    for tool, cats in tool_plan.items():
        cat_labels = ", ".join(owasp_label(c) for c in cats)
        rows.append(f"<tr><td>{_esc(tool)}</td><td>{_esc(cat_labels)}</td></tr>")
    return (
        "<table><thead><tr><th>Tool</th><th>ทดสอบหมวด</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _render_category_detail(cat: str, rows: list[dict]) -> str:
    body_rows = []
    for r in rows:
        rate = _pass_rate(r.get("passed", 0), r.get("total", 0))
        body_rows.append(
            f"<tr><td>{_esc(r.get('tool'))}</td><td>{_esc(r.get('probe'))}</td>"
            f"<td>{_esc(r.get('detector') or '-')}</td><td>{r.get('passed', 0)}</td>"
            f"<td>{r.get('total', 0)}</td><td>{rate}%</td></tr>"
        )
    return (
        f'<details open class="category-block"><summary>{_esc(owasp_label(cat))} '
        f'<span class="count">({len(rows)} รายการ)</span></summary>'
        "<table><thead><tr><th>Tool</th><th>Probe / Test</th><th>Detector</th>"
        f"<th>Pass</th><th>Total</th><th>Rate</th></tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table></details>"
    )


def build_report_html(results: list[dict], tool_plan: dict, target_config: dict) -> str:
    """สร้าง HTML report เดียวรวมผลทุก tool ที่ถูกเรียกในสแกนรอบนี้

    ใช้ได้ทั้งโชว์ inline ผ่าน st.components.v1.html() และเซฟเป็นไฟล์ .html
    เปิดตรงๆ ในเบราว์เซอร์ได้เลย (self-contained ไม่มี external asset)
    """
    summary = _summarize_by_owasp(results)
    grouped = _group_by_owasp(results)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    target_lines = [
        f"<li><strong>Type:</strong> {_esc(target_config.get('type'))}</li>",
        f"<li><strong>Model:</strong> {_esc(target_config.get('model'))}</li>",
    ]
    if target_config.get("base_url"):
        target_lines.append(f"<li><strong>Base URL:</strong> {_esc(target_config['base_url'])}</li>")

    category_sections = "".join(
        _render_category_detail(cat, grouped[cat]) for cat in sorted(grouped)
    ) or '<p class="empty">ไม่มีผลลัพธ์</p>'

    return f"""<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="utf-8">
<title>LLM Security Scan Report</title>
<style>{_CSS}</style>
</head>
<body>
  <h1>🛡️ LLM Security Scan Report</h1>
  <p class="meta">Generated: {generated_at}</p>
  {_overall_score(summary)}

  <h2>Target</h2>
  <ul class="target-info">{''.join(target_lines)}</ul>

  <h2>📊 สรุปตาม OWASP Category</h2>
  {_render_summary_table(summary)}

  <h2>🧭 Tool ที่ระบบเลือกใช้ (ความโปร่งใสของ decision logic)</h2>
  {_render_tool_plan_table(tool_plan)}

  <h2>🔍 รายละเอียดต่อ Category</h2>
  {category_sections}
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
        rate = _pass_rate(r.get("passed", 0), r.get("total", 0))
        writer.writerow([
            r.get("owasp_category") or "Uncategorized",
            r.get("tool", ""),
            r.get("probe", ""),
            r.get("detector") or "",
            r.get("passed", 0),
            r.get("total", 0),
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
    html_path.write_text(build_report_html(results, tool_plan, target_config), encoding="utf-8")

    json_path = output_dir / "report.json"
    json_path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "target": target_config,
                "tool_plan": tool_plan,
                "summary": _summarize_by_owasp(results),
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