"""
ui/app.py — Streamlit frontend

user เลือกแค่ "จะทดสอบอะไร" (target + OWASP category) — ไม่ต้องรู้จัก/เลือก
Garak, promptmap2, Giskard, PyRIT เอง โปรแกรม (backend -> core/selector.py)
เป็นคนตัดสินใจว่า category ไหนต้องใช้ tool ไหน แล้วโชว์ "tool_plan" ให้เห็น
ความโปร่งใสของการตัดสินใจหลังสแกนเสร็จ

ก่อนสแกนเต็มรูปแบบ (ซึ่งอาจใช้เวลาเป็นชั่วโมง) มีปุ่ม "Smoke Test" ให้กดยิง
สแกนจริงขนาดจิ๋วก่อน (garak 1 probe, promptmap2 1 iteration) — ไม่ block
การกด Start Scan แต่เตือนไว้ถ้ายังไม่ผ่าน จะได้ไม่ต้องรอเป็นชั่วโมงแล้วมาพังทีหลัง

รันด้วย: streamlit run ui/app.py
ต้องมี backend (FastAPI) รันอยู่ที่ BACKEND_URL ก่อน

2026-09 (fix): แก้ 2 จุดที่เกี่ยวเนื่องกัน —
  1. เดิม target_config ที่ส่งเข้า build_report_html() เป็นตัวแปร local ที่ build
     จากค่า widget สดๆ ของทุก rerun (Streamlit รันทั้งไฟล์ใหม่ทุก interaction)
     ถ้า user เปลี่ยน dropdown (เช่น Model) หลังสแกนเสร็จแล้วแต่ก่อนโหลด/ดาวน์โหลด
     report — report ที่ regenerate จะโชว์ target ผิด (ของ widget ปัจจุบัน ไม่ใช่
     ของตอนที่สแกนจริง) อันตรายสำหรับ security report เพราะทำให้เข้าใจผิดว่าผล
     มาจาก target ไหน แก้โดย snapshot target_config ไว้ใน session_state ตอนกด
     Start Scan แล้วใช้ snapshot นั้นเสมอเวลา build report แทนตัวแปรสด
  2. เดิม job_id ถูก reset (set เป็น None) เฉพาะ path status == "failed" แต่ไม่ reset
     ตอน "done" ทำให้ rerun ถัดไปทุกครั้ง (กด checkbox, เปลี่ยน dropdown ใดๆ) ยิง
     GET .../status และ .../report ซ้ำอีกรอบโดยไม่จำเป็น เป็นสาเหตุหลักที่ทำให้
     บั๊ก #1 เกิดง่าย เพราะ blockแสดงผล/build report ถูกเข้าซ้ำทุก interaction
     แก้โดย cache ผล report ไว้ใน session_state ผูกกับ job_id เดิม ไม่ fetch ซ้ำ
"""

import os
import sys
import time
from pathlib import Path

import requests
import pandas as pd
import streamlit as st

# ทำให้ import core.report ได้แน่นอน ไม่ว่าจะรัน `streamlit run ui/app.py` จากที่ไหน
# (แทรก project root — parent ของโฟลเดอร์ ui/ — เข้า sys.path)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from core.report import build_report_html, build_report_csv
    REPORT_AVAILABLE = True
except ImportError:
    REPORT_AVAILABLE = False

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")

st.set_page_config(page_title="LLM Security Scanner", page_icon="🛡️")
st.title("🛡️ LLM Security Scanner")

# ---- 1. เลือกโมเดลที่จะทดสอบ ----------------------------------------------
st.header("1. เลือกโมเดลที่จะทดสอบ")
provider = st.selectbox("Provider", ["ollama", "openai_compatible"], index=0)

target_config = {"type": provider}

if provider == "ollama":
    ollama_url = st.text_input("Ollama Base URL", "http://localhost:11434")
    target_config["base_url"] = ollama_url

    # ดึงรายชื่อโมเดลที่โหลดไว้ในเครื่องจาก Ollama อัตโนมัติ
    available_models = []
    try:
        resp = requests.get(f"{ollama_url.rstrip('/')}/api/tags", timeout=3)
        if resp.status_code == 200:
            available_models = [m["name"] for m in resp.json().get("models", [])]
    except Exception:
        pass

    if available_models:
        # ถ้าดึงเจอ ให้เลือกจาก Dropdown
        target_config["model"] = st.selectbox("Model", available_models, index=0)
    else:
        # ถ้าต่อไม่ติดหรือยังไม่มี ให้พิมพ์มือเหมือนเดิม
        target_config["model"] = st.text_input("Model", "dolphin3")

# ---- 2. เลือกหมวดที่จะทดสอบ (OWASP) — โปรแกรมเลือก tool ให้เองจากตรงนี้ ------
st.header("2. เลือกหมวดที่จะทดสอบ (OWASP)")
st.caption(
    "ระบบเลือก tool ที่เหมาะสมที่สุดให้อัตโนมัติตามหมวดที่เลือก — หมวดไหนมีมากกว่า "
    "1 ตัวเลือก จะมี dropdown ให้เปลี่ยนเป็น tool อื่นแทนได้"
)

try:
    categories = requests.get(f"{BACKEND_URL}/owasp_categories", timeout=5).json()
except requests.exceptions.RequestException:
    st.error("เชื่อมต่อ backend ไม่ได้ — เช็คว่า FastAPI รันอยู่หรือยัง")
    categories = {}

selected_categories = []
tool_overrides = {}  # {code: tool} — ใส่เฉพาะหมวดที่ user เปลี่ยนจาก default จริงๆ
# หมายเหตุ: /owasp_categories เปลี่ยน response shape แล้ว (เดิมคืน {code: label}
# ตรงๆ ตอนนี้คืน {code: {"label", "tools", "default_tool"}}) เพื่อให้ UI รู้ว่า
# หมวดนี้เลือก tool ได้กี่ตัวเลือก — ถ้า backend เก่ายังไม่ได้อัปเดต endpoint นี้
# โค้ดด้านล่างจะพังเพราะ info["label"] ใช้กับ string ไม่ได้ ต้องอัปเดต main.py คู่กัน
for code, info in categories.items():
    label = info["label"]
    tools = info.get("tools", [])
    default_tool = info.get("default_tool")

    col_check, col_tool = st.columns([3, 2])
    with col_check:
        checked = st.checkbox(f"{code}: {label}", value=True, key=f"cat_{code}")
    if checked:
        selected_categories.append(code)
        if len(tools) > 1:
            with col_tool:
                chosen = st.selectbox(
                    "Tool", tools,
                    index=tools.index(default_tool) if default_tool in tools else 0,
                    key=f"tool_{code}",
                    label_visibility="collapsed",
                )
            if chosen != default_tool:
                tool_overrides[code] = chosen
        else:
            with col_tool:
                st.caption(f"tool: {tools[0] if tools else '-'}")

# ---- 2.5 ความเร็ว/ความครอบคลุมของสแกน — คนละมิติกับ category ด้านบน --------
st.header("⚙️ ความเร็วของสแกน")
st.caption(
    "Quick = ยิง probe/rule ตัวแทนแค่ 1 ตัวต่อหมวด + promptmap2 1 iteration (เร็ว "
    "แต่ครอบคลุมน้อยกว่า) — Deep = ยิงทุก probe/rule ที่ผูกไว้กับหมวดนั้น + "
    "promptmap2 5 iterations (ช้ากว่า แต่ครอบคลุมเต็มที่)"
)
depth = st.radio(
    "เลือกโหมด",
    options=["quick", "deep"],
    index=1,
    format_func=lambda d: "⚡ Quick (เร็ว)" if d == "quick" else "🔍 Deep (ครอบคลุมเต็ม)",
    horizontal=True,
    key="scan_depth",
)

# ---- 2.6 Smoke Test — ยิงสแกนจริงขนาดจิ๋วก่อน เช็คว่า pipeline พร้อมมั้ย -------
st.header("🧪 ทดสอบระบบก่อน (แนะนำ)")
st.caption(
    "ยิงสแกนจริงแบบย่อ (garak แค่ 1 probe, promptmap2 แค่ 1 iteration) "
    "ใช้เวลาไม่กี่นาที เพื่อเช็คว่า Ollama/garak/promptmap2 พร้อมใช้งานจริง "
    "ก่อนสั่งสแกนเต็มรูปแบบที่อาจใช้เวลาเป็นชั่วโมง"
)

if "smoke_job_id" not in st.session_state:
    st.session_state.smoke_job_id = None
if "smoke_passed" not in st.session_state:
    st.session_state.smoke_passed = None  # None = ยังไม่เคยรัน, True/False = ผลล่าสุด

if st.button("🧪 Run Smoke Test"):
    if provider == "ollama" and not target_config.get("model"):
        st.error("กรุณาระบุชื่อโมเดลก่อน")
    else:
        resp = requests.post(f"{BACKEND_URL}/scan/smoke-test", json={"target": target_config})
        if resp.status_code == 200:
            st.session_state.smoke_job_id = resp.json()["job_id"]
            st.session_state.smoke_passed = None
        else:
            st.error(f"เริ่ม smoke test ไม่สำเร็จ: {resp.text}")

if st.session_state.smoke_job_id:
    smoke_job_id = st.session_state.smoke_job_id
    with st.spinner("⏳ กำลังยิง smoke test (สแกนจริงขนาดจิ๋ว)..."):
        while True:
            smoke_resp = requests.get(f"{BACKEND_URL}/scan/smoke-test/{smoke_job_id}/status")
            if smoke_resp.status_code != 200:
                st.error(f"Backend API Error ({smoke_resp.status_code}): {smoke_resp.text}")
                st.session_state.smoke_job_id = None
                break

            smoke_data = smoke_resp.json()
            status = smoke_data.get("status")

            if status == "done":
                result = smoke_data["result"]
                st.session_state.smoke_passed = result["passed"]
                for check in result["checks"]:
                    icon = "✅" if check["ok"] else "❌"
                    st.write(f"{icon} **{check['check']}** — {check['detail']}")
                st.session_state.smoke_job_id = None
                break

            if status == "failed":
                st.error(f"Smoke test ล้มเหลว: {smoke_data.get('error')}")
                st.session_state.smoke_passed = False
                st.session_state.smoke_job_id = None
                break

            time.sleep(2)

if st.session_state.smoke_passed is True:
    st.success("✅ Smoke test ผ่านหมด — pipeline พร้อมสแกนเต็มรูปแบบ")
elif st.session_state.smoke_passed is False:
    st.warning("⚠️ Smoke test ไม่ผ่านบางจุด — แนะนำให้แก้ก่อน ไม่งั้นสแกนเต็มรูปแบบอาจรอนานแล้วพังแบบเดียวกัน")

# ---- 3. ปุ่มสแกน ------------------------------------------------------------
st.header("3. เริ่มสแกน")

if "job_id" not in st.session_state:
    st.session_state.job_id = None
# snapshot ของ target_config ณ ตอนกด Start Scan — ใช้ตัวนี้เวลา build report เสมอ
# (ไม่ใช้ตัวแปร target_config สดด้านบน เพราะมันเปลี่ยนตามค่า widget ปัจจุบันทุก
# rerun ซึ่งอาจไม่ใช่ target ที่สแกนจริงแล้วถ้า user แก้ dropdown ทีหลัง)
if "scanned_target" not in st.session_state:
    st.session_state.scanned_target = None
# cache ผล report ผูกกับ job_id เพื่อไม่ต้องยิง GET .../report ซ้ำทุก rerun
if "report_cache_job_id" not in st.session_state:
    st.session_state.report_cache_job_id = None
if "report_cache_data" not in st.session_state:
    st.session_state.report_cache_data = None

if st.session_state.smoke_passed is not True:
    st.caption("💡 ยังไม่ได้รัน smoke test หรือยังไม่ผ่าน — กดสแกนเต็มรูปแบบได้เลยถ้ามั่นใจ แต่แนะนำให้ลอง smoke test ก่อน")

if st.button("🚀 Start Scan", type="primary"):
    if provider == "ollama" and not target_config.get("model"):
        st.error("กรุณาระบุชื่อโมเดล")
    elif not selected_categories:
        st.error("กรุณาเลือกอย่างน้อย 1 หมวด OWASP")
    else:
        scan_payload = {
            "target": target_config,
            "owasp_categories": selected_categories,
            "depth": depth,
        }
        if tool_overrides:
            scan_payload["tool_overrides"] = tool_overrides

        resp = requests.post(f"{BACKEND_URL}/scan", json=scan_payload)
        if resp.status_code == 200:
            st.session_state.job_id = resp.json()["job_id"]
            # snapshot target ตรงนี้ — คือ target ที่ backend จะสแกนจริงสำหรับ job นี้
            st.session_state.scanned_target = dict(target_config)
            # scan ใหม่ ล้าง cache report ของ job เก่าทิ้ง
            st.session_state.report_cache_job_id = None
            st.session_state.report_cache_data = None
            st.success(f"เริ่มสแกนแล้ว (job: {st.session_state.job_id[:8]}...)")
        else:
            st.error(f"เริ่มสแกนไม่สำเร็จ: {resp.text}")

# ---- 4. ติดตามสถานะ + แสดงผล ------------------------------------------------
if st.session_state.job_id:
    job_id = st.session_state.job_id
    status_placeholder = st.empty()

    with st.spinner("⏳ กำลังสแกน..."):
        while True:
            status_resp = requests.get(f"{BACKEND_URL}/scan/{job_id}/status")
            if status_resp.status_code != 200:
                st.error(f"Backend API Error ({status_resp.status_code}): {status_resp.text}")
                st.stop()

            data = status_resp.json()
            status = data.get("status")

            if not status:
                st.error(f"ไม่พบคีย์ 'status' ในข้อมูลที่ได้รับ: {data}")
                st.stop()
            status_placeholder.info(f"สถานะ: {status}")

            if status == "done":
                break
            if status == "failed":
                st.error(f"สแกนล้มเหลว: {status_resp.json().get('error')}")
                st.session_state.job_id = None
                break
            time.sleep(3)

    if st.session_state.job_id:  # ยังไม่ error
        # ใช้ cache ถ้าเคยดึง report ของ job นี้มาแล้ว ไม่ยิง request ซ้ำทุก rerun
        if st.session_state.report_cache_job_id == job_id and st.session_state.report_cache_data is not None:
            data = st.session_state.report_cache_data
            report_ok = True
        else:
            report_resp = requests.get(f"{BACKEND_URL}/scan/{job_id}/report")
            report_ok = report_resp.status_code == 200
            if report_ok:
                data = report_resp.json()
                st.session_state.report_cache_job_id = job_id
                st.session_state.report_cache_data = data

        if report_ok:
            summary = data["summary"]
            tool_plan = data.get("tool_plan", {})
            # target ที่ใช้ต่อจากนี้คือ snapshot ตอนกด Start Scan เสมอ ไม่ใช่ widget สด
            scanned_target = st.session_state.scanned_target or {}

            # ---- โชว์ว่าระบบเลือก tool ไหนให้ ทำไม (ความโปร่งใสของ decision logic) ----
            if tool_plan:
                st.subheader("🧭 ระบบเลือกใช้ tool ดังนี้")
                for tool, cats in tool_plan.items():
                    st.write(f"- **{tool}** → ทดสอบหมวด: {', '.join(cats)}")

            st.header("📊 ผลการสแกน")
            df = pd.DataFrame([
                {
                    "OWASP Category": cat,
                    "Pass": s["pass"],
                    "Total": s["total"],
                    "Pass Rate (%)": round(s["pass"] / s["total"] * 100, 1) if s["total"] else 0,
                }
                for cat, s in summary.items()
            ])
            st.dataframe(df, use_container_width=True)
            if not df.empty:
                st.bar_chart(df.set_index("OWASP Category")["Pass Rate (%)"])

            with st.expander("🔍 ดูผลดิบแยกตาม tool (raw data ก่อนรวม)"):
                raw_df = pd.DataFrame(data["raw"])
                st.dataframe(raw_df, use_container_width=True)
                st.caption(
                    "แถวเดียวกันหลาย tool อาจ map เข้า OWASP category เดียวกัน — "
                    "ตารางสรุปด้านบนคือผลรวมของทุก tool ต่อ category"
                )

            # ---- Unified Report — รวมทุก tool เป็น HTML report เดียว แนว garak ----
                        # ---- Unified Report — ดึงไฟล์ .html ที่ backend เซฟไว้แล้วมาแสดง/ดาวน์โหลด
            # โดยตรง (ไม่ build_report_html() ซ้ำเองใน Streamlit process อีกต่อไป) —
            # กันปัญหา backend restart แล้ว UI ยัง import core.report เวอร์ชันเก่าค้าง
            # ทำให้ไฟล์ที่ backend เซฟไว้กับไฟล์ที่ user ดาวน์โหลดจาก UI ไม่ตรงกัน
            # (เจอจริง: LLM10 map ถูกใน results/ แต่ผิดในไฟล์ที่ดาวน์โหลดจาก UI)
            st.header("📄 รายงานรวม (Unified Report)")
            report_html_resp = requests.get(f"{BACKEND_URL}/scan/{job_id}/report/html")
            if report_html_resp.status_code == 200:
                report_html = report_html_resp.text
                st.components.v1.html(report_html, height=900, scrolling=True)
                st.download_button(
                    "📥 ดาวน์โหลดรายงาน (HTML)",
                    data=report_html.encode("utf-8"),
                    file_name=f"llm_security_report_{job_id[:8]}.html",
                    mime="text/html",
                )
            else:
                st.warning(
                    f"ดึงไฟล์ report จาก backend ไม่สำเร็จ "
                    f"({report_html_resp.status_code}): {report_html_resp.text}"
                )

            if REPORT_AVAILABLE:
                # CSV ยัง build เองได้ตามปกติ เพราะ build_report_csv() คำนวณจากตัวเลข
                # pass/total ตรงๆ ไม่ผ่าน owasp_mapping ที่เคยมีปัญหา stale import —
                # เสี่ยงน้อยกว่า build_report_html() มาก แต่ยังต้อง import core.report
                # เข้าไป จะย้ายไป backend endpoint ทีหลังก็ได้ถ้าอยากตัด dependency นี้ทิ้งด้วย
                report_csv = build_report_csv(data["raw"])
                st.download_button(
                    "📥 ดาวน์โหลด CSV (รายละเอียดทุกแถว)",
                    data=report_csv.encode("utf-8"),
                    file_name=f"llm_security_report_{job_id[:8]}.csv",
                    mime="text/csv",
                )

            st.download_button(
                "📥 ดาวน์โหลด CSV (สรุปต่อ Category)",
                data=df.to_csv(index=False).encode("utf-8"),
                file_name=f"scan_summary_{job_id[:8]}.csv",
                mime="text/csv",
            )
        else:
            st.error(f"ดึงรายงานไม่สำเร็จ: {report_resp.text}")