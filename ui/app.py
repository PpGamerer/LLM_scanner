"""Streamlit frontend ของ scanner

รัน: streamlit run ui/app.py (ต้องเปิด backend FastAPI ไว้ก่อน)
"""

import os
import sys
import time
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

# ให้ import core.* ได้ไม่ว่าจะสั่งรันจากโฟลเดอร์ไหน
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from core.report import build_report_csv
    REPORT_AVAILABLE = True
except ImportError:
    REPORT_AVAILABLE = False

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")

st.set_page_config(page_title="LLM Vulnerability Scanner", page_icon="🛡️")
st.title("LLM Vulnerability Scanner")

# streamlit รันไฟล์นี้ใหม่ทุกครั้งที่กดอะไรสักอย่าง เลยเก็บ state ไว้ตรงนี้
for key, default in {
    "smoke_job_id": None,
    "smoke_passed": None,       # None = ยังไม่เคยรัน
    "job_id": None,
    "report_cache_job_id": None,
    "report_cache_data": None,
}.items():
    st.session_state.setdefault(key, default)


# ---------- 1. โมเดลที่จะทดสอบ ----------
st.header("1. เลือกโมเดล")
provider = st.selectbox("Provider", ["ollama", "openai_compatible"], index=0)
target_config = {"type": provider}

if provider == "ollama":
    ollama_url = st.text_input("Ollama Base URL", "http://localhost:11434")
    target_config["base_url"] = ollama_url

    # ลองดึงรายชื่อโมเดลจาก Ollama ถ้าต่อไม่ได้ก็ให้พิมพ์เอง
    available_models = []
    try:
        r = requests.get(f"{ollama_url.rstrip('/')}/api/tags", timeout=3)
        if r.status_code == 200:
            available_models = [m["name"] for m in r.json().get("models", [])]
    except Exception:
        pass

    if available_models:
        target_config["model"] = st.selectbox("Model", available_models, index=0)
    else:
        target_config["model"] = st.text_input("Model", "dolphin3")


# ---------- 2. หมวด OWASP ----------
st.header("2. เลือกหมวดที่จะทดสอบ (OWASP)")
st.caption(
    "ระบบเลือก tool ให้เองตามหมวด ถ้าหมวดไหนมี tool ให้เลือกมากกว่า 1 ตัว "
    "จะมี dropdown ให้เปลี่ยนได้"
)

try:
    categories = requests.get(f"{BACKEND_URL}/owasp_categories", timeout=5).json()
except requests.exceptions.RequestException:
    st.error("ต่อ backend ไม่ได้ ลองเช็คว่า FastAPI เปิดอยู่หรือเปล่า")
    categories = {}

selected_categories = []
tool_overrides = {}  # เก็บเฉพาะหมวดที่ user เปลี่ยนจาก default

# /owasp_categories คืน {code: {"label", "tools", "default_tool"}}
for code, info in categories.items():
    tools = info.get("tools", [])
    default_tool = info.get("default_tool")

    col_check, col_tool = st.columns([3, 2])
    with col_check:
        checked = st.checkbox(f"{code}: {info['label']}", value=True, key=f"cat_{code}")
    if not checked:
        continue

    selected_categories.append(code)
    with col_tool:
        if len(tools) > 1:
            chosen = st.selectbox(
                "Tool",
                tools,
                index=tools.index(default_tool) if default_tool in tools else 0,
                key=f"tool_{code}",
                label_visibility="collapsed",
            )
            if chosen != default_tool:
                tool_overrides[code] = chosen
        else:
            st.caption(f"tool: {tools[0] if tools else '-'}")


# ---------- โหมดความเร็ว ----------
st.header("โหมดการสแกน")
st.caption(
    "Quick: ใช้ probe ตัวแทนหมวดละตัว เร็วแต่ครอบคลุมน้อย / "
    "Deep: ยิงทุก probe ที่ผูกกับหมวดนั้น ช้ากว่าแต่ครบกว่า"
)
depth = st.radio(
    "โหมด",
    options=["quick", "deep"],
    index=1,
    format_func=lambda d: "Quick (เร็ว)" if d == "quick" else "Deep (ครบ)",
    horizontal=True,
    key="scan_depth",
)


# ---------- Smoke test ----------
st.header("Smoke test (ควรรันก่อน)")
st.caption(
    "สแกนจิ๋วๆ เพื่อเช็คว่า Ollama กับ tool ต่างๆ ใช้งานได้ "
    "จะได้ไม่ต้องรอสแกนจริงเป็นชั่วโมงแล้วค่อยมารู้ว่าพัง"
)

if st.button("Run Smoke Test"):
    if provider == "ollama" and not target_config.get("model"):
        st.error("ใส่ชื่อโมเดลก่อน")
    else:
        resp = requests.post(f"{BACKEND_URL}/scan/smoke-test", json={"target": target_config})
        if resp.status_code == 200:
            st.session_state.smoke_job_id = resp.json()["job_id"]
            st.session_state.smoke_passed = None
        else:
            st.error(f"เริ่ม smoke test ไม่ได้: {resp.text}")

if st.session_state.smoke_job_id:
    smoke_id = st.session_state.smoke_job_id
    with st.spinner("กำลังรัน smoke test..."):
        while True:
            r = requests.get(f"{BACKEND_URL}/scan/smoke-test/{smoke_id}/status")
            if r.status_code != 200:
                st.error(f"Backend error ({r.status_code}): {r.text}")
                st.session_state.smoke_job_id = None
                break

            smoke = r.json()
            if smoke.get("status") == "done":
                result = smoke["result"]
                st.session_state.smoke_passed = result["passed"]
                for check in result["checks"]:
                    msg = f"{check['check']}: {check['detail']}"
                    if check["ok"]:
                        st.success(msg)
                    else:
                        st.error(msg)
                st.session_state.smoke_job_id = None
                break

            if smoke.get("status") == "failed":
                st.error(f"Smoke test ล้มเหลว: {smoke.get('error')}")
                st.session_state.smoke_passed = False
                st.session_state.smoke_job_id = None
                break

            time.sleep(2)

if st.session_state.smoke_passed is True:
    st.success("Smoke test ผ่านทุกข้อ พร้อมสแกนจริง")
elif st.session_state.smoke_passed is False:
    st.warning("Smoke test ยังไม่ผ่านบางข้อ ควรแก้ก่อน ไม่งั้นสแกนจริงน่าจะพังแบบเดียวกัน")


# ---------- 3. เริ่มสแกน ----------
st.header("3. เริ่มสแกน")

if st.session_state.smoke_passed is not True:
    st.caption("ยังไม่ได้รัน smoke test (หรือยังไม่ผ่าน) ข้ามไปสแกนเลยก็ได้ แต่แนะนำให้รันก่อน")

if st.button("Start Scan", type="primary"):
    if provider == "ollama" and not target_config.get("model"):
        st.error("ใส่ชื่อโมเดลก่อน")
    elif not selected_categories:
        st.error("เลือกอย่างน้อย 1 หมวด")
    else:
        payload = {
            "target": target_config,
            "owasp_categories": selected_categories,
            "depth": depth,
        }
        if tool_overrides:
            payload["tool_overrides"] = tool_overrides

        resp = requests.post(f"{BACKEND_URL}/scan", json=payload)
        if resp.status_code == 200:
            st.session_state.job_id = resp.json()["job_id"]
            # job ใหม่ ล้าง cache ของ report เก่า
            st.session_state.report_cache_job_id = None
            st.session_state.report_cache_data = None
            st.success(f"เริ่มสแกนแล้ว (job {st.session_state.job_id[:8]})")
        else:
            st.error(f"เริ่มสแกนไม่ได้: {resp.text}")


# ---------- 4. สถานะและผลลัพธ์ ----------
if st.session_state.job_id:
    job_id = st.session_state.job_id
    status_box = st.empty()

    with st.spinner("กำลังสแกน..."):
        while True:
            r = requests.get(f"{BACKEND_URL}/scan/{job_id}/status")
            if r.status_code != 200:
                st.error(f"Backend error ({r.status_code}): {r.text}")
                st.stop()

            job = r.json()
            status = job.get("status")
            if not status:
                st.error(f"response ไม่มี status: {job}")
                st.stop()
            status_box.info(f"สถานะ: {status}")

            if status == "done":
                break
            if status == "failed":
                st.error(f"สแกนล้มเหลว: {job.get('error')}")
                st.session_state.job_id = None
                break
            time.sleep(3)

if st.session_state.job_id:
    # ดึง report ครั้งเดียวต่อ job ที่เหลือใช้ cache (ไม่งั้นทุก rerun จะยิงซ้ำ)
    if st.session_state.report_cache_job_id == job_id:
        report = st.session_state.report_cache_data
    else:
        r = requests.get(f"{BACKEND_URL}/scan/{job_id}/report")
        if r.status_code != 200:
            st.error(f"ดึงรายงานไม่ได้: {r.text}")
            st.stop()
        report = r.json()
        st.session_state.report_cache_job_id = job_id
        st.session_state.report_cache_data = report

    summary = report["summary"]
    tool_plan = report.get("tool_plan", {})

    if tool_plan:
        st.subheader("tool ที่ระบบเลือกใช้")
        for tool, cats in tool_plan.items():
            st.write(f"- **{tool}** → {', '.join(cats)}")

    st.header("ผลการสแกน")
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

    with st.expander("ดูผลดิบแยกตาม tool"):
        st.dataframe(pd.DataFrame(report["raw"]), use_container_width=True)
        st.caption("ตารางสรุปด้านบนคือผลรวมของทุก tool ต่อหมวด")

    # ดึง report.html ที่ backend เซฟไว้มาโชว์เลย ไม่ build ใหม่ฝั่ง UI
    # (เคยเจอว่าไฟล์ที่ดาวน์โหลดจาก UI ไม่ตรงกับที่ backend เซฟ เพราะ import core.report เก่าค้าง)
    st.header("รายงานรวม")
    html_resp = requests.get(f"{BACKEND_URL}/scan/{job_id}/report/html")
    if html_resp.status_code == 200:
        st.components.v1.html(html_resp.text, height=900, scrolling=True)
        st.download_button(
            "ดาวน์โหลดรายงาน (HTML)",
            data=html_resp.text.encode("utf-8"),
            file_name=f"llm_security_report_{job_id[:8]}.html",
            mime="text/html",
        )
    else:
        st.warning(f"ดึงไฟล์ report จาก backend ไม่ได้ ({html_resp.status_code}): {html_resp.text}")

    if REPORT_AVAILABLE:
        st.download_button(
            "ดาวน์โหลด CSV (ทุกแถว)",
            data=build_report_csv(report["raw"]).encode("utf-8"),
            file_name=f"llm_security_report_{job_id[:8]}.csv",
            mime="text/csv",
        )

    st.download_button(
        "ดาวน์โหลด CSV (สรุปต่อหมวด)",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name=f"scan_summary_{job_id[:8]}.csv",
        mime="text/csv",
    )