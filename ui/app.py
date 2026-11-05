"""Streamlit frontend ของ scanner

รัน: streamlit run ui/app.py (ต้องเปิด backend FastAPI ไว้ก่อน)
"""

import os

import pandas as pd
import requests
import streamlit as st
import re
from urllib.parse import quote

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")
# ค่าเริ่มต้นของช่อง Ollama URL — ใน Docker ตั้งเป็น http://host.docker.internal:11434
PUBLIC_BACKEND_URL = os.environ.get("PUBLIC_BACKEND_URL", "http://localhost:8000")

def link_files_to_backend(html_text: str, job_id: str) -> str:
    base = f"{PUBLIC_BACKEND_URL.rstrip('/')}/scan/{job_id}/files/"
    return re.sub(
        r'href="(?!#|https?:|mailto:)([^"]+)"',
        lambda m: f'href="{base}{quote(m.group(1))}" target="_blank" rel="noopener"',
        html_text,
    )

DEFAULT_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")

st.set_page_config(page_title="LLM Security Scanner", page_icon="🛡️")
st.title("LLM Security Scanner")

# streamlit รันไฟล์นี้ใหม่ทุกครั้งที่กดอะไรสักอย่าง เลยเก็บ state ไว้ตรงนี้
for key, default in {
    "smoke_job_id": None,
    "smoke_result": None,       # None = ยังไม่เคยรัน
    "job_id": None,
    "report_cache_job_id": None,
    "report_cache_data": None,
}.items():
    st.session_state.setdefault(key, default)

# session_state หายเวลา refresh หรือ browser ต่อ websocket ใหม่ (เช่น แท็บถูกพัก) ทำให้สแกนที่ยัง
# รันอยู่ที่ backend "หลุด" จากหน้าเว็บ เลยเก็บ job id ไว้ใน URL (?job=...) ด้วย
if st.session_state.job_id is None and st.query_params.get("job"):
    st.session_state.job_id = st.query_params["job"]


def api_get(path: str):
    """GET ไป backend คืน (status_code, json) หรือ (None, None) ถ้าต่อไม่ได้ชั่วคราว
    (เช่น backend กำลัง restart) — ไม่ raise เพื่อไม่ให้หน้าเว็บพังกลางสแกน"""
    try:
        r = requests.get(f"{BACKEND_URL}{path}", timeout=10)
    except requests.exceptions.RequestException:
        return None, None
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, None


# ---------- 1. โมเดลที่จะทดสอบ ----------
st.header("1. เลือกโมเดล")
provider = st.selectbox("Provider", ["ollama", "openai_compatible"], index=0)
target_config = {"type": provider}

if provider == "ollama":
    ollama_url = st.text_input("Ollama Base URL", DEFAULT_OLLAMA_URL)
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
        st.warning("ไม่พบ Model ใน Ollama กรุณาดาวน์โหลด Model ก่อน")
        target_config["model"] = st.text_input(
            "Model",
            value="",
            placeholder="เช่น llama3.2:3b"
        )


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
        try:
            resp = requests.post(
                f"{BACKEND_URL}/scan/smoke-test", json={"target": target_config}, timeout=30
            )
        except requests.exceptions.RequestException as e:
            st.error(f"ต่อ backend ไม่ได้: {e}")
        else:
            if resp.status_code == 200:
                st.session_state.smoke_job_id = resp.json()["job_id"]
                st.session_state.smoke_result = None
            else:
                st.error(f"เริ่ม smoke test ไม่ได้: {resp.text}")


@st.fragment(run_every=2)
def watch_smoke(smoke_id):
    """poll ทุก 2 วินาทีแบบไม่บล็อกสคริปต์ (fragment วนเองโดยไม่ต้องมี while/sleep)"""
    code, data = api_get(f"/scan/smoke-test/{smoke_id}/status")
    if code is None:
        st.caption("ต่อ backend ไม่ได้ชั่วคราว กำลังลองใหม่...")
        return
    if code != 200:
        st.session_state.smoke_result = {"passed": False, "error": f"Backend error ({code})"}
    elif data.get("status") == "done":
        st.session_state.smoke_result = data["result"]
    elif data.get("status") == "failed":
        st.session_state.smoke_result = {"passed": False, "error": data.get("error")}
    else:
        st.info("กำลังรัน smoke test...")
        return
    st.session_state.smoke_job_id = None
    st.rerun()


if st.session_state.smoke_job_id:
    watch_smoke(st.session_state.smoke_job_id)

smoke = st.session_state.smoke_result
smoke_ok = bool(smoke and smoke.get("passed"))
if smoke:
    if smoke.get("error"):
        st.error(f"Smoke test ล้มเหลว: {smoke['error']}")
    for check in smoke.get("checks", []):
        msg = f"{check['check']}: {check['detail']}"
        if check["ok"]:
            st.success(msg)
        else:
            st.error(msg)
    if smoke_ok:
        st.success("Smoke test ผ่านทุกข้อ พร้อมสแกนจริง")
    else:
        st.warning("Smoke test ยังไม่ผ่านบางข้อ ควรแก้ก่อน ไม่งั้นสแกนจริงน่าจะพังแบบเดียวกัน")


# ---------- 3. เริ่มสแกน ----------
st.header("3. เริ่มสแกน")

if not smoke_ok:
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

        try:
            resp = requests.post(f"{BACKEND_URL}/scan", json=payload, timeout=30)
        except requests.exceptions.RequestException as e:
            st.error(f"ต่อ backend ไม่ได้: {e}")
        else:
            if resp.status_code == 200:
                st.session_state.job_id = resp.json()["job_id"]
                st.query_params["job"] = st.session_state.job_id
                # job ใหม่ ล้าง cache ของ report เก่า
                st.session_state.report_cache_job_id = None
                st.session_state.report_cache_data = None
                st.success(f"เริ่มสแกนแล้ว (job {st.session_state.job_id[:8]})")
            else:
                st.error(f"เริ่มสแกนไม่ได้: {resp.text}")


# ---------- 4. สถานะและผลลัพธ์ ----------
@st.fragment(run_every=3)
def watch_job(job_id):
    """poll สถานะทุก 3 วินาทีแบบไม่บล็อกสคริปต์ พอ job จบ/ล้ม/หาย ก็สั่งวาดทั้งหน้าใหม่"""
    code, info = api_get(f"/scan/{job_id}/status")
    if code is None:
        st.warning("ต่อ backend ไม่ได้ชั่วคราว กำลังลองใหม่ (สแกนยังรันอยู่ที่ backend)")
        return
    if code != 200 or info.get("status") in ("done", "failed"):
        st.rerun()
    p = info.get("progress")
    if p and p.get("total"):
        st.progress(
            min(p["done"] / p["total"], 1.0),
            text=f"{p['label']} ({p['done']}/{p['total']} ขั้น)",
        )
    st.info(
        f"สถานะ: {info.get('status')} — เก็บลิงก์หน้านี้ไว้ได้ "
        "ปิดแล้วเปิดใหม่ก็กลับมาดูต่อได้"
    )


def forget_job():
    st.session_state.job_id = None
    st.query_params.clear()


job_done = False
job_id = st.session_state.job_id
if job_id:
    code, info = api_get(f"/scan/{job_id}/status")
    if code == 404:
        st.error("backend ไม่รู้จัก job นี้ (น่าจะ restart ไปแล้ว) ผลที่เซฟไว้จะอยู่ในโฟลเดอร์ results/")
        st.button("ล้างสถานะ", on_click=forget_job)
    elif code is not None and code != 200:
        st.error(f"Backend error ({code})")
        st.button("ล้างสถานะ", on_click=forget_job)
    elif code == 200 and info.get("status") == "failed":
        st.error(f"สแกนล้มเหลว: {info.get('error')}")
        st.button("ล้างสถานะ", on_click=forget_job)
    elif code == 200 and info.get("status") == "done":
        job_done = True
    else:
        # กำลังรัน/รอคิว หรือต่อ backend ไม่ได้ชั่วคราว
        watch_job(job_id)

if job_done:
    # ดึง report ครั้งเดียวต่อ job ที่เหลือใช้ cache (ไม่งั้นทุก rerun จะยิงซ้ำ)
    if st.session_state.report_cache_job_id == job_id:
        report = st.session_state.report_cache_data
    else:
        try:
            r = requests.get(f"{BACKEND_URL}/scan/{job_id}/report", timeout=30)
        except requests.exceptions.RequestException as e:
            st.error(f"ดึงรายงานไม่ได้ (ต่อ backend ไม่ติด): {e}")
            st.stop()
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
    html_resp = requests.get(f"{BACKEND_URL}/scan/{job_id}/report/html", timeout=30)
    if html_resp.status_code == 200:
        st.components.v1.html(link_files_to_backend(html_resp.text, job_id), height=900, scrolling=True)
        st.download_button(
            "ดาวน์โหลดรายงาน (HTML)",
            data=html_resp.text.encode("utf-8"),
            file_name=f"llm_security_report_{job_id[:8]}.html",
            mime="text/html",
        )
    else:
        st.warning(f"ดึงไฟล์ report จาก backend ไม่ได้ ({html_resp.status_code}): {html_resp.text}")

    csv_resp = requests.get(f"{BACKEND_URL}/scan/{job_id}/report/csv", timeout=30)
    if csv_resp.status_code == 200:
        st.download_button(
            "ดาวน์โหลด CSV (ทุกแถว)",
            data=csv_resp.content,
            file_name=f"llm_security_report_{job_id[:8]}.csv",
            mime="text/csv",
        )

    st.download_button(
        "ดาวน์โหลด CSV (สรุปต่อหมวด)",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name=f"scan_summary_{job_id[:8]}.csv",
        mime="text/csv",
    )