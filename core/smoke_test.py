"""
smoke_test.py — ทดสอบสแกนจริงขนาดจิ๋วเพื่อยืนยัน pipeline
"""

import time

from .runners.garak_runner import run_garak_scan
from .runners.promptmap2_runner import run_promptmap2_scan


def smoke_test_garak(model_name: str, timeout_sec: int | None = None) -> dict:
    """ยิง garak จริง แต่เลือก probe 'test' เพื่อเช็ค pipeline ให้เร็วที่สุด"""
    start = time.monotonic()
    try:
        rows = run_garak_scan(
            model_name=model_name,
            probes=["test.Blank"],  # แก้ตรงนี้: ใช้ probe สำหรับ test ระบบโดยเฉพาะ
            generations=1,
            timeout_sec=timeout_sec,
        )
    except Exception as exc:
        return {
            "check": "garak_smoke_scan",
            "ok": False,
            "detail": f"รัน garak จริงไม่สำเร็จ: {exc}",
            "rows": [],
        }

    elapsed = time.monotonic() - start

    if not rows:
        return {
            "check": "garak_smoke_scan",
            "ok": False,
            "detail": (
                f"garak subprocess รันจบใน {elapsed:.0f}s (ไม่ error) "
                "แต่ parse ผลลัพธ์ออกมาไม่ได้เลยสักแถว — เช็ค garak_parser.py"
            ),
            "rows": [],
        }

    return {
        "check": "garak_smoke_scan",
        "ok": True,
        "detail": f"garak รันจริงสำเร็จใน {elapsed:.0f}s ได้ {len(rows)} แถวผลลัพธ์ (probe: dan)",
        "rows": rows,
    }


def smoke_test_promptmap2(
    model_name: str,
    ollama_url: str = "http://localhost:11434",
    system_prompt_path: str = "system-prompt.txt",
    controller_model: str | None = None,
    controller_model_type: str | None = None,
    timeout_sec: int | None = None,  # ปิด timeout ตามที่ตกลงกันไว้ (2026-09) — เจอเคส
    # จริงว่า smoke test ไม่ได้ส่ง rule_types เลย ทำให้ promptmap2 รันทุก rule
    # ทุก type (distraction/harmful/hate/jailbreak/prompt_stealing/social_bias)
    # ไม่ใช่แค่ rule เดียวอย่างที่ comment เข้าใจผิดไว้ตอนแรก เกิน 600s ได้ง่ายมาก
    # ถ้าโมเดล local รันช้า (เช่นบน CPU) — ปิด timeout ไปก่อนจนกว่าจะจำกัด
    # rule_types ให้ smoke test เบาจริงๆ (ดู comment ใน run_smoke_test ด้านล่าง)
) -> dict:
    """ยิง promptmap2 จริง 1 iteration ต่อ rule"""
    start = time.monotonic()
    try:
        rows = run_promptmap2_scan(
            model_name=model_name,
            ollama_url=ollama_url,
            iterations=1,
            system_prompt_path=system_prompt_path,
            controller_model=controller_model,
            controller_model_type=controller_model_type,
            timeout_sec=timeout_sec,
        )
    except Exception as exc:
        return {
            "check": "promptmap2_smoke_scan",
            "ok": False,
            "detail": f"รัน promptmap2 จริงไม่สำเร็จ: {exc}",
            "rows": [],
        }

    elapsed = time.monotonic() - start

    if not rows:
        return {
            "check": "promptmap2_smoke_scan",
            "ok": False,
            "detail": (
                f"promptmap2 subprocess รันจบใน {elapsed:.0f}s (ไม่ error) "
                "แต่ parse ผลลัพธ์ออกมาไม่ได้เลยสักแถว"
            ),
            "rows": [],
        }

    return {
        "check": "promptmap2_smoke_scan",
        "ok": True,
        "detail": f"promptmap2 รันจริงสำเร็จใน {elapsed:.0f}s ได้ {len(rows)} แถวผลลัพธ์ (iterations=1)",
        "rows": rows,
    }


def run_smoke_test(target_config: dict, tools: list[str] | None = None) -> list[dict]:
    if target_config.get("type") != "ollama":
        return [{
            "check": "target_type",
            "ok": False,
            "detail": f"smoke test รองรับเฉพาะ target type 'ollama' ตอนนี้ (ได้ '{target_config.get('type')}')",
            "rows": [],
        }]

    tools = tools or ["garak", "promptmap2"]
    model_name = target_config["model"]
    results = []

    if "garak" in tools:
        results.append(smoke_test_garak(model_name))

    if "promptmap2" in tools:
        # ใช้ or เพื่อป้องกัน NoneType fallback fail
        ollama_url = target_config.get("base_url") or "http://localhost:11434"
        sys_path = target_config.get("system_prompt_path") or "system-prompt.txt"
        
        results.append(smoke_test_promptmap2(
            model_name=model_name,
            ollama_url=ollama_url,
            system_prompt_path=sys_path,
            controller_model=target_config.get("controller_model"),
            controller_model_type=target_config.get("controller_model_type"),
        ))

    return results


def smoke_test_passed(results: list[dict]) -> bool:
    return all(r["ok"] for r in results)

if __name__ == "__main__":
    import json
    from .selector import summarize_by_owasp

    # ตั้งค่า target config ให้ตรงกับโมเดลที่ใช้รัน (เช่น llama3.2:1b หรือ dolphin3)
    target_config = {
        "type": "ollama",
        "model": "llama3.2:1b", 
        "base_url": "http://localhost:11434"
    }

    print("🚀 เริ่มรัน Smoke Test...\n")
    results = run_smoke_test(target_config)

    all_raw_rows = []
    for r in results:
        print(("✅" if r["ok"] else "❌"), r["check"], "-", r["detail"])
        if r["ok"]:
            # เก็บผลลัพธ์ดิบของแต่ละ tool มารวมไว้ใน list เดียวกัน
            all_raw_rows.extend(r.get("rows", []))

    if smoke_test_passed(results):
        print("\n" + "="*60)
        print("📊 MOCK REPORT (โครงสร้างเดียวกับที่ API คืนค่าให้ Streamlit UI)")
        print("="*60)

        # จำลองการทำงานของ Backend: จัดกลุ่มผลลัพธ์ตาม OWASP Category
        summary = summarize_by_owasp(all_raw_rows)

        mock_api_report = {
            "summary": summary,
            "tool_plan": {
                "garak": ["LLM01", "LLM06", "LLM09"], 
                "promptmap2": ["LLM07"]
            },
            "raw_count": len(all_raw_rows),
            "raw_sample_first_2_rows": all_raw_rows[:2]  # โชว์โครงสร้าง raw data เป็นตัวอย่าง
        }

        # พิมพ์ JSON ออกมาดูโครงสร้าง
        print(json.dumps(mock_api_report, indent=2, ensure_ascii=False))
    else:
        print("\n⚠️ รันไม่ผ่าน กรุณาเช็ค error ด้านบน")