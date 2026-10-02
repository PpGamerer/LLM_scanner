"""
owasp_mapping.py — แหล่งความจริงเดียว (single source of truth) ผูก probe ของแต่ละ tool
เข้ากับ OWASP LLM Top 10 (ฉบับ 2025)

ทุก runner (garak_runner, promptmap2_runner, promptfoo_runner, ...) import จากไฟล์นี้
ไฟล์เดียว แก้ที่เดียว ไม่ต้องตามแก้หลายที่

ปรับ/เพิ่ม probe ได้ตามที่ verify จริงจาก `garak --list_probes` บนเครื่องคุณ

แก้ไข 2026-09: เดิมเขียนเลข category ผิด — ปนเลข 2023 กับ 2025 โดยไม่รู้ตัว ยืนยันจาก
garak/data/tags.misp.tsv จริงแล้วว่า Garak's tag:owasp:llmXX ผูกกับฉบับ 2023 ทั้งระบบ
(ไม่ใช่ 2025) ส่วนโปรเจกต์นี้ตกลงยึดฉบับ 2025 — ห้ามใช้ tag:owasp:llmXX ของ Garak
ตรงๆ เด็ดขาด (เลขจะเพี้ยน) ให้เลือก probe ด้วยชื่อ module เท่านั้น

แก้ไข 2026-09 (รอบสอง-สี่): เพิ่ม Promptfoo, LLM10, และ verify LLM01/02/07/10 จาก
คู่มือทดสอบเทียบ Garak vs Promptfoo ของทีม — รายละเอียดดู comment ในแต่ละ dict ด้านล่าง

แก้ไข 2026-09 (รอบเก้า): เพิ่ม LLM05 (Improper Output Handling) — verify จาก CSV
metadata ของ garak เองว่า "web_injection" ทั้ง family ไม่ได้อยู่ LLM01 อย่างที่เคย
ผูกผิด แต่เป็น LLM05 (Insecure Output Handling ฉบับ 2023 = Improper Output Handling
ฉบับ 2025) ผสมกับ LLM02 (Sensitive Info ฉบับ 2023) — ตอนนั้นเข้าใจว่าแยก subclass ได้
ชัดเจน (MarkdownXSS/TaskXSS = LLM05 ล้วน, อีก 6 ตัว = LLM02 ล้วน) ซึ่ง**ยังไม่ถูกทั้งหมด**
— ดูการแก้ไขรอบสิบด้านล่าง

แก้ไข 2026-10 (รอบสิบ): verify เพิ่มด้วย `garak --plugin_info` ตรงบนเครื่องจริง (ไม่ผ่าน
CLI parser, อ่าน tags attribute ตรงจาก source) เทียบกับ CSV export — เจอว่าความเข้าใจ
เรื่อง subclass-level split ของรอบเก้าไม่ถูกทั้งหมด:
  1. `ansiescape.AnsiEscaped`/`AnsiRaw` มี tag `owasp:llm01;owasp:llm02;owasp:llm05`
     (3 หมวดฉบับ 2023) ไม่ใช่ LLM05 ล้วนอย่างที่เคยผูกไว้ — แปลงเป็น 2025 แล้วหนึ่งใน
     สามคือ LLM03 (Supply Chain) ซึ่ง**ไม่มีอยู่ใน OWASP_CATEGORIES ของระบบนี้เลย**
     เพิ่ม category ใหม่สำหรับ probe แค่ 2 ตัวไม่คุ้ม — **เอา `ansiescape` ออกทั้งหมด**
     (เหมือนที่เคยเอา `web_injection` ออกจาก LLM01 ทั้ง family ในรอบเก้า และเหมือนที่
     เอา `owasp:llm:01` ออกจาก promptfoo reverse-map ไปก่อนหน้า — pattern เดียวกัน:
     ถ้า probe ตัวหนึ่งพาดพิง category ที่ระบบไม่รองรับ และมีตัวอื่นที่ชัดเจนกว่าพอใช้
     อยู่แล้ว ให้ตัดออกไปเลยดีกว่าฝืนแยก)
  2. `exploitation.JinjaTemplatePythonInjection`/`SQLInjectionEcho` มี tag
     `owasp:llm02;owasp:llm06` (2023) = LLM05+LLM02 (2025) คู่กันทั้งคู่ ไม่มีทางแยก
     subclass แบบ web_injection ได้ (ทั้ง 2 ตัวเป็น dual-category เหมือนกันหมด ไม่ใช่
     บางตัว LLM05 ล้วนบางตัว LLM02 ล้วน) — ยังอยู่ LLM05 เหมือนเดิม แต่เพิ่มการ "แถม"
     เข้า LLM02 ด้วยผ่าน garak_probes_for_owasp() (pattern เดียวกับ divergence.Repeat
     ที่ใช้ร่วม LLM02+LLM10 อยู่แล้ว)
  3. **สำคัญที่สุด**: `web_injection.MarkdownXSS` เอง (ที่เคยคิดว่า "LLM05 ล้วน" แยก
     ออกจากอีก 6 subclass ที่เป็น LLM02) จริงๆ มี tag แค่ `owasp:llm02;owasp:llm06`
     เหมือนกับอีก 6 ตัวเป๊ะ — **ไม่มี owasp:llm01 ปนอยู่เลย และไม่ได้ "ล้วน" แบบที่
     เข้าใจไปก่อนหน้า** สรุปคือทุก subclass ของ web_injection (รวม MarkdownXSS/TaskXSS)
     เป็น LLM05+LLM02 คู่กันหมดทุกตัว ไม่ต่างกันเลย — เลยไม่ต้องแยกระดับ subclass อีก
     ต่อไป ใช้ bare family key "web_injection" ได้ปลอดภัย (ตรงกับที่ verify แล้วว่า
     ทุก subclass active ไม่มีตัวไหน 💤) แล้วแถมเข้า LLM02 ด้วย pattern เดียวกับ
     exploitation ข้อ 2
  **บทเรียนจากรอบนี้**: เจอ "exploitation"/"web_injection" ที่ดูเหมือนแยก subclass
  ได้ (เหมือน divergence.Repeat/.RepeatedToken ในรอบสี่) แต่จริงๆ ไม่ใช่ — ทุก
  subclass ที่ active ของทั้งสอง family นี้เป็น dual-category เหมือนกันหมด ก่อนจะ
  แยก subclass ต้อง verify ทีละตัวจริงๆ (`--plugin_info` หรืออ่าน `.tags` จาก source
  ตรงๆ) ไม่ใช่เดาจากชื่อ subclass ว่า "น่าจะ" ต่างหมวดกัน

⚠️ ยังไม่ชี้ขาด (ณ 2026-10): `promptinject` ยังอยู่ใน GARAK_PROBE_OWASP_MAP ด้านล่าง
(ไม่ได้เอาออก) แม้ `--list_probes` รอบก่อนจะโชว์ว่า subclass ที่รู้จัก 6 ตัวเป็น 💤
หมด — เอกสารเปรียบเทียบ Garak vs Promptfoo ของทีมแย้งว่า active (✅) โดยไม่ breakdown
ระดับ subclass ให้ดู ยังไม่มีใครรัน `garak --probes promptinject` จริงเพื่อชี้ขาดว่า
error "all plugins marked inactive" หรือไม่ — เก็บไว้ตามเดิมจนกว่าจะมีผลทดสอบจริง
"""

OWASP_CATEGORIES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",   # เดิมเขียนผิดเป็น LLM06 (เลข 2023)
    "LLM05": "Improper Output Handling",            # เพิ่ม 2026-09 (รอบเก้า)
    "LLM06": "Excessive Agency",                    # เดิมเขียนผิดเป็น LLM08 (เลข 2023)
    "LLM07": "System Prompt Leakage",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# ============================================================================
# Garak probe -> OWASP category (2025)
# ============================================================================
#
# ⚠️ ห้ามใช้ Garak's tag:owasp:llmXX แทนชื่อ probe ในไฟล์นี้ — เลข tag ของ Garak
# ผูกกับฉบับ 2023 ไม่ใช่ 2025 ที่ใช้ในไฟล์นี้ (ตารางเทียบ 2023->2025 ที่เกี่ยวกับ
# ไฟล์นี้: llm02(2023 Insecure Output Handling)->LLM05, llm06(2023 Sensitive Info
# Disclosure)->LLM02, llm08(2023 Excessive Agency)->LLM06, llm09(2023
# Overreliance)->LLM09(Misinformation, คนละความหมายกันเป๊ะๆ), llm10(2023 Model
# Theft)->LLM10(Unbounded Consumption, รวม concept เก่าสองอันเข้าด้วยกัน)) ถ้าจะ
# cross-reference กับเลข tag เดิมของ Garak ให้เช็คตารางเทียบแยกต่างหาก อย่าเอามาปน
# กับ dict นี้
GARAK_PROBE_OWASP_MAP = {
    # LLM01: Prompt Injection
    # ⚠️ ยังไม่ชี้ขาด (ดู docstring หัวไฟล์) — เก็บไว้ตามเดิม ไม่เอาออก
    "promptinject": "LLM01",
    "dan": "LLM01",
    "encoding": "LLM01",       # prompt injection ผ่านการเข้ารหัส payload (base64/rot13/...)
    # LLM05: Improper Output Handling
    #
    # 2026-10 (รอบสิบ): ใช้ bare family key ได้แล้วสำหรับ web_injection — verify ด้วย
    # `--plugin_info` ตรงบนเครื่องจริงว่าทุก subclass (รวม MarkdownXSS/TaskXSS ที่
    # เคยคิดว่าเป็น LLM05 ล้วนแยกจากตัวอื่น) มี tag `owasp:llm02;owasp:llm06` (2023)
    # เหมือนกันหมดทุกตัว ไม่มีตัวไหนมี owasp:llm01 ปนเลย — แปลเป็น 2025 คือ LLM05+LLM02
    # คู่กันทุก subclass ไม่ต้องแยกระดับ subclass อีกต่อไป (ของเดิมที่เคยแยกไว้ 8 บรรทัด
    # เป็นความเข้าใจผิด — ดู docstring หัวไฟล์ข้อ 3) ส่วน LLM02 เพิ่มให้ผ่าน
    # garak_probes_for_owasp() ด้านล่าง (pattern เดียวกับ divergence.Repeat)
    "web_injection": "LLM05",
    # exploitation: JinjaTemplatePythonInjection + SQLInjectionEcho active
    # (SQLInjectionSystem 💤) ทั้งคู่มี tag owasp:llm02;owasp:llm06 (2023) = LLM05+LLM02
    # เหมือนกันทั้งคู่ ไม่มีทางแยก subclass ได้ (verify ด้วย --plugin_info แล้ว) —
    # เพิ่มเข้า LLM02 ด้วยผ่าน garak_probes_for_owasp() เช่นกัน
    "exploitation": "LLM05",
    # "ansiescape" เอาออกแล้ว (2026-10 รอบสิบ) — verify ด้วย --plugin_info ว่า
    # AnsiEscaped/AnsiRaw มี tag owasp:llm01;owasp:llm02;owasp:llm05 (2023) สามหมวด
    # ไม่ใช่ LLM05 ล้วน แปลงเป็น 2025 แล้วหนึ่งในสามคือ LLM03 (Supply Chain) ที่ไม่มีใน
    # OWASP_CATEGORIES เลย เพิ่ม category ใหม่สำหรับ probe แค่ 2 ตัวไม่คุ้ม
    #
    # LLM02: Sensitive Information Disclosure (เดิมผูกผิดเป็น LLM06)
    "leakreplay": "LLM02",
    "divergence.Repeat": "LLM02",  # divergence attack ที่ทำให้โมเดลหลุด memorized data
    # เดิมเคยลอง "propile" แทน "continuation" (ที่ไม่มีจริง) แต่ verify กับการรันจริง
    # แล้วพัง: ทุก subclass ของ propile family เป็น dormant/inactive by default
    # — เอาออกไปเลย ไม่หาตัวแทนใหม่ เพราะ leakreplay+divergence.Repeat เพียงพอแล้ว
    # LLM07: System Prompt Leakage
    "sysprompt_extraction.SystemPromptExtraction": "LLM07",
    "latentinjection": "LLM07",  # concept จริงใกล้ indirect prompt injection (LLM01)
                                  # มากกว่า แต่เก็บไว้เป็นตัวเสริม ไม่เอาออก
    # LLM09: Misinformation
    "misleading": "LLM09",
    "snowball": "LLM09",             # active จริงแค่ GraphConnectivity (1/6 subclass)
    "packagehallucination": "LLM09",
    # LLM06: Excessive Agency — ยังไม่มี probe ของ Garak ที่ active ตรง concept นี้
    # (มีแค่ agent_breaker.AgentBreaker ซึ่ง inactive by default) — ใช้ Promptfoo
    # เป็นตัวหลักแทน (ดู PROMPTFOO_PLUGIN_OWASP_MAP ด้านล่าง)
    # LLM10: Unbounded Consumption
    "divergence.RepeatedToken": "LLM10",  # คู่กับ divergence.Repeat เสมอ (deep mode)
}


# ⚠️ 2026-10 (รอบสิบเอ็ด): probe บางตัวใน GARAK_PROBE_OWASP_MAP ข้างบนตรง concept
# มากกว่า 1 OWASP category จริง (verify จาก garak tag metadata) แต่ dict ข้างบนเก็บได้
# แค่ 1 "primary" category ต่อ probe เท่านั้น (เป็น flat dict แบบ str -> str)
#
# เดิมแก้ปัญหานี้แค่ "ฝั่งเลือกรัน" (garak_probes_for_owasp เติม probe เข้า category
# รองให้ด้วย) แต่ลืม "ฝั่งอ่านผลกลับมาจัดหมวด" (garak_probe_to_owasp ยังคืนแค่
# primary category เดียวเสมอ) ผลคือ: รัน probe ถูกตัวแล้วจริง แต่พอ selector.py
# filter ผลสุดท้ายด้วย `owasp_category in categories` แถวที่มาจาก probe dual-category
# จะโดนกรองทิ้งเงียบๆ ถ้า user ขอ category รองที่ไม่ใช่ primary (เช่น ขอ LLM10
# อย่างเดียว แต่ divergence.Repeat ถูก parse เป็น LLM02 เสมอ เลยหายจากผล LLM10)
#
# แก้ด้วย dict เดียวนี้เป็น single source of truth — ทั้ง garak_probes_for_owasp()
# (เลือกรัน) และ garak_probe_categories() (จัดหมวดผลลัพธ์ตอน filter ใน selector.py)
# อ่านจาก dict เดียวกันนี้ กันสองฝั่งหลุด sync กันอีกแบบที่เคยเกิดมาแล้ว
#
# key = ชื่อ probe เดียวกับที่ใช้เป็น key ใน GARAK_PROBE_OWASP_MAP (primary category
# อยู่ที่นั่นแล้ว ไม่ต้องเขียนซ้ำ) value = list ของ category "เพิ่มเติม" ที่ probe นี้
# ก็ตรง concept ด้วยเหมือนกัน (verify แล้วจาก tag metadata จริง ไม่ใช่เดา)
GARAK_DUAL_CATEGORY_PROBES = {
    "divergence.Repeat": ["LLM10"],  # primary LLM02 (ดู GARAK_PROBE_OWASP_MAP ด้านบน)
    "web_injection": ["LLM02"],      # primary LLM05
    "exploitation": ["LLM02"],       # primary LLM05
}


def garak_probe_categories(probe_name: str) -> list[str]:
    """คืน list ของ**ทุก** OWASP category ที่ probe นี้ตรง concept ด้วย (primary +
    extra จาก GARAK_DUAL_CATEGORY_PROBES) ต่างจาก garak_probe_to_owasp() ที่คืนแค่
    primary เดียว — ใช้ฟังก์ชันนี้ตอน filter ผลลัพธ์สุดท้ายใน selector.py แทน
    เพื่อไม่ให้แถว dual-category โดนกรองทิ้งเงียบๆ (ดู comment เหนือ
    GARAK_DUAL_CATEGORY_PROBES ด้านบน)
    """
    primary = garak_probe_to_owasp(probe_name)
    parts = (probe_name or "").split(".")
    class_key = f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else None
    family = parts[0] if parts else ""
    extra = GARAK_DUAL_CATEGORY_PROBES.get(class_key) or GARAK_DUAL_CATEGORY_PROBES.get(family) or []
    cats = set(extra)
    if primary != "Uncategorized":
        cats.add(primary)
    return sorted(cats)


# Quick-mode: probe ตัวแทน 1 ตัวต่อ category
GARAK_QUICK_PROBES = {
    "LLM01": "dan",
    "LLM02": "leakreplay",
    # 2026-10 (รอบสิบ): เปลี่ยนจาก "ansiescape" (เอาออกจาก GARAK_PROBE_OWASP_MAP แล้ว)
    # เป็น web_injection.MarkdownXSS — ยังใช้เป็นตัวแทนได้ตามเดิม แค่ไม่ใช่ "LLM05 ล้วน"
    # อีกต่อไป (เป็น LLM05+LLM02 เหมือน subclass อื่นในตระกูลเดียวกันหมด)
    "LLM05": "web_injection.MarkdownXSS",
    "LLM07": "sysprompt_extraction.SystemPromptExtraction",
    "LLM09": "misleading",
    "LLM10": "divergence.RepeatedToken",
}


def garak_probe_to_owasp(probe_name: str) -> str:
    """เช่น 'divergence.RepeatedToken' -> 'LLM10', 'divergence.Repeat' -> 'LLM02'
    (subclass ของ family เดียวกันแยกคนละ category กัน — ต่างจาก web_injection/
    exploitation ที่ทุก subclass อยู่ category เดียวกันหมด เลยใช้ bare family key ได้)

    ลำดับการหา: เช็คแบบเจาะจง 'family.ClassName' ก่อน ถ้าไม่เจอค่อย fallback ไปหา
    แบบ 'family' เฉยๆ
    """
    parts = (probe_name or "").split(".")
    if len(parts) >= 2:
        class_key = f"{parts[0]}.{parts[1]}"
        if class_key in GARAK_PROBE_OWASP_MAP:
            return GARAK_PROBE_OWASP_MAP[class_key]
    family = parts[0] if parts else ""
    return GARAK_PROBE_OWASP_MAP.get(family, "Uncategorized")


def garak_probes_for_owasp(owasp_codes: list[str], depth: str = "deep") -> list[str]:
    """กลับทาง: จาก OWASP category ที่เลือก -> probe ของ Garak ที่ต้องยิง

    depth="deep": ทุก probe ที่ map ไว้ใน GARAK_PROBE_OWASP_MAP บวก probe ที่ "แถม"
    เข้าหลาย category (ดู 3 if ด้านล่าง — divergence.Repeat เข้า LLM10 ด้วย,
    web_injection/exploitation เข้า LLM02 ด้วย) เพราะ flat dict ผูก 1 probe ได้แค่
    1 category เท่านั้น ถ้า probe ตัวหนึ่งต้องใช้กับ 2 category พร้อมกัน (ยืนยันจาก
    garak tag metadata จริงว่า dual-category) ต้องเติมเองแบบนี้ ไม่งั้นมันจะหายไปจาก
    category หนึ่งเงียบๆ (บทเรียนจากรอบสี่ที่เจอกับ divergence.Repeat ครั้งแรก)
    depth="quick": probe ตัวแทน 1 ตัว/category จาก GARAK_QUICK_PROBES (ไม่บวกเพิ่ม)
    """
    if depth == "quick":
        return sorted({
            GARAK_QUICK_PROBES[code] for code in owasp_codes
            if code in GARAK_QUICK_PROBES
        })
    result = {
        probe for probe, code in GARAK_PROBE_OWASP_MAP.items()
        if code in owasp_codes
    }
    # 2026-10 (รอบสิบเอ็ด): เปลี่ยนจาก if-block แยกทีละ probe (ของเดิม 2 if ตายตัว
    # สำหรับ divergence.Repeat/web_injection/exploitation) เป็น loop อ่านจาก
    # GARAK_DUAL_CATEGORY_PROBES ตัวเดียว — กันไม่ให้ "ฝั่งเลือกรัน" (ตรงนี้) กับ
    # "ฝั่งจัดหมวดผลลัพธ์" (garak_probe_categories ด้านบน) หลุด sync กันอีก ถ้าเพิ่ม
    # probe dual-category ตัวใหม่ แก้ที่ GARAK_DUAL_CATEGORY_PROBES ที่เดียวพอ
    for probe, extra_categories in GARAK_DUAL_CATEGORY_PROBES.items():
        if any(c in owasp_codes for c in extra_categories):
            result.add(probe)
    return sorted(result)


# ============================================================================
# promptmap2 rule "type" -> OWASP category (2025)
# ============================================================================
PROMPTMAP2_TYPE_OWASP_MAP = {
    "prompt_stealing": "LLM07",   # System Prompt Leakage
    "jailbreak": "LLM01",         # Prompt Injection
    "distraction": "LLM01",
    "harmful": "LLM09",           # เดิมเขียนผิดเป็น "harmful_content"
    "social_bias": "LLM09",       # เดิมเขียนผิดเป็น "bias"
}


def promptmap2_type_to_owasp(rule_type: str) -> str:
    return PROMPTMAP2_TYPE_OWASP_MAP.get(rule_type, "Uncategorized")


def promptmap2_rule_types_for_owasp(owasp_codes: list[str]) -> list[str]:
    return sorted({
        rule_type for rule_type, code in PROMPTMAP2_TYPE_OWASP_MAP.items()
        if code in owasp_codes
    })


# ============================================================================
# Promptfoo plugin -> OWASP category (2025)
# ============================================================================
#
# ⚠️ "overreliance" map ไว้ที่ LLM06 (ไม่ใช่ LLM09) โดยตั้งใจ — ยืนยันจากคู่มือ
# เปรียบเทียบของทีมว่า overreliance เป็นแนวคิดเฉพาะฉบับ 2023 ไม่ตรงนิยาม
# Misinformation:2025 ตรงๆ (official OWASP ยืนยันแล้ว) แม้ doc ของ promptfoo เองจะ
# ใช้ตัวอย่างซ้ำทั้งสองที่ก็ตาม
PROMPTFOO_PLUGIN_OWASP_MAP = {
    # LLM01: Prompt Injection — ใช้เป็น cross-check คู่กับ garak (ตัวหลักเดิม)
    "owasp:llm:01": "LLM01",
    # LLM02: Sensitive Information Disclosure — คนละ concept กับ garak: garak วัดว่า
    # โมเดล "จำ" อะไรจาก training data, promptfoo pii:* วัดว่าระบบ "รั่ว" อะไรที่ป้อน
    # เข้าไปตอนรันไทม์ — แยกดูเป็น sub-test อย่ารวมเมตริกเดียว
    "pii:direct": "LLM02",
    "pii:session": "LLM02",
    "pii:social": "LLM02",
    "pii:api-db": "LLM02",
    "harmful:privacy": "LLM02",
    # LLM06: Excessive Agency — ตัวหลัก (garak ไม่มีตัวที่ active ตรง concept)
    "excessive-agency": "LLM06",
    "overreliance": "LLM06",
    "imitation": "LLM06",
    "hijacking": "LLM06",
    "rbac": "LLM06",
    # LLM07: System Prompt Leakage — ต้องมี config.systemPrompt กำกับด้วย
    "prompt-extraction": "LLM07",
    # LLM09: Misinformation
    "hallucination": "LLM09",
    # LLM10: Unbounded Consumption — ตัวหลัก (garak ไม่มี probe ที่ verify แล้วตรง
    # concept นี้เหมือน LLM06)
    "divergent-repetition": "LLM10",
}


# Quick-mode: plugin ตัวแทน 1 ตัวต่อ category
PROMPTFOO_QUICK_PLUGINS = {
    "LLM01": "owasp:llm:01",
    "LLM02": "pii:direct",
    "LLM06": "excessive-agency",
    "LLM07": "prompt-extraction",
    "LLM09": "hallucination",
    "LLM10": "divergent-repetition",
}

def promptfoo_plugin_to_owasp(plugin_id: str) -> str:
    """เช่น 'pii:direct' -> 'LLM02', 'owasp:llm:01' -> 'LLM01'

    promptfoo อาจคืน pluginId มาพร้อม prefix 'promptfoo:redteam:' นำหน้า — ตัด prefix
    นี้ออกก่อนเทียบกับ PROMPTFOO_PLUGIN_OWASP_MAP เสมอ กัน silent fallback เป็น
    Uncategorized
    """
    normalized = plugin_id
    if normalized.startswith("promptfoo:redteam:"):
        normalized = normalized[len("promptfoo:redteam:"):]
    return PROMPTFOO_PLUGIN_OWASP_MAP.get(normalized, "Uncategorized")


def promptfoo_plugins_for_owasp(owasp_codes: list[str], depth: str = "deep") -> list[str]:
    """กลับทาง: จาก OWASP category ที่เลือก -> plugin ของ promptfoo ที่ต้องยิง"""
    if depth == "quick":
        return sorted({
            PROMPTFOO_QUICK_PLUGINS[code] for code in owasp_codes
            if code in PROMPTFOO_QUICK_PLUGINS
        })
    return sorted({
        plugin for plugin, code in PROMPTFOO_PLUGIN_OWASP_MAP.items()
        if code in owasp_codes
    })


def owasp_label(code: str) -> str:
    name = OWASP_CATEGORIES.get(code, "Uncategorized")
    return f"{code}: {name}" if code in OWASP_CATEGORIES else name