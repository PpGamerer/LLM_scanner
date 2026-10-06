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
ผูกผิด แต่เป็น LLM05 ผสมกับ LLM02 — ตอนนั้นเข้าใจว่าแยก subclass ได้ชัดเจน ซึ่งยังไม่ถูก
ทั้งหมด (ดูรอบสิบ)

แก้ไข 2026-10 (รอบสิบ): verify เพิ่มด้วย `garak --plugin_info` ตรงบนเครื่องจริง (ไม่ผ่าน
CLI parser, อ่าน tags attribute ตรงจาก source) เทียบกับ CSV export — เจอว่าความเข้าใจ
เรื่อง subclass-level split ของรอบเก้าไม่ถูกทั้งหมด:
  1. `ansiescape.AnsiEscaped`/`AnsiRaw` มี tag `owasp:llm01;owasp:llm02;owasp:llm05`
     (3 หมวดฉบับ 2023) ไม่ใช่ LLM05 ล้วนอย่างที่เคยผูกไว้ — แปลงเป็น 2025 แล้วหนึ่งใน
     สามคือ LLM03 (Supply Chain) ซึ่งไม่มีอยู่ใน OWASP_CATEGORIES ของระบบนี้เลย —
     เอา `ansiescape` ออกทั้งหมด
  2. `exploitation.JinjaTemplatePythonInjection`/`SQLInjectionEcho` มี tag
     `owasp:llm02;owasp:llm06` (2023) = LLM05+LLM02 (2025) คู่กันทั้งคู่ ไม่มีทางแยก
     subclass ได้ — เพิ่มเข้า LLM02 ด้วยผ่าน garak_probes_for_owasp()
  3. `web_injection.MarkdownXSS` เองก็มี tag แค่ `owasp:llm02;owasp:llm06` เหมือนกับ
     อีก 6 subclass เป๊ะ ไม่ได้ "ล้วน" แบบที่เข้าใจไปก่อนหน้า — ทุก subclass ของ
     web_injection เป็น LLM05+LLM02 คู่กันหมดทุกตัว ใช้ bare family key ได้ปลอดภัย

แก้ไข 2026-10 (รอบสิบเอ็ด): เพิ่ม GARAK_DUAL_CATEGORY_PROBES เป็น single source of
truth สำหรับ probe ที่ตรง concept มากกว่า 1 category — ของเดิมแก้แค่ฝั่ง "เลือกรัน"
(garak_probes_for_owasp เติม probe เข้า category รองให้) แต่ลืมฝั่ง "อ่านผลกลับมา
จัดหมวด" (garak_probe_to_owasp ยังคืนแค่ primary เดียว) ทำให้ผลของ probe dual-category
โดนกรองทิ้งเงียบๆ ตอน filter ด้วย category รอง — แก้ด้วย garak_probe_categories() ที่
คืนทุก category ที่ probe ตรง ใช้ตอน filter ผลสุดท้ายใน selector.py แทน

แก้ไข 2026-10 (รอบสิบสอง): ปิดจบสถานะ `promptinject` ที่ค้างไว้ตั้งแต่รอบสิบ — verify
ซ้ำกับ `garak --list_probes` วันที่ 2026-10-02 (เครื่องเดียวกับที่ verify
exploitation/web_injection ด้วย --plugin_info) ยืนยันชัดว่า `promptinject.
HijackHateHumans`, `.HijackKillHumans`, `.HijackLongPrompt` **active จริงทั้ง 3 ตัว**
มีแค่ 3 ตัว `*Full` เท่านั้นที่ dormant (💤) — ตรงกับ pattern เดียวกับทุก family อื่น
ในระบบ (ตัวเต็ม active, ตัว *Full dormant) ไม่ใช่ dormant ทั้ง family แบบที่เคยกังวลไว้
`"promptinject": "LLM01"` จึงถูกต้องตามเดิม ไม่ต้องแก้ — ปิดเป็น resolved
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
#
# ⚠️ เตือนซ้ำอีกชั้น: tag:owasp:llm01 ของ Garak (ฉบับ 2023) ดึง probe ปนมาเยอะกว่าที่
# คิด ไม่ใช่แค่ promptinject/dan/encoding ที่ curate ไว้ที่นี่ — sysprompt_extraction,
# latentinjection, phrasing, doctor, dra, sata, goodside.Tag,
# smuggling.HomoglyphObfuscation, adaptive_attacks ก็ติด owasp:llm01 (2023) เหมือนกัน
# ทั้งที่บางตัว curate ไว้เป็น category อื่นในไฟล์นี้ (เช่น sysprompt_extraction ->
# LLM07) — เป็นอีกเหตุผลที่ห้ามใช้ tag shorthand แม้แต่ "หมวดที่เลขนิ่งข้ามฉบับ" อย่าง
# LLM01 ต้องระบุชื่อ module ตรงๆ เสมอ (ยืนยันจากคู่มือทดสอบของทีมที่เจอปัญหานี้จริง)
GARAK_PROBE_OWASP_MAP = {
    # LLM01: Prompt Injection
    # verify แล้ว 2026-10 (รอบสิบสอง): active จริง 3/6 subclass (HijackHateHumans,
    # HijackKillHumans, HijackLongPrompt) — *Full variants dormant ตาม pattern ปกติ
    # ของทุก family ในระบบ ไม่ใช่ dormant ทั้ง family — ยืนยันซ้ำกับ --list_probes
    # 2026-10-02 แล้วว่าถูกต้อง ไม่ต้องเอาออก
    "promptinject": "LLM01",
    "dan": "LLM01",
    "encoding": "LLM01",       # prompt injection ผ่านการเข้ารหัส payload (base64/rot13/...)
    # LLM05: Improper Output Handling
    #
    # 2026-10 (รอบสิบ, ยืนยันซ้ำรอบสิบสองด้วย --plugin_info ตรง): ใช้ bare family key
    # ได้แล้วสำหรับ web_injection — ทุก subclass (รวม MarkdownXSS/TaskXSS ที่เคยคิดว่า
    # เป็น LLM05 ล้วนแยกจากตัวอื่น) มี tag `owasp:llm02;owasp:llm06` (2023) เหมือนกัน
    # หมดทุกตัว ไม่มีตัวไหนมี owasp:llm01 ปนเลย — แปลเป็น 2025 คือ LLM05+LLM02 คู่กัน
    # ทุก subclass ไม่ต้องแยกระดับ subclass อีกต่อไป ส่วน LLM02 เพิ่มให้ผ่าน
    # garak_probes_for_owasp() ด้านล่าง (pattern เดียวกับ divergence.Repeat)
    "web_injection": "LLM05",
    # exploitation: JinjaTemplatePythonInjection + SQLInjectionEcho active
    # (SQLInjectionSystem 💤) ทั้งคู่มี tag owasp:llm02;owasp:llm06 (2023) = LLM05+LLM02
    # เหมือนกันทั้งคู่ — verify ซ้ำด้วย --plugin_info ตรง 2026-10-02 แล้วตรงเป๊ะ ไม่มีทาง
    # แยก subclass ได้ — เพิ่มเข้า LLM02 ด้วยผ่าน garak_probes_for_owasp() เช่นกัน
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


# probe บางตัวใน GARAK_PROBE_OWASP_MAP ข้างบนตรง concept มากกว่า 1 OWASP category จริง
# (verify จาก garak tag metadata) แต่ dict ข้างบนเก็บได้แค่ 1 "primary" category ต่อ
# probe เท่านั้น (เป็น flat dict แบบ str -> str)
#
# ทั้ง garak_probes_for_owasp() (เลือกรัน) และ garak_probe_categories() (จัดหมวดผล
# ลัพธ์ตอน filter ใน selector.py) อ่านจาก dict เดียวนี้ กันสองฝั่งหลุด sync กัน (เจอ
# บั๊กนี้มาแล้วตอนรอบสี่ที่แก้แค่ฝั่งเดียว — ดูรายละเอียดใน README หัวข้อ "บั๊กที่ต้อง
# จำไว้")
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
    เข้าหลาย category (อ่านจาก GARAK_DUAL_CATEGORY_PROBES) เพราะ flat dict ผูก 1
    probe ได้แค่ 1 category เท่านั้น ถ้า probe ตัวหนึ่งต้องใช้กับ 2 category พร้อมกัน
    (ยืนยันจาก garak tag metadata จริงว่า dual-category) ต้องเติมเองแบบนี้ ไม่งั้นมัน
    จะหายไปจาก category หนึ่งเงียบๆ
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
