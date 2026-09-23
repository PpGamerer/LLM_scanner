"""
owasp_mapping.py — แหล่งความจริงเดียว (single source of truth) ผูก probe ของแต่ละ tool
เข้ากับ OWASP LLM Top 10 category

ทุก runner (garak_runner, giskard_runner, pyrit_runner, ...) import จากไฟล์นี้
ไฟล์เดียว แก้ที่เดียว ไม่ต้องตามแก้หลายที่

ปรับ/เพิ่ม probe ได้ตามที่ verify จริงจาก `garak --list_probes` บนเครื่องคุณ
"""

OWASP_CATEGORIES = {
    "LLM01": "Prompt Injection",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Excessive Agency",
    "LLM09": "Misinformation",
}

# Garak probe -> OWASP category
#
# แต่ละ category ผูกกับ probe ได้หลายตัว (ดู dict ด้านล่าง) — ใช้ตอนโหมด "deep"
# ส่วนโหมด "quick" ใช้ GARAK_QUICK_PROBES (ประกาศถัดจาก garak_probe_to_owasp())
# แทน ยิงแค่ probe ตัวแทน 1 ตัว/category พอ ไม่ต้องยิงครบทุกตัว — ดูการใช้งานจริง
# ที่ garak_probes_for_owasp(codes, depth=...) ด้านล่าง ถูกเรียกจาก selector.py
# ตาม depth ที่ user เลือกบน UI (quick/deep) ไม่ได้ผูกกับ PRESET_PROBES เดิมใน
# garak_runner.py อีกต่อไป (อันนั้นเหลือไว้เป็น fallback เฉพาะตอนเรียก
# run_garak_scan() ตรงๆ โดยไม่ผ่าน selector.py เช่น จาก smoke_test.py)
#
# ชื่อ probe family อ้างอิงจาก `garak --list_probes` (ดู docs.garak.ai) — ถ้า
# เพิ่ม/ลบ ต้อง verify กับเวอร์ชัน garak ที่ลงจริงบนเครื่องด้วย เพราะ probe
# ใหม่ๆ เพิ่มทุก release
GARAK_PROBE_OWASP_MAP = {
    # LLM01: Prompt Injection
    "promptinject": "LLM01",
    "dan": "LLM01",
    "encoding": "LLM01",       # prompt injection ผ่านการเข้ารหัส payload (base64/rot13/...)
    "web_injection": "LLM01",  # แก้จาก "xss" (ไม่มี probe family นี้จริง) — verify กับ
                                # `garak --list_probes` (v0.17.0) แล้ว family จริงคือ
                                # "web_injection" (มี web_injection.MarkdownXSS / TaskXSS
                                # อยู่ข้างใน) ของเดิม "xss" ไม่ match probe อะไรเลย ทำให้
                                # ตอนยิงโหมด deep ส่ง --probes ที่มีชื่อไม่รู้จักปนไป garak
                                # อาจ error ทั้ง subprocess ฉุด probe อื่นใน category
                                # เดียวกันพังไปด้วย
    # LLM06: Sensitive Information Disclosure
    "leakreplay": "LLM06",
    "divergence": "LLM06",     # divergence attack ที่ทำให้โมเดลหลุด memorized data
    # เดิมเคยลอง "propile" แทน "continuation" (ที่ไม่มีจริง) แต่ verify กับการรันจริง
    # แล้วพัง: ทุก subclass ของ propile family เป็น dormant/inactive by default
    # (PIILeakQuadruplet/Triplet/Twin/Unstructured ทำเครื่องหมาย 💤 หมดใน
    # `garak --list_probes` ไม่มีตัวไหน active เลย) พอส่งแค่ชื่อ family เฉยๆ garak
    # เลย error ทันที "all plugins in 'probes.propile' are marked inactive" —
    # เอาออกไปเลย ไม่หาตัวแทนใหม่ เพราะ leakreplay+divergence สอง family ด้านบน
    # มี subclass active อยู่แล้วเพียงพอสำหรับ LLM06 (verify แล้วว่าไม่ใช่ dormant
    # ทั้ง family เหมือน propile)
    # LLM07: System Prompt Leakage (garak เป็น tool เสริม — ตัวหลักคือ promptmap2)
    "latentinjection": "LLM07",
    # LLM09: Misinformation
    "misleading": "LLM09",
    "snowball": "LLM09",             # ถามคำถามที่ดันให้โมเดลตอบผิดแบบมั่นใจ
    "packagehallucination": "LLM09", # โมเดลแนะนำ package/library ที่ไม่มีจริง
}


# Quick-mode: probe ตัวแทน 1 ตัวต่อ category (ครอบคลุมน้อยกว่า แต่เร็วกว่ามาก) —
# ใช้ตอน user เลือกโหมด "quick" บน UI แทนที่จะยิงทุก probe ที่ map ไว้ใน
# GARAK_PROBE_OWASP_MAP (โหมด "deep") เลือกตัวที่คุ้มสุด/เป็นตัวแทนที่ดีสุดของ
# แต่ละ category ไว้ล่วงหน้า
GARAK_QUICK_PROBES = {
    "LLM01": "dan",
    "LLM06": "leakreplay",
    "LLM07": "latentinjection",
    "LLM09": "misleading",
}


def garak_probe_to_owasp(probe_name: str) -> str:
    """เช่น 'promptinject.HijackHateHumans' -> 'LLM01'"""
    short_name = (probe_name or "").split(".")[0]
    return GARAK_PROBE_OWASP_MAP.get(short_name, "Uncategorized")


def garak_probes_for_owasp(owasp_codes: list[str], depth: str = "deep") -> list[str]:
    """กลับทาง: จาก OWASP category ที่เลือก -> probe ของ Garak ที่ต้องยิง

    depth="deep" (ค่าเริ่มต้น): เอาทุก probe ที่ map ไว้ใน GARAK_PROBE_OWASP_MAP
    depth="quick": เอาแค่ probe ตัวแทน 1 ตัว/category จาก GARAK_QUICK_PROBES
    (เร็วกว่ามาก เหมาะกับเช็คคร่าวๆ ก่อนสแกนเต็มรูปแบบ)
    """
    if depth == "quick":
        return sorted({
            GARAK_QUICK_PROBES[code] for code in owasp_codes
            if code in GARAK_QUICK_PROBES
        })
    return sorted({
        probe for probe, code in GARAK_PROBE_OWASP_MAP.items()
        if code in owasp_codes
    })


# promptmap2 rule "type" (จาก YAML rule) -> OWASP category
# หมายเหตุ: ชื่อ type ต้องตรงกับโฟลเดอร์ rules/ จริงของ promptmap2
# (distraction, harmful, hate, jailbreak, prompt_stealing, social_bias — ดู README
# ส่วน "โครงสร้างไฟล์") — README เคยบันทึกว่าแก้ "harmful_content"/"bias" เป็น
# "harmful"/"social_bias" แล้ว แต่ของจริงในไฟล์นี้ยังเป็นชื่อเก่าอยู่ (ยืนยันจาก
# scan จริงที่ promptmap2 คืน type "distraction" มาได้ปกติ แต่ "harmful"/"social_bias"
# จะไม่มีทาง match กับ "harmful_content"/"bias" เดิม เลยเข้า Uncategorized แล้วโดนกรองทิ้ง
# เงียบๆ เหมือนที่ README อธิบายไว้ตอนแรกว่าเป็นบั๊ก) — แก้ชื่อให้ตรงแล้วในนี้
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
    """กลับทาง: จาก OWASP category ที่เลือก -> rule type ของ promptmap2 ที่ต้องสั่งรัน
    (ใช้ส่งเข้า --rule-type เพื่อไม่ให้ promptmap2 รันรวมทุก type แล้วมาปนกันตอน filter ทีหลัง)"""
    return sorted({
        rule_type for rule_type, code in PROMPTMAP2_TYPE_OWASP_MAP.items()
        if code in owasp_codes
    })


def owasp_label(code: str) -> str:
    name = OWASP_CATEGORIES.get(code, "Uncategorized")
    return f"{code}: {name}" if code in OWASP_CATEGORIES else name