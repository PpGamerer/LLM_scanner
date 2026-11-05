# LLM Vulnerability Scanning Platform

โครงตามสถาปัตยกรรม 3 ชั้น: **Core Engine (Python)** → **API (FastAPI)** → **UI (Streamlit)** → **Docker Compose**

## แนวคิดหลัก: ระบบเลือก tool ให้เอง ไม่ใช่ user เลือก (แต่ override ได้)

User เลือกแค่ **target** (Ollama model) และ **OWASP category ที่อยากทดสอบ**
(เช่น LLM01, LLM07) — ไม่ต้องรู้จัก Garak/promptmap2/Promptfoo/Giskard/PyRIT เลย
ก็สแกนได้ทันที

`core/selector.py` คือส่วนที่ตัดสินใจแทน user ผ่าน 2 dict แยกกัน (**ดีไซน์ปัจจุบัน
ตั้งแต่รอบ 7** — ไม่ใช่ `CATEGORY_TOOL_MAP` แบบ list เดียวแล้ว):

```python
# tool ไหน "ทำหมวดนี้ได้บ้าง" — verify แล้วจากการเทียบ probe/plugin/rule จริง
CATEGORY_CAPABLE_TOOLS = {
    "LLM01": ["garak", "promptfoo"],
    "LLM02": ["garak", "promptfoo"],
    "LLM05": ["garak"],                    # ดูหัวข้อ "LLM05" ด้านล่าง
    "LLM06": ["promptfoo"],                # garak ไม่มี probe active ตรง concept นี้
    "LLM07": ["promptmap2", "garak", "promptfoo"],
    "LLM09": ["garak", "promptfoo"],
    "LLM10": ["garak", "promptfoo"],
}

# ตัวที่เลือกให้อัตโนมัติถ้า user ไม่ได้สั่งผ่าน tool_overrides
CATEGORY_DEFAULT_TOOL = {
    "LLM01": "garak", "LLM02": "garak", "LLM05": "garak",
    "LLM06": "promptfoo", "LLM07": "promptfoo", "LLM09": "garak", "LLM10": "promptfoo",
}
```

ของเดิม (ก่อนรอบ 7) ใช้ `CATEGORY_TOOL_MAP` เป็น `{category: [tool, tool, ...]}`
เดียว ตั้งใจให้รันทุก tool ใน list "พร้อมกันเสมอ" เพื่อ cross-validate — แต่ในทาง
ปฏิบัติไม่เคยถูกตั้งค่าให้รันคู่จริงสักหมวด (list มีแค่ tool เดียวแทบทุกที่อยู่แล้ว)
เลยเปลี่ยนดีไซน์: **default รัน 1 tool/หมวดเหมือนเดิม** แต่เปิดช่องให้ user สั่ง
`tool_overrides` (เช่น `{"LLM07": "garak"}`) ผ่าน body ของ `POST /scan` ได้ ถ้าอยาก
ลอง tool อื่นในหมวดเดียวกันแทน — `resolve_tool_plan()` เป็นคนตัดสินจริง (fallback
ไป default เงียบๆ ถ้า override ไม่ใช่ตัวเลือกที่หมวดนั้นรองรับ ไม่ raise error)

ผลลัพธ์หลังสแกนจะมี `tool_plan` บอกด้วยว่าแต่ละ category ใช้ tool ไหน (โชว์บน UI
ผ่าน `GET /owasp_categories` ที่คืน `{code: {label, tools, default_tool}}`) เพื่อ
ความโปร่งใส — ตอบคำถาม "ทำไมเลือก tool นี้" ได้ทันทีถ้าถูกซักในห้องสอบ

**หมายเหตุ**: category `LLM08` (Vector and Embedding Weaknesses) **ยังไม่**อยู่ใน
`OWASP_CATEGORIES` เลยตอนนี้ — ไม่มีทั้ง garak/promptfoo ที่ตรง concept นี้เลย ต้องรอ
`pyrit_runner.py` + custom RAG scenario ก่อนถึงจะเพิ่มเข้า UI ได้ (`LLM03`, `LLM04`
ก็เช่นกัน — ไม่มี probe/plugin สำเร็จรูปตรง concept ในทั้งสอง tool)

## คำเตือนสำคัญ: ห้ามใช้ `tag:owasp:llmXX` ของ Garak เลยสักหมวด แม้แต่ LLM01

เคยเข้าใจว่า LLM01 เป็น "หมวดที่เลขนิ่งข้ามฉบับ" จึงใช้ `tag:owasp:llm01` (shorthand)
ได้อย่างปลอดภัย — **เข้าใจผิด** คู่มือทดสอบของทีมเจอจริงว่า `tag:owasp:llm01` (ฉบับ
2023 ของ Garak) ดึง probe ปนมาเยอะกว่าที่ curate ไว้ใน `GARAK_PROBE_OWASP_MAP` มาก:
นอกจาก `promptinject`/`dan`/`encoding` แล้ว ยังมี `sysprompt_extraction` (curate ไว้
เป็น **LLM07** ในระบบนี้), `latentinjection`, `phrasing`, `doctor`, `dra`, `sata`,
`goodside.Tag`, `smuggling.HomoglyphObfuscation`, `adaptive_attacks` ติด tag นี้ด้วย
ทั้งหมด — **ต้องระบุชื่อ module ตรงๆ เสมอทุกหมวด ไม่มีข้อยกเว้น** (`probes.promptinject,
probes.dan,probes.encoding` สำหรับ LLM01) ห้ามใช้ `tag:owasp:llmXX` เป็น shortcut
แม้แต่หมวดเดียว

⚠️ **ถ้าทดสอบด้วย `garak --probes <family>` ผ่าน CLI มือ**: flag `--probes`
(deprecated ตั้งแต่ v0.15.1.pre1) จะขึ้น `"nothing to do"` ถ้าใส่ชื่อ family เดี่ยว
ไม่มีคอมม่าคั่น แม้ family นั้น active จริง — ยืนยันแล้ว (2026-10 รอบสิบสาม) ทั้ง `dan`
(รู้แน่ชัดว่า active) และ `promptinject` ได้ผล `"nothing to do"` เหมือนกันทุกตัวอักษร
ไม่เกี่ยวกับสถานะ active/dormant ใดๆ เลย **ไม่กระทบ pipeline จริง** เพราะ
`garak_runner.py` ส่ง `",".join(probes)` เสมอ ไม่เคยส่งชื่อ family เดี่ยวผ่าน flag นี้
— ถ้าจะทดสอบ CLI มือ ใส่อย่างน้อย 2 probe คั่นด้วยคอมม่าเสมอ หรือใช้ `--spec` แทน
ตามที่คู่มือทดสอบของทีมใช้อยู่

## LLM05 (Improper Output Handling) — เพิ่มใหม่ (2026-09/10 รอบเก้า-สิบ)

ตอนแรกคิดว่า `web_injection` ทั้ง family ควรอยู่ LLM01 (ผูกไว้แบบนั้นมาตั้งแต่ต้น) —
verify จาก `garak` tag metadata จริง (`--plugin_info`, เทียบกับ CSV export) แล้วพบว่า
**ผิด**: ทุก subclass ของ `web_injection` มี tag `owasp:llm02;owasp:llm06` (ฉบับ 2023)
ไม่มีตัวไหนติด `owasp:llm01` เลย แปลเป็นฉบับ 2025 คือ **LLM05 (Improper Output
Handling) + LLM02 (Sensitive Info Disclosure) คู่กันทุก subclass** ไม่ใช่ LLM01

ระหว่างแก้ยังเจอรายละเอียดเพิ่มอีก 2 รอบ:
- ตอนแรกเข้าใจว่าแยก subclass ได้ชัดเจน (`MarkdownXSS`/`TaskXSS` = LLM05 "ล้วน", อีก
  6 subclass ที่เหลือ = LLM02 "ล้วน") — **ก็ยังผิด**: verify ซ้ำด้วย `--plugin_info`
  ตรงบนเครื่องแล้วพบว่า `MarkdownXSS` เองก็มี tag `owasp:llm02;owasp:llm06` เหมือน
  อีก 6 ตัวเป๊ะ ไม่ได้ "ล้วน" ตามที่เข้าใจ — เลยเปลี่ยนมาใช้ **bare family key
  `"web_injection"`** (ปลอดภัยเพราะทุก subclass อยู่ dual-category เดียวกันหมด) แทน
  การแยกระดับ subclass ที่เคยทำไว้ — **ยืนยันซ้ำอีกรอบ (2026-10-02) ด้วย
  `--plugin_info probes.web_injection.MarkdownXSS` ตรงๆ ผลตรงกันเป๊ะ ปิดเป็น
  resolved แล้ว**
- `exploitation` (`JinjaTemplatePythonInjection`, `SQLInjectionEcho`) ก็ dual-category
  เดียวกัน (LLM05+LLM02) — ยืนยันแล้วว่าไม่มีทางแยก subclass ได้เหมือนกัน (verify ซ้ำ
  2026-10-02 ด้วย `--plugin_info` ตรงทั้ง 2 probe ผลตรงกันเป๊ะ ปิดเป็น resolved)
- `ansiescape` เคยถูกผูกไว้ที่ LLM05 ด้วย (คิดว่าเบาและชัดเจนสุด) แต่ verify แล้วว่า
  tag จริงคือ `owasp:llm01;owasp:llm02;owasp:llm05` (3 หมวดฉบับ 2023!) แปลงเป็น 2025
  แล้วหนึ่งในสามคือ **LLM03 (Supply Chain) ที่ไม่มีอยู่ใน `OWASP_CATEGORIES` ของระบบ
  นี้เลย** — เพิ่ม category ใหม่สำหรับ probe แค่ 2 ตัวไม่คุ้ม **เอาออกทั้งหมด**

**Promptfoo ยังไม่รองรับ LLM05** — ตามแผนของทีม ฝั่งนี้ต้องเขียน custom assertion เอง
(เช่น `not-contains '<script>'`, JS assertion เช็ค SQL/shell pattern) ไม่ใช่ plugin
สำเร็จรูปเหมือนหมวดอื่น เลยยังไม่มี runner รองรับใน codebase นี้ — `CATEGORY_CAPABLE_TOOLS["LLM05"]`
มีแค่ `["garak"]` ตัวเดียว

✅ **`promptinject` (LLM01) — ปิดจบแล้ว (2026-10 รอบสิบสอง)**: เคยกังวลว่า
`--list_probes` รอบก่อนโชว์ว่า subclass ที่รู้จัก 6 ตัวเป็น 💤 (dormant) หมด ขัดกับ
เอกสารเปรียบเทียบของทีมที่บอกว่า active — verify ซ้ำกับ `--list_probes` วันที่
2026-10-02 ยืนยันชัดว่า `HijackHateHumans`/`HijackKillHumans`/`HijackLongPrompt`
**active จริงทั้ง 3 ตัว** มีแค่ 3 ตัว `*Full` เท่านั้นที่ dormant (pattern เดียวกับทุก
family อื่นในระบบ) — ข้อมูลที่เคยเห็นว่า "dormant หมด" เป็นการอ่าน/บันทึกผิดพลาดจาก
แหล่งอื่น ไม่ใช่สถานะจริงของ garak — `"promptinject": "LLM01"` ถูกต้องตามเดิม

## บั๊กที่ต้องจำไว้: probe เดียวตรงได้มากกว่า 1 category (dual-category probes)

`GARAK_PROBE_OWASP_MAP` เป็น flat dict แบบ `probe -> category เดียว` แต่ probe บางตัว
(`divergence.Repeat`, `web_injection`, `exploitation`) ตรง concept มากกว่า 1 category
จริง (verify จาก garak tag metadata) — เจอบั๊กเดียวกันนี้ **2 รอบแยกกัน** เพราะแก้แค่
ฝั่งเดียวตอนแรก:

1. **รอบสี่** (`divergence.Repeat` กับ LLM02+LLM10): แก้แค่ฝั่ง "เลือกรัน" — ทำให้
   `garak_probes_for_owasp(["LLM10"])` ส่ง `divergence.Repeat` ไปรันด้วยจริง
2. **รอบสิบเอ็ด** (ค้นพบว่าบั๊กเดิมยังไม่หมด): ฝั่ง "จัดหมวดผลลัพธ์กลับมา" ยังไม่ได้
   แก้ตาม — `garak_probe_to_owasp()` คืนแค่ primary category เดียวเสมอ (`LLM02` สำหรับ
   `divergence.Repeat`) ทำให้ `selector.py` ขั้นตอน filter สุดท้าย
   (`owasp_category in categories`) กรองทิ้งผลลัพธ์นี้เงียบๆ ทุกครั้งที่ user ขอ LLM10
   อย่างเดียว (ทั้งที่ probe ถูกรันมาเพราะ LLM10 โดยเฉพาะ!) — บั๊กเดียวกันเจอซ้ำกับ
   `web_injection`/`exploitation` ตอนเพิ่ม LLM05 เข้ามาด้วย

**แก้แบบถาวร**: เพิ่ม `GARAK_DUAL_CATEGORY_PROBES` ใน `owasp_mapping.py` เป็น single
source of truth ตัวเดียว — ทั้ง `garak_probes_for_owasp()` (เลือกรัน) และ
`garak_probe_categories()` (ฟังก์ชันใหม่ คืน**ทุก**category ที่ probe ตรง ใช้ใน
`selector._expand_dual_category_garak_rows()` ตอน filter ผลสุดท้าย) อ่านจาก dict
เดียวกันนี้ ถ้าเจอ probe dual-category ตัวใหม่ในอนาคต แก้ที่ `GARAK_DUAL_CATEGORY_PROBES`
จุดเดียวพอ ไม่ต้องแก้ 2 ที่แยกกันเหมือนที่ผ่านมา — **บทเรียน**: เจอ probe ที่ "ต้องรัน
เพื่อ category อื่นด้วย" ต้องเช็คทั้งสองทิศทาง (รันถูกไหม + ผลถูกจัดหมวดถูกไหม) พร้อม
กันเสมอ ไม่ใช่แก้ทิศทางเดียวแล้วถือว่าจบ — **ยืนยันทั้ง 3 probe (`divergence.Repeat`,
`web_injection`, `exploitation`) ด้วย `--plugin_info` ตรงจากซอร์สแล้วรอบสิบสอง ปิดเป็น
resolved ทั้งหมด ไม่ต้อง verify ซ้ำอีก**

## Promptfoo — ✅ verify แล้ว (ไม่ใช่ "ยังไม่เคยรันจริง" อีกต่อไป)

ต่างจาก garak/promptmap2 (Python, เรียกผ่าน venv python.exe) ตรงที่ **Promptfoo เป็น
Node.js CLI** ติดตั้งแยกจาก python venv ของโปรเจกต์นี้โดยสิ้นเชิง ต้องมี Node.js/npm
บนเครื่อง (หรือใน container ของ backend) ก่อน:

```bash
npm install -g promptfoo
# หรือถ้าไม่อยากติดตั้ง global: set env var PROMPTFOO_USE_NPX=1 แทน (ใช้ npx แทน —
# ช้ากว่ารอบแรกที่ต้องดาวน์โหลด แต่ไม่ต้อง npm install -g)
```

Promptfoo เป็น **config-driven** (ไม่ใช่ CLI flag ล้วนแบบ garak) — `promptfoo_runner.py`
generate ไฟล์ `promptfooconfig.yaml` เองตาม plugin ที่ต้องการ 
แล้วเรียกสองขั้น: `promptfoo redteam generate -c <config>.yaml -o <redteam>.yaml --no-cache`
ตามด้วย `promptfoo redteam eval -c <redteam>.yaml -o <output>.json -o <output>.html --no-cache`
(แยกสองขั้นเพื่อไม่ให้ path ของ HTML report ถูกส่งไปเป็น config)

**สถานะ ณ ตอนนี้ — ✅ verify ผ่านจริงแล้ว หลายรอบ:**
- รันจริงสำเร็จจนจบหลายรอบ (ไม่ใช่แค่ครั้งเดียว) — ปัญหา `ENOENT` ที่เคยเจอตอนแรก
  ไม่ใช่จากโค้ดเรา แก้แล้ว
- `numTests` ต่อ plugin ปรับผ่าน env var ได้แล้ว: `PROMPTFOO_QUICK_TESTS` (depth
  "quick", default 10) / `PROMPTFOO_DEEP_TESTS` (depth "deep", default 50)
- **grader model แยกจาก target model แล้ว** ผ่าน env var `PROMPTFOO_GRADER_MODEL`
  (default `"dolphin3"`) — ไม่ใช้ target model ตัดสินผลตัวเอง
- **exit-code handling ถูกต้องแล้ว**: promptfoo คืน exit code 100 ในบางกรณีที่ไม่ใช่
  error จริง (เช่น มี test ที่ fail ตามที่ตั้งใจ) — ของเดิมเคยถือว่า exit ≠ 0 คือ error
  เสมอ แก้แล้วให้แยกแยะ 100 ออกจาก error code อื่นจริงๆ
- **pluginId prefix handle แล้ว**: promptfoo คืน pluginId พร้อม prefix
  `"promptfoo:redteam:"` นำหน้าบางที — `promptfoo_plugin_to_owasp()` ตัด prefix นี้
  ออกก่อนเทียบกับ `PROMPTFOO_PLUGIN_OWASP_MAP` เสมอแล้ว กัน silent fallback เป็น
  Uncategorized (เจอจริงกับ `divergent-repetition`/LLM10 ที่เคยหายไปเงียบๆ)
- แก้ bug ที่ `owasp:llm:01` เคยขยายเป็น 28 sub-plugin ไม่ใช่ 1 test อย่างที่ตั้งใจ
  (default strategies ของ promptfoo คูณเข้าไปเองด้วย) — เติม `"strategies": []` ใน
  `_build_config()` แล้ว + smoke test เปลี่ยนเป็น plugin เดี่ยวแทน preset
- `system_prompt_path` เดียวกับที่ promptmap2 ใช้ ถูก reuse ให้ promptfoo's
  `prompt-extraction` plugin ด้วย (ผ่าน `_resolve_system_prompt_file` ที่ import มาจาก
  `promptmap2_runner.py` ตรงๆ ไม่เขียนซ้ำ) — ไม่ต้องเพิ่ม field ใหม่ใน UI

ใน Docker: `Dockerfile.backend` ติดตั้ง Node.js 20 + `promptfoo` ให้แล้ว (pin เวอร์ชันได้ด้วย
`--build-arg PROMPTFOO_VERSION=x.y.z` หรือ `build.args` ใน compose — ควร pin เป็นเวอร์ชันที่ทดสอบแล้ว
เพราะ `latest` ทำให้ build คนละวันได้ plugin id/output schema คนละแบบ)

## promptmap2 — ⚠️ opt-in เท่านั้น ไม่ใช่ default อีกต่อไป

`promptmap2` ยังอยู่ใน `CATEGORY_CAPABLE_TOOLS["LLM07"]` เป็นตัวเลือกที่ user สั่งผ่าน
`tool_overrides` ได้ แต่**ไม่ใช่ default**ของ LLM07 อีกต่อไป (default คือ `promptfoo`)
— เหตุผล: `promptmap2` เป็น side project คนเดียว ไม่มี OWASP หรือองค์กรไหนรับรองอย่าง
เป็นทางการ (ต่างจาก garak ที่ NVIDIA ดูแล และ promptfoo ที่มี doc ผูก OWASP ชัดเจน) และ
เคยมีประวัติบั๊กผลหายไปเงียบๆ มาแล้ว (ดู bullet เรื่อง `PROMPTMAP2_TYPE_OWASP_MAP` ใน
หัวข้อ "สถานะตอนนี้" ด้านล่าง) — ยังเก็บไว้เป็นตัวเลือกเพราะเป็น tool เดียวที่ทำ concept
"prompt stealing" ได้เจาะจงกว่า garak's `sysprompt_extraction`/promptfoo's
`prompt-extraction` แต่ไม่อยากให้เป็นค่าเริ่มต้นที่ user ไม่รู้ตัวว่ากำลังพึ่ง tool ที่
ความน่าเชื่อถือยังไม่เท่า 2 ตัวหลัก

## Timeout — ปิดไว้ตอนนี้ (ตั้งใจ ไม่ใช่บั๊ก)

`selector.py` ส่ง `timeout_sec=None` ให้ทั้ง `run_garak_scan`/`run_promptmap2_scan`/
`run_promptfoo_scan` และ `smoke_test.py` ก็ default `timeout_sec=None` เหมือนกัน —
**ปิดไว้ตั้งใจ** เพราะเจอเคสจริงว่า promptmap2 อาจกินเวลานานเกิน 600s ได้ง่ายถ้า rule
ในหมวดนั้นมีเยอะ (โดยเฉพาะ smoke test ที่ยังไม่ได้จำกัด `rule_types` เลยรันทุก rule
ทุก type ทุกครั้ง) การปิด timeout แลกกับความเสี่ยงว่าถ้า subprocess ค้างจริง (เช่น
Ollama ไม่ตอบ) job จะแขวนไม่มีวันจบเอง ต้อง kill เองถ้าเจอ

## Depth (quick / deep) — ใช้เฉพาะ "สแกนจริง" เท่านั้น

`run_scan(..., depth="quick"|"deep")` ปรับ 3 จุด:
- **จำนวน garak probe/category**: `quick` = probe ตัวแทน 1 ตัว/category
  (`GARAK_QUICK_PROBES`), `deep` = ทุก probe ที่ map ไว้ใน `GARAK_PROBE_OWASP_MAP`
  บวก probe dual-category ที่เกี่ยวข้อง (ดูหัวข้อ dual-category ด้านบน)
- **promptmap2 iterations**: `quick` = 1, `deep` = 5
- **promptfoo numTests ต่อ plugin**: `quick` = plugin ตัวแทน 1 ตัว/category
  (`PROMPTFOO_QUICK_PLUGINS`) × `PROMPTFOO_QUICK_TESTS` (default 10), `deep` = ทุก
  plugin ที่ map ไว้ × `PROMPTFOO_DEEP_TESTS` (default 50)

ค่าอื่นนอกจาก `"quick"`/`"deep"` จะเงียบๆ fallback เป็น `"deep"` ไม่ error ให้เห็น

**Smoke test (`core/smoke_test.py`) ไม่รับ/ไม่ใช้ `depth` เลย** — hardcode ค่าเล็กสุด
ตายตัวเสมอ (`probes=["test.Blank"]`, `promptmap2 iterations=1`,
`promptfoo plugins=["harmful:hate"], num_tests=1`)

⚠️ **ยังไม่ verify**: `smoke_test_garak()` ใช้ probe `"test.Blank"` ซึ่งเป็น probe ที่
`--list_probes` โชว์เป็น 💤 (dormant) — ไม่เหมือน `propile` ที่ dormant ทั้ง family
(ส่งชื่อ family เปล่าๆ แล้ว error) ตรงนี้ส่งชื่อ **เต็ม** `"test.Blank"` ตรงๆ (ไม่ใช่แค่
`"test"`) ซึ่งตามหลักการ (probe ที่ sleeping ยังเรียกตรงๆ ด้วยชื่อเต็มได้ — ยืนยันแล้ว
จาก pattern เดียวกันกับ `promptinject` subclass ที่ active เรียกตรงได้ปกติ) น่าจะรันได้
ปกติ — **แต่ยังไม่เคยยืนยันจริงว่า garak ปฏิบัติกับ dormant probe ที่ถูกเรียกชื่อเต็ม
ต่างจาก family เปล่าๆ จริงหรือเปล่า** ควรรัน smoke test จริงสักรอบแล้วเช็ค error log
ก่อนเชื่อ 100%

**บั๊กที่รู้แล้วแต่ยังไม่แก้**: `smoke_test_promptmap2()` ไม่ได้ส่ง `rule_types` เลย ทำให้
promptmap2 รันทุก rule ทุก type แทนที่จะเบาจริงๆ อย่างที่ตั้งใจ — นี่คือสาเหตุที่เคยชน
timeout 600s มาก่อน (ตอนนี้ปิด timeout ไปแล้วเลยไม่ error แต่ก็ยังช้ากว่าที่ควรอยู่ดี)

## โครงสร้างไฟล์

```
llm_scanner/
├── core/
│   ├── generators/base.py       # target adapter (Ollama, OpenAI-compatible, Matthew)
│   ├── runners/
│   │   ├── garak_runner.py      # เรียก Garak (external tool)
│   │   ├── promptmap2_runner.py # เรียก promptmap2 (external tool) — opt-in เท่านั้น
│   │   └── promptfoo_runner.py  # เรียก Promptfoo (external tool, Node.js) — ✅ verify แล้ว
│   ├── parsers/
│   │   ├── garak_parser.py      # แปลง garak report -> schema กลาง
│   │   ├── promptmap2_parser.py # แปลง promptmap2 output -> schema กลาง
│   │   └── promptfoo_parser.py  # แปลง promptfoo output -> schema กลาง — ✅ verify แล้ว
│   ├── owasp_mapping.py         # ผูก probe/rule/plugin <-> OWASP category (แหล่งความจริงเดียว)
│   │                             # รวม GARAK_DUAL_CATEGORY_PROBES (probe ที่ตรง >1 category)
│   ├── selector.py              # decision logic: category ไหนใช้ tool ไหน (entry point: run_scan())
│   │                             # CATEGORY_CAPABLE_TOOLS/CATEGORY_DEFAULT_TOOL/resolve_tool_plan()
│   ├── report.py                # รวมผลทุก tool เป็น HTML report เดียว + dedupe pass/total ต่อ probe
│   │                             # (_dedupe_probe_stats() กัน detector หลายตัวบวกซ้ำ)
│   └── smoke_test.py            # สแกนจริงขนาดจิ๋วเช็ค pipeline ก่อนสแกนเต็ม
├── promptmap/                    # git clone github.com/utkusen/promptmap (ไม่ได้อยู่ใน repo นี้)
│   └── rules/                    # distraction, harmful, hate, jailbreak, prompt_stealing, social_bias
├── results/                       # ไฟล์ผลสแกนดิบทั้งหมด แยกโฟลเดอร์ต่อรอบสแกน:
│                                  #   results/<scan_id>/report.html|.json|.csv +
│                                  #   ไฟล์ดิบของแต่ละ tool (รวม promptfoo_config_*.yaml)
├── api/main.py                   # FastAPI: POST /scan (รับ tool_overrides ด้วย),
│                                  #   GET /scan/{id}/status, GET /scan/{id}/report,
│                                  #   GET /scan/{id}/report/html (ไฟล์จริงจากดิสก์)
├── ui/app.py                     # Streamlit form + dropdown เลือก tool ต่อหมวด + unified report
├── docker-compose.yml
├── Dockerfile.backend             # Python 3.11 + Node.js 20 + promptfoo + garak + promptmap2
├── Dockerfile.frontend            # streamlit อย่างเดียว ไม่ import core/
├── .env.example                   # copy เป็น .env (grader model, จำนวน test ฯลฯ)
├── .dockerignore
├── requirements-backend.txt
└── requirements-frontend.txt
```

## สถานะตอนนี้ (สำคัญ — อ่านก่อนใช้)

- ✅ **Garak + target type "ollama"** — implement ครบ ใช้งานได้จริงทั้งบนเครื่องและใน Docker
  (ต้องส่ง `--generator_options` ให้ทั้ง `OllamaGenerator` และ `OllamaGeneratorChat` — ดูหัวข้อ "วิธีรัน")
- ⚠️ **promptmap2 + target type "ollama"** — implement ครบ แต่เป็น **opt-in เท่านั้น
  ไม่ใช่ default** (ดูหัวข้อ "promptmap2" ด้านบน) ต้อง
  `git clone github.com/utkusen/promptmap` มาวางที่ `./promptmap/` (ไม่ได้อยู่บน PyPI)
- ✅ **Promptfoo + target type "ollama"** — verify กับการรันจริงแล้วหลายรอบ (ดูหัวข้อ
  "Promptfoo" ด้านบน) ส่วนรันใน Docker เขียน Dockerfile ให้แล้วแต่ยังไม่เคย build จริง
- ✅ **Field name ใน `garak_parser.py` — verify กับ report จริงแล้ว**: eval entry ของ garak
  ใช้ `total_evaluated` (ไม่ใช่ `total` อย่างที่เดาไว้ตอนแรก) มี fallback ไป `total_processed` ด้วย
  1 probe อาจมีหลาย eval entry ถ้าโดนเช็คด้วยหลาย detector (เก็บ field `detector` แยกไว้แล้ว)
- ✅ **`report.py` มี `_dedupe_probe_stats()`** — กัน detector หลายตัวของ probe เดียวกัน
  บวก pass/total ซ้ำกันตอนสรุปผล (1 probe ที่โดนเช็คด้วย 2 detector ไม่ควรถูกนับเป็น
  2 เท่าของจำนวนจริง)
- ✅ **`GARAK_PROBE_OWASP_MAP` + `GARAK_DUAL_CATEGORY_PROBES`** — verify กับ
  `garak --list_probes`/`--plugin_info` จริงหลายรอบ (v0.17.0, ล่าสุด 2026-10-02):
  - `"xss"` ไม่มี probe family นี้จริง — แก้เป็น `"web_injection"` แล้ว ตอนนี้ map เข้า
    **LLM05** (ไม่ใช่ LLM01 อย่างที่เคยผูกไว้ตอนแรก — ดูหัวข้อ "LLM05" ด้านบน) ผ่าน
    bare family key + dual-category กับ LLM02 — **ยืนยันซ้ำด้วย `--plugin_info` ตรง
    2026-10-02 แล้ว ปิดเป็น resolved**
  - `"continuation"` ไม่มีจริง — เคยลองแก้เป็น `"propile"` แต่ verify แล้วพัง: ทุก
    subclass เป็น dormant หมด garak error ทันที `"all plugins marked inactive"` —
    เอาออกจาก mapping แล้ว ไม่หาตัวแทนใหม่ (leakreplay+divergence.Repeat พอแล้ว)
  - `"ansiescape"` เคยลองผูกเข้า LLM05 แต่ verify แล้วว่าครอบ 3 category จริง (รวม
    LLM03 ที่ไม่มีในระบบ) — เอาออกแล้ว (ดูหัวข้อ "LLM05" ด้านบน)
  - `"divergence"` แยกระดับ subclass แล้ว (`.Repeat`→LLM02, `.RepeatedToken`→LLM10)
    เพราะ 2 subclass นี้ต้องแยกคนละ category — ทั้งคู่ dual-category กับอีกฝั่งด้วย
    (ดูหัวข้อ "บั๊กที่ต้องจำไว้" ด้านบน)
  - ✅ **`promptinject` (LLM01) ปิดจบแล้ว** — active จริง 3/6 subclass (ไม่ใช่ dormant
    ทั้ง family อย่างที่เคยกังวล) ยืนยันซ้ำกับ `--list_probes` 2026-10-02 แล้ว
  - **บทเรียน**: ก่อนเพิ่ม probe family ใหม่เข้า mapping ต้องเช็ค (1) ไม่ใช่ dormant
    ทั้ง family (เครื่องหมาย 💤 ทุกตัวใน `--list_probes`) และ (2) ไม่ใช่ dual-category
    กับหมวดอื่นที่ยังไม่ได้ map ไว้ (เช็คด้วย `--plugin_info` หรืออ่าน `.tags` จาก
    source ตรงๆ ไม่ใช่เดาจากชื่อ) — บทเรียนเดียวกันนี้ยังไม่ได้ apply กับ promptfoo
    plugin ใหม่ เพราะยังไม่มีทางเช็ค "active/dormant" ของ promptfoo plugin ได้จนกว่า
    จะรันจริง (ไม่มี `--list_probes` เทียบเท่าที่ตรวจไว้แล้ว)
- ✅ **`_parse_pass_rate` ใน `promptmap2_parser.py` ใช้ตัวเลขจริงแล้ว**: ของเดิมทิ้งตัวเลข
  passed จาก string `"3/5"` ไปเฉยๆ แก้ให้ parse ทั้ง passed/total จาก pass_rate string
  ตรงๆ แล้ว — verify กับ scan จริง (LLM07) แล้วว่าตัวเลขรายแถวถูกต้อง
- ✅ **polarity ของ `"passed"` ใน promptmap2 — verify กับ output จริงแล้ว**: `passed: false`
  หมายถึง attack สำเร็จ (test failed) ตรงตามที่ logic invert ไว้เดิม
- ✅ **promptmap2 controller model default — แก้ความเข้าใจผิดแล้ว**: ถ้าไม่ระบุ
  `--controller-model` promptmap2 จะใช้ **target model ตัวเดียวกัน**เป็น controller ด้วย
  ไม่ต้องมี `OPENAI_API_KEY` ก็รันได้
- ✅ **`PROMPTMAP2_TYPE_OWASP_MAP` แก้ชื่อ type ผิดแล้ว**: ของเดิมเขียน `harmful_content`/`bias`
  ซึ่งไม่ตรงกับ rule type จริงของ promptmap2 (`harmful`/`social_bias`) — แก้แล้ว
- ✅ **promptmap2 ยิงเจาะจงตาม OWASP category ที่เลือกแล้ว**: ส่ง `--rule-type`
  เข้า promptmap2 ตรงๆ ผ่าน `promptmap2_rule_types_for_owasp()`
- ✅ **system prompt สำหรับ promptmap2 auto-resolve แล้ว** — ลำดับหา: ไฟล์ที่ระบุเอง
  → `./promptmap/system-prompts.txt` ที่มากับ repo → ดึงจาก Ollama `/api/show`
  อัตโนมัติ — `promptfoo_runner.py` reuse ฟังก์ชันเดียวกันนี้ด้วย
- ✅ **`run_garak_scan(probes=[])` ไม่ fallback ไปยิง preset แล้ว**: เช็ค `probes is None`
  แทน `probes or ...` — `run_promptfoo_scan` เขียนตาม pattern เดียวกัน
- ✅ **`run_scan()` คืนค่า `scan_id` แล้ว**: เซฟไฟล์ลง `results/<scan_id>/` และคืน
  ชื่อโฟลเดอร์กลับมาด้วย เก็บไว้ใน `JOBS[job_id]["result"]["scan_id"]`
- ✅ **Windows-safe**: garak/promptmap2 runner หา Python จาก `venv/Scripts/python.exe`
  ถ้ามี และใช้ absolute path สำหรับ report/output เสมอ
- ✅ **Unified HTML report ดึงจากไฟล์จริงแล้ว** — เพิ่ม `GET /scan/{job_id}/report/html`
  ให้ UI ดึงไฟล์ที่เซฟไว้จริงบน `results/<scan_id>/report.html` ตรงๆ แทนการ
  `build_report_html()` ใหม่ใน memory ทุกครั้ง (กันปัญหา stale-import/backend restart
  แล้วหา report เก่าไม่เจอ) — `ui/app.py` ยังมีปุ่มแบบเดิม (build ใน memory + download
  button) คู่กันไว้ด้วยเผื่ออยากดูแบบ inline เร็วๆ โดยไม่โหลดไฟล์
- ✅ **`report.py`/`ui/app.py` วน loop ผ่าน `tool_plan`/`results` แบบ generic** —
  ไม่ hardcode ชื่อ tool เลย เพิ่ม tool ใหม่ (promptfoo) โดยไม่ต้องแตะโค้ดส่วนแสดงผลเลย
- ✅ **Smoke test** — ยิงสแกนจริงขนาดจิ๋ว (garak, promptmap2, promptfoo) ก่อนสแกนเต็ม
  รูปแบบ ต่อเข้า UI แล้ว (ปุ่ม "Run Smoke Test") แต่ยังมี 2 จุดค้าง (ดูหัวข้อ "Depth"
  ด้านบน: `test.Blank` dormant ยังไม่ verify, `rule_types` ของ promptmap2 ยังไม่ถูกจำกัด)
- ✅ **โหมด `depth="deep"` verify แล้วกับข้อมูลจริง (2026-10)**: รัน deep mode ครบ
  ทุกหมวด (LLM01/02/05/06/07/09/10) จนจบสำเร็จ — ยืนยัน GARAK_DUAL_CATEGORY_PROBES/
  _expand_dual_category_garak_rows()/_dedupe_probe_stats() ทำงานถูกต้องร่วมกัน
  ตรวจสอบเลขย้อนกลับแล้วตรง 100%: divergence.Repeat โผล่ถูกทั้ง LLM02+LLM10,
  web_injection/exploitation โผล่ถูกทั้ง LLM02+LLM05, summary ของ LLM10 (34/86)
คำนวณจากแถวดิบได้ตรงเป๊ะ
- ❌ **target type "openai_compatible" / "matthew"** — ยังไม่ implement ใน `selector.py`
  จะ raise `NotImplementedError` ถ้าเรียกใช้ตอนนี้ **บั๊กที่พบเพิ่ม**: `ui/app.py` มีให้
  เลือก provider `"openai_compatible"` ในดรอปดาวน์ด้วย แต่ไม่มี input field
  (`base_url`/`api_key`/`model`) ให้เลยสักช่อง — ยังไม่ได้แก้ (นอกสโคป ollama-only
  ตอนนี้ — ถ้าจะเปิด ต้องแก้ `promptfoo_runner._build_config` ด้วย เพราะ hardcode
  provider id เป็น `"ollama:chat:<model>"`)
- ❌ **Giskard / PyRIT runner** — ยังไม่ได้เขียน มีแค่โครง comment ว่าจะต่อตรงไหน
  (นี่คือจุดที่ `LLM08` ต้องรอ)
- ⚠️ **Job storage เป็น in-memory dict** ใน `api/main.py` — ถ้า restart backend
  ประวัติ job หาย พอสำหรับเดโม ถ้าต้องการ persist จริงจังค่อยเปลี่ยนเป็น SQLite

## วิธีรัน (Ollama รันเป็น service ใน compose)

```bash
  git clone https://github.com/utkusen/promptmap
  cp .env.example .env          # ใส่ PROMPTFOO_EMAIL ด้วย (promptfoo redteam ถามอีเมลครั้งแรก)
  docker compose up --build
  docker compose exec ollama ollama pull llama-guard3:1b   # grader(แนะนำllama-guard3:1b) และเพิ่มโมเดลที่จะสแกน
```
port 8000 (backend) และ 8501 (frontend) ถูก publish ที่ทุก interface (`"8000:8000"`, `"8501:8501"`)
API ไม่มี auth และสั่งรันสแกนได้ ถ้าอยู่บนเครือข่ายที่ไม่ไว้ใจ ให้แก้ `ports` ใน `docker-compose.yml`
เป็น `"127.0.0.1:8000:8000"` / `"127.0.0.1:8501:8501"`

Node.js กับ promptfoo ติดตั้งใน image ให้แล้ว ไม่ต้องลงบนเครื่อง host

เปิดเบราว์เซอร์ไปที่ `http://localhost:8501`

**Ollama**: compose รัน Ollama เป็น service `ollama` เอง (volume `ollama-data`) ทั้ง backend และ frontend
ใช้ `OLLAMA_URL=http://ollama:11434` (ตั้งใน `.env`) เป็นค่าเริ่มต้นของช่อง "Ollama Base URL" —
ต้อง `ollama pull` โมเดลที่จะสแกนและ grader เข้า container นี้ก่อน

ถ้าอยากใช้ Ollama บนเครื่อง host แทน ให้ตั้ง `OLLAMA_URL=http://host.docker.internal:11434`,
เพิ่ม `extra_hosts: ["host.docker.internal:host-gateway"]` ให้ backend/frontend ใน compose
และให้ Ollama บน host listen ที่ `0.0.0.0` (`OLLAMA_HOST=0.0.0.0 ollama serve`)

**garak ไม่อ่าน env และต้องส่ง host เอง**: `OllamaGenerator` มี default `127.0.0.1:11434`
และ garak v0.17.0 สร้าง `OllamaGeneratorChat` (subclass) จริงตอนใช้ `--model_type ollama`
จึงต้องส่ง `--generator_options` ที่ตั้ง `host` ให้ **ทั้งสองคลาส** (`OllamaGenerator` และ
`OllamaGeneratorChat`) ถ้าตั้งแค่คลาสแรก garak จะต่อ `127.0.0.1` ใน container ตัวเองแล้ว
ขึ้น `ConnectionError: Failed to connect to Ollama` (ดูได้จาก `connect_tcp.started host='127.0.0.1'`
ใน `/root/.local/share/garak/garak.log`)

## รันแบบไม่ใช้ Docker (debug ง่ายกว่าตอนพัฒนา)

```bash
pip install -r requirements-backend.txt
npm install -g promptfoo   # ไม่ได้อยู่ใน requirements-backend.txt เพราะเป็น Node.js package

uvicorn api.main:app --port 8000
# ไม่แนะนำ --reload ตอนทดสอบสแกนจริง — core/runners เขียนไฟล์ผลสแกนลง
# results/<scan_id>/ ระหว่างสแกน ถ้า reload watcher เฝ้าดูโฟลเดอร์นี้ด้วย จะรีสตาร์ท
# ตัวเองกลางทาง ถ้าอยากเก็บ --reload ไว้:
#   uvicorn api.main:app --reload --reload-exclude "results/*" --port 8000

pip install -r requirements-frontend.txt
streamlit run ui/app.py
```

ก่อนรันเต็มรูปแบบ แนะนำรัน smoke test ก่อน:

```bash
python -m core.smoke_test
```

## Next steps

1. **ยืนยัน `test.Blank` (garak smoke test) ว่าจริงๆ รันได้แม้เป็น 💤**
2. **ลอง `docker compose up --build` จริงสักรอบ** แล้วเช็คว่า (ก) pip resolve garak กับ promptmap2 ผ่าน
   (ข) `promptfoo` รันใน container ได้ (ค) garak ต่อ Ollama ใน container ติด — แก้ `--generator_options` ให้ครอบ `OllamaGeneratorChat` แล้ว แต่ยังต้องรัน smoke test ยืนยันอีกรอบ
3. จำกัด `rule_types` ให้ `smoke_test_promptmap2()`
4. เขียน `pyrit_runner.py` ตาม pattern เดียวกับ runner อื่น แล้วเติม `LLM08` เข้าระบบ
5. เขียน custom assertion ของ Promptfoo สำหรับ LLM05
6. เติม target type `openai_compatible`/`matthew`
7. เปลี่ยน job storage จาก in-memory dict เป็น SQLite
8. อัปเดตคู่มือรันทดสอบเทียบ Garak vs Promptfoo (LLM01/02/07/10) ให้ใช้ชื่อ module
   แทน tag:owasp:llmXX ทุกหมวด และเพิ่ม exploitation/web_injection เข้าคำสั่ง LLM02
   deep mode ให้ครบ