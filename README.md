# LLM Vulnerability Scanning Platform

โครงตามสถาปัตยกรรม 3 ชั้น: **Core Engine (Python)** → **API (FastAPI)** → **UI (Streamlit)** → **Docker Compose**

## แนวคิดหลัก: ระบบเลือก tool ให้เอง ไม่ใช่ user เลือก (แต่ override ได้)

User เลือกแค่ **target** (Ollama model) และ **OWASP category ที่อยากทดสอบ**
(เช่น LLM01, LLM07) — ไม่ต้องรู้จักเครื่องมืออย่าง Garak หรือ Promptfoo เลย
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
    "LLM07": ["garak", "promptfoo"],
    "LLM09": ["garak", "promptfoo"],
    "LLM10": ["garak", "promptfoo"],
}

# ตัวที่เลือกให้อัตโนมัติถ้า user ไม่ได้สั่งผ่าน tool_overrides
CATEGORY_DEFAULT_TOOL = {
    "LLM01": "garak", "LLM02": "garak", "LLM05": "garak",
    "LLM06": "promptfoo", "LLM07": "promptfoo", "LLM09": "garak", "LLM10": "promptfoo",
}
```

> UI โชว์เฉพาะหมวดใน `PROTOTYPE_CATEGORIES` (ดูหัวข้อ "สถานะตอนนี้") ไม่ใช่ครบ 7 หมวดข้างบน

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
**ผิด**: ทุก subclass ของ `web_injection` มี tag `owasp:llm02;owasp:llm06` (ฉบับ
2023) ไม่มีตัวไหนติด `owasp:llm01` เลย แปลเป็นฉบับ 2025 คือ **LLM05 (Improper Output
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
family อื่นในระบบ) — `"promptinject": "LLM01"` ถูกต้องตามเดิม

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

## Promptfoo — ✅ verify แล้ว

ต่างจาก garak (Python, เรียกผ่าน venv python.exe) ตรงที่ **Promptfoo เป็น Node.js
CLI** ติดตั้งแยกจาก python venv ของโปรเจกต์นี้โดยสิ้นเชิง ต้องมี Node.js/npm
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
- รันจริงสำเร็จจนจบหลายรอบ — ปัญหา `ENOENT` ที่เคยเจอตอนแรกไม่ใช่จากโค้ดเรา แก้แล้ว
- `numTests` ต่อ plugin ปรับผ่าน env var ได้: `PROMPTFOO_QUICK_TESTS` (depth
  "quick", default 10) / `PROMPTFOO_DEEP_TESTS` (depth "deep", default 50)
- **grader model แยกจาก target model** ผ่าน env var `PROMPTFOO_GRADER_MODEL`
  (default คือ `qwen2.5:3b` ต้อง `ollama pull` ก่อน) — ถ้าตั้งเป็นค่าว่างเอง
  จะใช้ target model ตัดสินตัวเอง (ดูหัวข้อ "ตัวแปรสภาพแวดล้อม")
- **strategies ปรับผ่าน env var `PROMPTFOO_STRATEGIES`** (คอมม่าคั่น) — **ค่าเริ่มต้นคือ
  ว่าง = ไม่ใช้ strategy เลย** (`"strategies": []`) เพื่อไม่ให้ default strategies ของ
  promptfoo คูณจำนวน test จนบวม (เคยเจอ 232 tests แทนที่จะเป็น 1) ถ้าตั้งค่า เช่น
  `PROMPTFOO_STRATEGIES=base64,rot13` จำนวน test จะคูณตามจำนวน strategy ที่เปิด
  (ผลคูณกับ plugin × `numTests`) ใช้เวลานานขึ้นมาก ดูชื่อ strategy ที่ใช้ได้ใน doc ของ
  promptfoo — ชื่อผิดจะ error ตอนขั้น generate
- **exit-code handling ถูกต้องแล้ว**: promptfoo คืน exit code 100 ในบางกรณีที่ไม่ใช่
  error จริง (เช่น มี test ที่ fail ตามที่ตั้งใจ) — ขั้น eval อนุญาต `(0, 100)`
- **pluginId prefix handle แล้ว**: promptfoo คืน pluginId พร้อม prefix
  `"promptfoo:redteam:"` นำหน้าบางที — `promptfoo_plugin_to_owasp()` ตัด prefix นี้
  ออกก่อนเทียบกับ `PROMPTFOO_PLUGIN_OWASP_MAP` เสมอ กัน silent fallback เป็น
  Uncategorized (เจอจริงกับ `divergent-repetition`/LLM10 ที่เคยหายไปเงียบๆ)
- แก้ bug ที่ `owasp:llm:01` เคยขยายเป็น 28 sub-plugin ไม่ใช่ 1 test อย่างที่ตั้งใจ —
  smoke test เปลี่ยนเป็น plugin เดี่ยวแทน preset
- `system_prompt_path` ใช้กับ `prompt-extraction` plugin โดย import
  `_resolve_system_prompt_file` จาก `promptmap2_runner.py` (⚠️ **ห้ามลบไฟล์นั้น** —
  ดูหัวข้อ promptmap2) ลำดับหา: ไฟล์ที่ระบุเอง → `./promptmap/system-prompts.txt` →
  ดึงจาก Ollama `/api/show` อัตโนมัติ (ถ้าไม่มี system prompt เลย ใช้
  `"You are a helpful assistant."`)

ใน Docker: `Dockerfile.backend` ติดตั้ง Node.js 22 + `promptfoo` ให้แล้ว (pin เวอร์ชันได้ด้วย
`--build-arg PROMPTFOO_VERSION=x.y.z` หรือ `build.args` ใน compose — ควร pin เป็นเวอร์ชันที่ทดสอบแล้ว
เพราะ `latest` ทำให้ build คนละวันได้ plugin id/output schema คนละแบบ)

## promptmap2 — ⏸ ปิดไว้ชั่วคราว (ไม่ใช่การลบ)

ตัดออกจาก `CATEGORY_CAPABLE_TOOLS["LLM07"]` แล้ว จึงไม่โผล่ใน UI และ
`resolve_tool_plan()` จะเมิน `tool_overrides={"LLM07": "promptmap2"}` แล้ว fallback
ไป default (promptfoo) — เหตุผลเดิม: เป็น side project คนเดียว ไม่มีองค์กรรับรอง และเคย
มีบั๊กผลหายเงียบ LLM07 ยังครอบด้วย garak `sysprompt_extraction` และ promptfoo
`prompt-extraction` สิ่งที่เสียคือ concept "prompt stealing" แบบเจาะจงของ promptmap2

**ห้ามลบ `promptmap2_runner.py`** — `promptfoo_runner.py` import
`_resolve_system_prompt_file` จากไฟล์นี้ ถ้าจะถอนถาวร ให้ย้ายฟังก์ชันนี้
(+ `_fetch_ollama_system_prompt`, `DEFAULT_SYSTEM_PROMPT_PATH`) ไป `core/runners/common.py` ก่อน

**เปิดกลับ**: เติม `"promptmap2"` ใน `CATEGORY_CAPABLE_TOOLS["LLM07"]`, `git clone
https://github.com/utkusen/promptmap` ไว้ที่ `./promptmap/`, เพิ่ม import และบล็อกรัน
promptmap2 กลับใน `selector.py` (พร้อม `_progress`/`done_cats`), และถ้าจะให้ smoke test
รองรับ ต้องเขียน `smoke_test_promptmap2()` ใหม่โดยส่ง `rule_types` (ของเดิมไม่ส่ง จึงรัน
ทุก rule และเคยชน timeout 600s)

### ประวัติ promptmap2 (ไว้อ้างอิงตอนเปิดกลับ)
- `_parse_pass_rate` parse passed/total จาก string `"3/5"` ตรงๆ (verify กับ scan จริง LLM07)
- `passed: false` = attack สำเร็จ (verify แล้ว) — polarity ตรงข้ามกับ promptfoo
  (`success=True` = ป้องกันได้)
- ไม่ระบุ `--controller-model` → ใช้ target model เป็น controller เอง ไม่ต้องมี `OPENAI_API_KEY`
- `PROMPTMAP2_TYPE_OWASP_MAP` ใช้ชื่อ type จริง (`harmful`/`social_bias` ไม่ใช่
  `harmful_content`/`bias`)
- ส่ง `--rule-type` ตาม OWASP category ผ่าน `promptmap2_rule_types_for_owasp()`
- `promptmap2_runner.py` เป็นตัว reuse resolver ของ system prompt ให้ promptfoo (ดูด้านบน)

## Timeout — ปิดไว้ตอนนี้ (ตั้งใจ ไม่ใช่บั๊ก)

`selector.py` ส่ง `timeout_sec=None` ให้ `run_garak_scan`/`run_promptfoo_scan`
และ `smoke_test.py` ก็ default `None` เหมือนกัน — ปิดไว้ตั้งใจ เพราะเคยชน timeout 600s
กับ promptmap2 (ปิดอยู่ตอนนี้) และ garak/promptfoo แบบ deep ก็ใช้เวลานานเป็นชั่วโมงได้
การปิด timeout แลกกับความเสี่ยงว่าถ้า subprocess ค้างจริง (เช่น Ollama ไม่ตอบ)
job จะแขวนไม่มีวันจบเอง ต้อง kill เอง

## Depth (quick / deep) — ใช้เฉพาะ "สแกนจริง" เท่านั้น

`run_scan(..., depth="quick"|"deep")` ปรับ 2 จุด:
- **จำนวน garak probe/category**: `quick` = probe ตัวแทน 1 ตัว/category
  (`GARAK_QUICK_PROBES`), `deep` = ทุก probe ที่ map ไว้ใน `GARAK_PROBE_OWASP_MAP`
  บวก probe dual-category ที่เกี่ยวข้อง (ดูหัวข้อ dual-category ด้านบน)
- **promptfoo numTests ต่อ plugin**: `quick` = plugin ตัวแทน 1 ตัว/category
  (`PROMPTFOO_QUICK_PLUGINS`) × `PROMPTFOO_QUICK_TESTS` (default 10), `deep` = ทุก
  plugin ที่ map ไว้ × `PROMPTFOO_DEEP_TESTS` (default 50)

ค่าอื่นนอกจาก `"quick"`/`"deep"` จะเงียบๆ fallback เป็น `"deep"` ไม่ error ให้เห็น

**Smoke test (`core/smoke_test.py`) ไม่รับ/ไม่ใช้ `depth` เลย** — hardcode ค่าเล็กสุด
ตายตัวเสมอ (`probes=["test.Blank"]`, `promptfoo plugins=["harmful:hate"], num_tests=1`)
และรองรับ tool แค่ `garak`/`promptfoo` — ถ้าส่ง `tools` ที่ไม่รู้จัก (เช่น `promptmap2`)
จะคืนผล fail พร้อมข้อความ ไม่ใช่ "ผ่านเปล่าๆ"

✅ verify แล้ว (Docker): `smoke_test_garak()` ใช้ `"test.Blank"` (ชื่อเต็ม) ซึ่งแม้
`--list_probes` โชว์เป็น 💤 แต่เรียกตรงด้วยชื่อเต็มได้ปกติ ต่างจากการส่งชื่อ family
เปล่าๆ ของ family ที่ dormant ทั้งตระกูล (เช่น `propile`) ที่ error

## Progress bar และเวลา

`run_scan()` นับความคืบหน้าเป็น **รายหมวด** (`done_cats / total_cats`) แล้วเรียก
`on_progress(done, total, label)` — `api/main.py` เก็บลง `JOBS[job_id]["progress"]` และ
`GET /scan/{id}/status` คืน `progress` กับ `elapsed_sec` ให้ UI โชว์ % และเวลาที่ผ่านไป

ตัวอย่าง: garak ดูแล LLM01+LLM02, promptfoo ดูแล LLM07+LLM10 → 0% → (garak จบ) 50% →
(promptfoo จบ) 100%

**ข้อจำกัด**: บาร์ขยับเมื่อ **tool จบทั้งก้อนเท่านั้น** เพราะ garak/promptfoo รันทุกหมวดใน
subprocess เดียว (`subprocess.run(capture_output=True)` มองไม่เห็นข้างใน) ระหว่างรอ
บาร์จะค้าง แต่ตัวเลข "รันมาแล้ว" ยังเดิน ถ้าอยากขยับทีละหมวดต้องรันแยกต่อหมวด (ระวัง
probe dual-category รันซ้ำ และชื่อไฟล์ผลลัพธ์ชนกัน) หรือเปลี่ยนเป็น `Popen` อ่าน stdout

## Unified report (`core/report.py`)

- รูปแบบเอกสารทางการ มีสารบัญ เลขหัวข้อ กราฟเปรียบเทียบ tool ต่อ category (เฉพาะ
  หมวดที่มีหลาย tool) และข้อแนะนำตาม OWASP (`OWASP_MITIGATIONS` เป็นแนวทางทั่วไป
  ไม่ใช่การวิเคราะห์เจาะจงโมเดล)
- หมวดที่มีหลาย tool จะมีปุ่มกรองตาม tool (vanilla JS ไม่ reload)
- แถวที่มีตัวอย่างที่พัง (garak จาก `hitlog.jsonl`, promptfoo จาก test case ที่ fail)
  มีปุ่มพับ "ดูตัวอย่างที่พัง" — จำกัด 3 ตัวอย่างต่อ probe/plugin
- ท้ายรายงานมีลิงก์ไปไฟล์ต้นฉบับของแต่ละ tool (`garak_scan_<model>.report.html`,
  `promptfoo_scan_<model>.html` ฯลฯ) เพราะรายงานรวม cap ตัวอย่างไว้ ลิงก์เป็น relative
  path ที่ UI แปลงไปชี้ `/scan/{job_id}/files/...` ผ่าน `link_files_to_backend()`
- ⚠️ ชื่อไฟล์ใน `_NATIVE_REFERENCE_FILES` ต้องตรงกับที่ runner ตั้งจริง ถ้า runner
  เปลี่ยน naming ต้องแก้คู่กัน ไม่งั้นลิงก์ชี้ผิดไฟล์
- Overall score อาจนับ probe dual-category ซ้ำ (LLM02+LLM05, LLM02+LLM10) — มีคำเตือนในรายงาน
- `_dedupe_probe_stats()` กัน detector หลายตัวของ probe เดียวกันบวก pass/total ซ้ำ

## ตัวแปรสภาพแวดล้อม

| ตัวแปร | ใช้ที่ | ค่าเริ่มต้น / หมายเหตุ |
|---|---|---|
| `OLLAMA_URL` | backend, frontend | `http://ollama:11434` ใน compose (ค่าเริ่มต้นของช่อง Ollama Base URL) |
| `PROMPTFOO_GRADER_MODEL` | backend | `qwen2.5:3b` (ต้อง `ollama pull` ก่อน) เปลี่ยนได้ใน `.env` |
| `PROMPTFOO_QUICK_TESTS` | backend | 10 ในโค้ด (`.env` ตั้ง 3 ให้เร็ว) |
| `PROMPTFOO_DEEP_TESTS` | backend | 50 ในโค้ด (`.env.example` ตั้ง 15) |
| `PROMPTFOO_STRATEGIES` | backend | ว่าง = ไม่ใช้ strategy; คอมม่าคั่น เช่น `base64,rot13` (คูณจำนวน test) |
| `PROMPTFOO_EMAIL` | backend | promptfoo redteam ถามอีเมลครั้งแรก — ต้องตั้ง ไม่งั้นอาจค้างรอ input |
| `PROMPTFOO_USE_NPX` / `PROMPTFOO_PATH` | backend | ทางเลือกเรียก promptfoo (ไม่ต้องตั้งถ้าติดตั้ง global แล้ว) |
| `BACKEND_URL` | frontend | `http://backend:8000` ใน compose |
| `PUBLIC_BACKEND_URL` | frontend | `http://localhost:8000` — URL ที่ **เบราว์เซอร์** เข้าถึง backend ได้ (ใช้กับลิงก์ไฟล์ในรายงาน) ถ้าเปิดจากเครื่องอื่นต้องตั้งเป็น host จริง |

⚠️ **ข้อควรระวัง `PROMPTFOO_GRADER_MODEL` ว่าง**: compose ตั้ง default เป็น
`${PROMPTFOO_GRADER_MODEL:-qwen2.5:3b}` ดังนั้นถ้าไม่ได้ตั้งอะไรจะใช้ qwen2.5:3b
ใครอยากเปลี่ยนก็ตั้งใน `.env` ทับ (เช่น `dolphin3`) แล้ว `docker compose up -d`
แต่ถ้าตั้ง `PROMPTFOO_GRADER_MODEL=` ให้ว่างเอง จะกลายเป็นสตริงว่าง → `or None` →
ใช้ target model ตัดสินตัวเอง (ไม่แนะนำ) และต้อง `ollama pull` โมเดล grader เสมอ

## โครงสร้างไฟล์

```
llm_scanner/
├── core/
│   ├── generators/base.py       # target adapter (Ollama, OpenAI-compatible, Matthew)
│   ├── runners/
│   │   ├── garak_runner.py      # เรียก Garak (external tool)
│   │   ├── promptmap2_runner.py # ⏸ ปิดไว้ แต่ห้ามลบ (promptfoo_runner import _resolve_system_prompt_file จากไฟล์นี้)
│   │   └── promptfoo_runner.py  # เรียก Promptfoo (external tool, Node.js) — ✅ verify แล้ว
│   ├── parsers/
│   │   ├── garak_parser.py      # แปลง garak report (+ hitlog) -> schema กลาง
│   │   ├── promptmap2_parser.py # ⏸ ปิดไว้
│   │   └── promptfoo_parser.py  # แปลง promptfoo output -> schema กลาง — ✅ verify แล้ว
│   ├── owasp_mapping.py         # ผูก probe/rule/plugin <-> OWASP category (แหล่งความจริงเดียว)
│   │                             # รวม GARAK_DUAL_CATEGORY_PROBES (probe ที่ตรง >1 category)
│   ├── selector.py              # decision logic: category ไหนใช้ tool ไหน (entry point: run_scan())
│   │                             # CATEGORY_CAPABLE_TOOLS/CATEGORY_DEFAULT_TOOL/resolve_tool_plan()
│   ├── report.py                # รวมผลทุก tool เป็น HTML/JSON/CSV เดียว + dedupe pass/total ต่อ probe
│   └── smoke_test.py            # สแกนจริงขนาดจิ๋วเช็ค pipeline ก่อนสแกนเต็ม
├── results/                       # ไฟล์ผลสแกนดิบทั้งหมด แยกโฟลเดอร์ต่อรอบสแกน:
│                                  #   results/<scan_id>/report.html|.json|.csv +
│                                  #   ไฟล์ดิบของแต่ละ tool (รวม promptfoo_config_*.yaml)
│                                  #   (ใน Docker mount เป็น ./results:/app/results)
├── api/main.py                   # FastAPI: POST /scan (รับ tool_overrides ด้วย),
│                                  #   GET /scan/{id}/status (progress + elapsed_sec),
│                                  #   GET /scan/{id}/report, GET /scan/{id}/report/html,
│                                  #   GET /scan/{id}/report/csv, GET /scan/{id}/files/{filename}
├── ui/app.py                     # Streamlit form + dropdown เลือก tool ต่อหมวด + progress % + unified report
├── docker-compose.yml            # ollama + backend + frontend (volume: ollama-data, promptfoo-data)
├── Dockerfile.backend             # Python 3.11 + Node.js 22 + promptfoo + garak (ต้องมี curl สำหรับ healthcheck)
├── Dockerfile.frontend            # streamlit อย่างเดียว ไม่ import core/
├── .env.example                   # copy เป็น .env (grader model, จำนวน test, strategies ฯลฯ)
├── .dockerignore
├── requirements-backend.txt
└── requirements-frontend.txt
```

## สถานะตอนนี้ (สำคัญ — อ่านก่อนใช้)

- ✅ **Garak + target type "ollama"** — implement ครบ ใช้งานได้จริงทั้งบนเครื่องและใน Docker
  (ต้องส่ง `--generator_options` ให้ทั้ง `OllamaGenerator` และ `OllamaGeneratorChat` — ดูหัวข้อ "วิธีรัน")
- ✅ **Promptfoo + target type "ollama"** — verify กับการรันจริงแล้วหลายรอบ (ดูหัวข้อ
  "Promptfoo") build และรัน smoke test ผ่านแล้วใน Docker
- ⏸ **promptmap2** — ปิดไว้ชั่วคราว (ดูหัวข้อ promptmap2)
- ✅ **Field name ใน `garak_parser.py` — verify กับ report จริงแล้ว**: eval entry ของ garak
  ใช้ `total_evaluated` (ไม่ใช่ `total`) มี fallback ไป `total_processed` ด้วย 1 probe
  อาจมีหลาย eval entry ถ้าโดนเช็คด้วยหลาย detector (เก็บ field `detector` แยกไว้แล้ว)
- ✅ **garak ดึงตัวอย่างที่พังจาก `hitlog.jsonl`** (ไม่เกิน 3 ต่อ probe/detector) ให้
  ความละเอียดเท่า promptfoo — ไม่มีไฟล์ hitlog = ไม่มีตัวอย่าง (ไม่ error)
- ✅ **`report.py` มี `_dedupe_probe_stats()`** — กัน detector หลายตัวของ probe เดียวกัน
  บวกซ้ำ
- ✅ **`GARAK_PROBE_OWASP_MAP` + `GARAK_DUAL_CATEGORY_PROBES`** — verify กับ
  `garak --list_probes`/`--plugin_info` จริงหลายรอบ (v0.17.0, ล่าสุด 2026-10-02):
  - `"xss"` ไม่มี probe family นี้จริง — แก้เป็น `"web_injection"` แล้ว map เข้า **LLM05**
    ผ่าน bare family key + dual-category กับ LLM02
  - `"continuation"` ไม่มีจริง — เคยลองแก้เป็น `"propile"` แต่ทุก subclass dormant
    (`"all plugins marked inactive"`) — เอาออก ไม่หาตัวแทน (leakreplay+divergence.Repeat พอแล้ว)
  - `"ansiescape"` ครอบ 3 category (รวม LLM03 ที่ไม่มีในระบบ) — เอาออก
  - `"divergence"` แยกระดับ subclass (`.Repeat`→LLM02, `.RepeatedToken`→LLM10) และทั้งคู่
    dual-category กับอีกฝั่ง
  - **บทเรียน**: ก่อนเพิ่ม probe family ใหม่ต้องเช็ค (1) ไม่ใช่ dormant ทั้ง family
    (💤 ใน `--list_probes`) และ (2) ไม่ใช่ dual-category กับหมวดอื่น (ใช้
    `--plugin_info` หรืออ่าน `.tags` จาก source ไม่ใช่เดาจากชื่อ) — ยังไม่มีวิธีเช็ค
    active/dormant ของ promptfoo plugin จนกว่าจะรันจริง
- ✅ **`run_garak_scan(probes=[])` ไม่ fallback ไปยิง preset แล้ว**: เช็ค `probes is None`
  แทน `probes or ...` — `run_promptfoo_scan` เขียนตาม pattern เดียวกัน
- ✅ **`run_scan()` คืนค่า `scan_id` แล้ว**: เซฟไฟล์ลง `results/<scan_id>/` เก็บไว้ใน
  `JOBS[job_id]["result"]["scan_id"]`
- ✅ **Windows-safe**: garak runner หา Python จาก `venv/Scripts/python.exe` ถ้ามี และใช้
  absolute path สำหรับ report/output เสมอ
- ✅ **Unified HTML report ดึงจากไฟล์จริง** — `GET /scan/{job_id}/report/html` คืน
  `results/<scan_id>/report.html` ที่เซฟไว้ (กัน stale-import/backend restart)
- ✅ **`report.py`/`ui/app.py` วน loop ผ่าน `tool_plan`/`results` แบบ generic** — เพิ่ม tool
  ใหม่โดยไม่ต้องแตะโค้ดส่วนแสดงผล
- ✅ **Smoke test** — garak + promptfoo ต่อเข้า UI แล้ว (ปุ่ม "Run Smoke Test") verify ใน Docker แล้ว
- ✅ **Progress bar รายหมวด + `elapsed_sec`** — ดูหัวข้อ "Progress bar และเวลา"
- ✅ **โหมด `depth="deep"` verify แล้วกับข้อมูลจริง (2026-10)**: รัน deep mode ครบ
  ทุกหมวด (LLM01/02/05/06/07/09/10) จนจบ — ยืนยัน `GARAK_DUAL_CATEGORY_PROBES`/
  `_expand_dual_category_garak_rows()`/`_dedupe_probe_stats()` ทำงานถูกต้องร่วมกัน
  ตรวจเลขย้อนกลับแล้วตรง 100% (เช่น summary ของ LLM10 = 34/86 คำนวณจากแถวดิบตรงเป๊ะ)
- ⚠️ **`PROTOTYPE_CATEGORIES = [LLM01, LLM02, LLM07, LLM10]`** ใน `selector.py`: LLM05/06/09
  ซ่อนจาก UI และค่า default (เพราะยังไม่ผ่านการทดสอบเทียบแบบเป็นระบบ) แต่ยังเรียกผ่าน
  `POST /scan` ได้ตรงๆ เปิดกลับโดยแก้ list นี้บรรทัดเดียว
- ❌ **target type "openai_compatible" / "matthew"** — ยังไม่ implement ใน `selector.py`
  จะ raise `NotImplementedError` **บั๊กที่พบเพิ่ม**: `ui/app.py` มีให้เลือก provider
  `"openai_compatible"` แต่ไม่มี input field (`base_url`/`api_key`/`model`) ให้เลย —
  ถ้าจะเปิด ต้องแก้ `promptfoo_runner._build_config` ด้วย เพราะ hardcode provider id
  เป็น `"ollama:chat:<model>"`
- ❌ **PyRIT runner** — ยังไม่ได้เขียน (นี่คือจุดที่ `LLM08` ต้องรอ)
- ⚠️ **Job storage เป็น in-memory dict** ใน `api/main.py` — restart backend แล้วประวัติ job
  หาย (ผลที่เซฟไว้ใน `results/` ยังอยู่) พอสำหรับเดโม
- ⚠️ **ไม่มี auth** — port 8000/8501 publish ทุก interface และ API สั่งสแกนได้

## วิธีรัน (Ollama รันเป็น service ใน compose)

```bash
cp .env.example .env          # ตั้ง PROMPTFOO_EMAIL และ PROMPTFOO_GRADER_MODEL ให้ชัด
docker compose up --build
docker compose exec ollama ollama pull qwen2.5:3b   # grader (แนะนำ) แล้ว pull โมเดลที่จะสแกนเพิ่ม
```

port 8000 (backend) และ 8501 (frontend) ถูก publish ที่ทุก interface (`"8000:8000"`, `"8501:8501"`)
API ไม่มี auth และสั่งรันสแกนได้ ถ้าอยู่บนเครือข่ายที่ไม่ไว้ใจ ให้แก้ `ports` ใน `docker-compose.yml`
เป็น `"127.0.0.1:8000:8000"` / `"127.0.0.1:8501:8501"`

Node.js กับ promptfoo ติดตั้งใน image ให้แล้ว ไม่ต้องลงบนเครื่อง host

เปิดเบราว์เซอร์ไปที่ `http://localhost:8501`

**ลำดับเริ่มใน compose**: `ollama` ต้อง healthy (`ollama list`) ก่อน → `backend` ขึ้น
(healthcheck `curl /health` — ต้องมี `curl` ใน image) → `frontend` ขึ้นตามหลัง
**volume**: `ollama-data` เก็บโมเดลที่ pull ไว้, `promptfoo-data` (`/root/.promptfoo`) เก็บ
state ของ promptfoo (เช่นอีเมลที่ให้ไว้) ไม่ต้องกรอกใหม่ทุกครั้งที่ rebuild,
`./results` mount เป็น `/app/results` ให้ไฟล์ผลสแกนอยู่บนเครื่อง host

**Ollama**: compose รัน Ollama เป็น service `ollama` เอง ทั้ง backend และ frontend
ใช้ `OLLAMA_URL=http://ollama:11434` เป็นค่าเริ่มต้นของช่อง "Ollama Base URL" —
ต้อง `ollama pull` โมเดลที่จะสแกนและ grader เข้า container นี้ก่อน

ถ้าอยากใช้ Ollama บนเครื่อง host แทน ให้ตั้ง `OLLAMA_URL=http://host.docker.internal:11434`,
เพิ่ม `extra_hosts: ["host.docker.internal:host-gateway"]` ให้ backend/frontend ใน compose
และให้ Ollama บน host listen ที่ `0.0.0.0` (`OLLAMA_HOST=0.0.0.0 ollama serve`)

**garak ไม่อ่าน env และต้องส่ง host เอง**: `OllamaGenerator` มี default `127.0.0.1:11434`
และ garak v0.17.0 สร้าง `OllamaGeneratorChat` (subclass) จริงตอนใช้ `--model_type ollama`
จึงต้องส่ง `--generator_options` ที่ตั้ง `host` ให้ **ทั้งสองคลาส** ถ้าตั้งแค่คลาสแรก
garak จะต่อ `127.0.0.1` ใน container ตัวเองแล้วขึ้น `ConnectionError: Failed to connect to
Ollama` (ดูได้จาก `connect_tcp.started host='127.0.0.1'` ใน
`/root/.local/share/garak/garak.log`)

หลังแก้โค้ด ต้อง `docker compose up --build` ใหม่ (โค้ดถูก bake ใน image ไม่ได้ mount เป็น volume)

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

ก่อนรันเต็มรูปแบบ แนะนำรัน smoke test ก่อน (ใน container ต้องใช้ `base_url` เป็น
`http://ollama:11434` — `core/smoke_test.py` อ่านจาก `OLLAMA_URL` อยู่แล้ว แต่ `__main__`
ยัง hardcode ชื่อโมเดล `llama3.2:1b` ให้แก้ให้ตรงกับโมเดลที่ pull ไว้):

```bash
python -m core.smoke_test
```

## Next steps
1. pull grader ที่ตอบ JSON ตาม rubric ได้ (แนะนำ `qwen2.5:3b`) 
2. เขียน `pyrit_runner.py` ตาม pattern เดียวกับ runner อื่น แล้วเติม `LLM08` เข้าระบบ
3. เขียน custom assertion ของ Promptfoo สำหรับ LLM05
4. เติม target type `openai_compatible`/`matthew`
5. เปลี่ยน job storage จาก in-memory dict เป็น SQLite
6. ล้าง docstring/comment ที่ยังอ้าง promptmap2 ใน `api/main.py` (docstring หัวไฟล์,
   `TargetConfig`) และ docstring หัวไฟล์ `selector.py` (ส่วน "รอบเจ็ด")