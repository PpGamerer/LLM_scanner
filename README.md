# LLM Security Scanner — โครง starter

โครงตามสถาปัตยกรรม 3 ชั้น: **Core Engine (Python)** → **API (FastAPI)** → **UI (Streamlit)** → **Docker Compose**

## แนวคิดหลัก: ระบบเลือก tool ให้เอง ไม่ใช่ user เลือก

User เลือกแค่ **target** (Ollama model) และ **OWASP category ที่อยากทดสอบ**
(เช่น LLM01, LLM07) — ไม่ต้องรู้จัก Garak/promptmap2/Giskard/PyRIT เลย

`core/selector.py` คือส่วนที่ตัดสินใจแทน user ผ่าน `CATEGORY_TOOL_MAP`:

```python
CATEGORY_TOOL_MAP = {
    "LLM01": ["garak"],       # Prompt Injection -> Garak
    "LLM06": ["garak"],       # Sensitive Info -> Garak
    "LLM07": ["promptmap2"],  # System Prompt Leakage -> promptmap2
    "LLM09": ["garak"],       # Misinformation -> Garak
}
```

ปรับ mapping นี้ได้ตามผลการทดลองจริง — นี่คือ "decision rule" ที่เป็น IP ของทีม
ไม่ใช่แค่เรียก tool ต่อกันเฉยๆ

ผลลัพธ์หลังสแกนจะมี `tool_plan` บอกด้วยว่าแต่ละ category ใช้ tool ไหน (โชว์บน UI)
เพื่อความโปร่งใส — ตอบคำถาม "ทำไมเลือก tool นี้" ได้ทันทีถ้าถูกซักในห้องสอบ

**หมายเหตุ**: category `LLM08` (Excessive Agency) โชว์เป็น checkbox บน UI ด้วย
(เพราะอยู่ใน `owasp_mapping.OWASP_CATEGORIES`) แต่**ยังไม่มี tool ผูกไว้ใน
`CATEGORY_TOOL_MAP`** — ถ้า user ติ๊กเลือก จะถูกกรองทิ้งเงียบๆ ใน `run_scan()`
ไม่ error แต่ก็ไม่มีข้อมูลของ LLM08 ในผลลัพธ์เลย (รอ PyRIT runner)

## Timeout — ปิดไว้ตอนนี้ (ตั้งใจ ไม่ใช่บั๊ก)

`selector.py` ส่ง `timeout_sec=None` ให้ทั้ง `run_garak_scan`/`run_promptmap2_scan` และ
`smoke_test.py` ก็ default `timeout_sec=None` ทั้ง `smoke_test_garak`/`smoke_test_promptmap2`
เหมือนกัน — **ปิดไว้ตั้งใจ** (ตัดสินใจ 2026-09) เพราะเจอเคสจริงว่า promptmap2 อาจกินเวลา
นานเกิน 600s ได้ง่ายถ้า rule ในหมวดนั้นมีเยอะ (โดยเฉพาะ smoke test ที่ยังไม่ได้จำกัด
`rule_types` เลยรันทุก rule ทุก type ทุกครั้ง) การปิด timeout แลกกับความเสี่ยงว่าถ้า
subprocess ค้างจริง (เช่น Ollama ไม่ตอบ) job จะแขวนไม่มีวัน fail เอง ต้อง kill เอง
ถ้าจะเปิด timeout กลับมา ควรแก้ต้นตอก่อน (จำกัด `rule_types` ให้ smoke test เบาจริง)
ไม่ใช่แค่ตั้งตัวเลขเดา

## Depth (quick / deep) — ใช้เฉพาะ "สแกนจริง" เท่านั้น

`run_scan(..., depth="quick"|"deep")` ปรับ 2 จุด:
- **จำนวน garak probe/category** ผ่าน `garak_probes_for_owasp(categories, depth=depth)`:
  `quick` = probe ตัวแทน 1 ตัว/category (`GARAK_QUICK_PROBES`), `deep` = ทุก probe ที่
  map ไว้ใน `GARAK_PROBE_OWASP_MAP`
- **promptmap2 iterations**: `quick` = 1, `deep` = 5

ค่าอื่นนอกจาก `"quick"`/`"deep"` (เผี้ยนจาก client) จะเงียบๆ fallback เป็น `"deep"`
ไม่ error ให้เห็น — ถ้าจะ debug เรื่อง depth ผิดคาด ให้เช็คจุดนี้ก่อน

**Smoke test (`core/smoke_test.py`) ไม่รับ/ไม่ใช้ `depth` เลย** — hardcode ค่าเล็กสุด
ตายตัวเสมอ (`probes=["test.Blank"]`, `iterations=1`) เร็วกว่า `depth="quick"` ของสแกนจริง
ด้วยซ้ำ เพราะ `test.Blank` แทบไม่ทำอะไรเลย ต่างจาก `dan`/`leakreplay` ที่ยังยิง attack จริง
**บั๊กที่รู้แล้วแต่ยังไม่แก้**: `smoke_test_promptmap2()` ไม่ได้ส่ง `rule_types` เลย ทำให้
promptmap2 รันทุก rule ทุก type (`distraction`/`harmful`/`hate`/`jailbreak`/
`prompt_stealing`/`social_bias`) แทนที่จะเบาจริงๆ อย่างที่ comment บอกไว้ — นี่คือสาเหตุที่
เคยชน timeout 600s มาก่อน (ตอนนี้ปิด timeout ไปแล้วเลยไม่ error แต่ก็ยังช้ากว่าที่ควรอยู่ดี)

## โครงสร้างไฟล์

```
llm_scanner/
├── core/
│   ├── generators/base.py       # target adapter (Ollama, OpenAI-compatible, Matthew)
│   ├── runners/
│   │   ├── garak_runner.py      # เรียก Garak (external tool)
│   │   └── promptmap2_runner.py # เรียก promptmap2 (external tool)
│   ├── parsers/
│   │   ├── garak_parser.py      # แปลง garak report -> schema กลาง
│   │   └── promptmap2_parser.py # แปลง promptmap2 output -> schema กลาง
│   ├── owasp_mapping.py         # ผูก probe/rule <-> OWASP category (แหล่งความจริงเดียว)
│   ├── selector.py              # decision logic: category ไหนใช้ tool ไหน (entry point: run_scan())
│   ├── report.py                # รวมผลทุก tool เป็น HTML report เดียว (แนว garak แต่รวม tool)
│   └── smoke_test.py            # สแกนจริงขนาดจิ๋วเช็ค pipeline ก่อนสแกนเต็ม
├── promptmap/                    # git clone github.com/utkusen/promptmap (ไม่ได้อยู่ใน repo นี้)
│   └── rules/                    # distraction, harmful, hate, jailbreak, prompt_stealing, social_bias
├── results/                       # ไฟล์ผลสแกนดิบทั้งหมด แยกโฟลเดอร์ต่อรอบสแกน:
│                                  #   results/<scan_id>/report.html|.json|.csv +
│                                  #   ไฟล์ดิบของแต่ละ tool — สร้างอัตโนมัติ, scan_id
│                                  #   ส่งกลับมาให้ทาง API ด้วย (ดูหัวข้อ scan_id ด้านล่าง)
├── api/main.py                   # FastAPI: POST /scan, GET /scan/{id}/status, GET /scan/{id}/report
├── ui/app.py                     # Streamlit form + unified report
├── docker-compose.yml
├── Dockerfile.backend
├── Dockerfile.frontend
├── requirements-backend.txt
└── requirements-frontend.txt
```

## สถานะตอนนี้ (สำคัญ — อ่านก่อนใช้)

- ✅ **Garak + target type "ollama"** — implement ครบ ใช้งานได้จริง
- ✅ **promptmap2 + target type "ollama"** — implement ครบ ต้อง
  `git clone github.com/utkusen/promptmap` มาวางที่ `./promptmap/` (ไม่ได้อยู่บน PyPI)
- ✅ **Field name ใน `garak_parser.py` — verify กับ report จริงแล้ว**: eval entry ของ garak
  ใช้ `total_evaluated` (ไม่ใช่ `total` อย่างที่เดาไว้ตอนแรก) มี fallback ไป `total_processed` ด้วย
  1 probe อาจมีหลาย eval entry ถ้าโดนเช็คหลาย detector (เก็บ field `detector` แยกไว้แล้ว)
- ✅ **`GARAK_PROBE_OWASP_MAP` แก้ probe family ที่ไม่มีจริง/ใช้ไม่ได้แล้ว**:
  - `"xss"` ไม่มี probe family นี้จริง — verify กับ `garak --list_probes` (v0.17.0) แล้ว
    แก้เป็น `"web_injection"` (มี `web_injection.MarkdownXSS`/`TaskXSS` จริง และทุก
    subclass active ไม่มีตัวไหน dormant — verify แล้ว)
  - `"continuation"` ก็ไม่มีจริงเช่นกัน — **เคยลองแก้เป็น `"propile"` แต่ verify กับการรันจริง
    แล้วพัง**: ทุก subclass ของ `propile` family (`PIILeakQuadruplet`/`Triplet`/`Twin`/
    `Unstructured`) เป็น dormant/inactive by default หมดทุกตัว พอส่งแค่ชื่อ family เฉยๆ
    garak error ทันที `"all plugins in 'probes.propile' are marked inactive"` — **เอา
    `propile` ออกจาก mapping แล้ว ไม่หาตัวแทนใหม่** เพราะ LLM06 มี `leakreplay`+`divergence`
    ที่ active อยู่แล้วเพียงพอ (verify แล้วว่าไม่ dormant ทั้ง family เหมือน propile)
    **บทเรียน**: ก่อนเพิ่ม probe family ใหม่เข้า mapping ต้องเช็คว่าไม่ใช่ dormant ทั้ง
    family (เครื่องหมาย 💤 ทุกตัวใน `--list_probes` = สัญญาณเตือน) ไม่ใช่แค่เช็คว่า
    family นั้น "มีอยู่จริง" เฉยๆ
- ✅ **`_parse_pass_rate` ใน `promptmap2_parser.py` ใช้ตัวเลขจริงแล้ว**: ของเดิมทิ้งตัวเลข
  passed จาก string `"3/5"` ไปเฉยๆ (เก็บแค่ total) แล้วไปเดา passed แบบ all-or-nothing จาก
  boolean `passed` ของทั้ง test — ทำให้ pass rate ที่โชว์ผู้ใช้ไม่ตรงกับตัวเลขจริงที่ promptmap2
  รายงานมา แก้ให้ parse ทั้ง passed/total จาก pass_rate string ตรงๆ แล้ว — verify กับ
  scan จริง (LLM07) แล้วว่าตัวเลขรายแถวถูกต้อง (เช่น `0/1` → 0.0%, `1/1` → 100.0%)
- ✅ **polarity ของ `"passed"` ใน promptmap2 — verify กับ output จริงแล้ว**: `passed: false`
  หมายถึง attack สำเร็จ (test failed) ตรงตามที่ logic invert ไว้เดิม
- ✅ **promptmap2 controller model default — แก้ความเข้าใจผิดแล้ว**: ถ้าไม่ระบุ
  `--controller-model` promptmap2 จะใช้ **target model ตัวเดียวกัน**เป็น controller ด้วย
  (ไม่ใช่ OpenAI อย่างที่เข้าใจผิดไว้ตอนแรก) ไม่ต้องมี `OPENAI_API_KEY` ก็รันได้ แต่ README
  ของ promptmap2 เตือนว่าโมเดลอ่อนเป็น controller อาจตัดสิน pass/fail ผิดได้ ถ้าอยากแม่นกว่า
  ให้ส่ง `controller_model`/`controller_model_type` เป็นโมเดลที่แรงกว่า
- ✅ **`PROMPTMAP2_TYPE_OWASP_MAP` แก้ชื่อ type ผิดแล้ว**: ของเดิมเขียน `harmful_content`/`bias`
  ซึ่งไม่ตรงกับ rule type จริงของ promptmap2 (`harmful`/`social_bias`) — แก้แล้ว
- ✅ **promptmap2 ยิงเจาะจงตาม OWASP category ที่เลือกแล้ว**: `selector.py` ส่ง `--rule-type`
  เข้า promptmap2 ตรงๆ ผ่าน `promptmap2_rule_types_for_owasp()`
- ✅ **system prompt สำหรับ promptmap2 auto-resolve แล้ว** (`_resolve_system_prompt_file`):
  ลำดับหา — (1) ไฟล์ที่ระบุเอง ถ้ามี (2) `./promptmap/system-prompts.txt` ที่มากับ repo
  promptmap2 เอง ถ้ามี (3) ดึง system prompt จริงจาก Ollama model ผ่าน `/api/show` มาสร้างไฟล์
  ให้อัตโนมัติ
- ✅ **`run_garak_scan(probes=[])` ไม่ fallback ไปยิง preset แล้ว**: เปลี่ยนเป็นเช็ค
  `probes is None` แทน `probes or ...` — `[]` (ตั้งใจส่งมาว่า "ไม่ต้องรันเลย") คืน `[]` จริงๆ
- ✅ **`run_scan()` คืนค่า `scan_id` แล้ว**: เซฟ `report.html`/`.json`/`.csv` + ไฟล์ดิบของ
  แต่ละ tool ลง `results/<scan_id>/` และคืนชื่อโฟลเดอร์นั้นกลับมาด้วย —
  `run_scan()` return `(results, tool_plan, scan_id)` และ `api/main.py` เก็บ `scan_id` ไว้ใน
  `JOBS[job_id]["result"]["scan_id"]` ให้ดึงผ่าน `GET /scan/{job_id}/report` ได้
  **ยังไม่ได้ทำ**: `ui/app.py` ยังไม่โชว์ `scan_id`/path นี้ให้ user เห็นบนหน้าเว็บ และถ้ารันผ่าน
  Docker ต้อง mount volume `./results:/app/results` ไว้ใน `docker-compose.yml` ด้วย ไม่งั้น
  รู้ scan_id แต่เข้าไฟล์จริงในเครื่อง host ไม่ได้อยู่ดี — ยังไม่ verify ว่า mount ไว้แล้วหรือยัง
- ✅ **Windows-safe**: ทั้งสอง runner หา Python จาก `venv/Scripts/python.exe` ถ้ามี (กัน env
  เพี้ยน) และใช้ absolute path สำหรับ report/output เสมอ กัน garak เอาไฟล์ไปซ่อนที่อื่น
- ✅ **Unified HTML report** (`core/report.py`) — รวมผลจากทุก tool เป็น HTML เดียว จัดกลุ่มตาม
  OWASP category — ต่อเข้า `ui/app.py` แล้ว (โชว์ inline + ปุ่มดาวน์โหลด `.html`) แต่ report
  ที่ UI โชว์เป็นการ build ใหม่ใน memory ผ่าน `build_report_html()` ไม่ใช่ไฟล์ที่เซฟไว้จริงบน
  `results/<scan_id>/` — ถ้า backend restart ก่อนกด "ดูรายงาน" อีกครั้ง ต้องไปหาไฟล์ที่เซฟไว้
  บนดิสก์เอง (ใช้ `scan_id` ด้านบน) — **verify แล้วกับสแกนจริง (quick, LLM01/06/07/09,
  llama3.2:1b) ว่า report ออกมาถูกต้อง ครบทุก category ไม่มีตัวไหนหายเงียบๆ**
- ✅ **Smoke test** (`core/smoke_test.py`) — ยิงสแกนจริงขนาดจิ๋ว (garak probe `test.Blank`,
  promptmap2 1 iteration) ก่อนสแกนเต็มรูปแบบ ต่อเข้า UI แล้ว (ปุ่ม "Run Smoke Test") ไม่รับ
  `depth` (ดูหัวข้อ Depth ด้านบน) — timeout ปิดไว้แล้ว (ดูหัวข้อ Timeout ด้านบน) แต่ยังมีบั๊ก
  `rule_types` ไม่ถูกจำกัดค้างอยู่ (ดูหัวข้อ Depth ด้านบนเช่นกัน)
- ⚠️ **โหมด `depth="deep"` ยัง verify ไม่ครบ**: quick mode (ยืนยันแล้วว่าผ่านจริง — ดูด้านบน)
  ไม่เคยแตะ `propile` หรือ `web_injection` เลย เพราะ `GARAK_QUICK_PROBES` ใช้แค่ probe
  ตัวแทนตัวเดียวต่อ category ส่วน deep mode ที่เคย error จาก `propile` (ตอนนี้เอาออกแล้ว)
  ยังไม่เคยรันจนจบสำเร็จให้เห็นสักครั้ง — **ควรลอง deep mode อีกรอบเพื่อยืนยันว่า
  `web_injection` (ตัวที่แก้แทน `xss`) รันได้จริงไม่ error เหมือนที่ `propile` เคยเป็น**
- ❌ **target type "openai_compatible" / "matthew"** — ยังไม่ implement ใน `selector.py`
  จะ raise `NotImplementedError` ถ้าเรียกใช้ตอนนี้ (ทำงานได้กับ `"ollama"` เท่านั้น)
  **บั๊กที่พบเพิ่ม**: `ui/app.py` มีให้เลือก provider `"openai_compatible"` ในดรอปดาวน์ด้วย
  แต่ไม่มี `elif` เตรียม input field (`base_url`/`api_key`/`model`) ให้เลยสักช่อง ถ้า user
  เลือกจะส่ง request ที่ไม่มี `model` ไปโดน backend ตอบ 422 กลับมางงๆ — ยังไม่ได้แก้
  (นอกสโคป ollama-only ตอนนี้)
- ❌ **Giskard / PyRIT / Promptfoo runner** — ยังไม่ได้เขียน มีแค่โครง comment ใน `selector.py`
  ว่าจะต่อตรงไหน (ดู `CATEGORY_TOOL_MAP` — นี่คือจุดที่ LLM08 ต้องรอ) ถ้าจะเพิ่ม Promptfoo
  ทีหลัง: ต่างจาก garak/promptmap2 ตรงที่เป็น Node.js runtime (ต้องเพิ่มเข้า
  `Dockerfile.backend`) และ config-driven (ต้อง generate YAML แทน CLI flags) — งานที่กิน
  เวลาที่สุดคือ verify ว่า promptfoo's built-in plugin ไหน map เข้า OWASP category ไหน
  ให้ถูกจากเอกสารจริง (เหมือนที่ต้อง verify garak probes เอง ไม่ใช่เดา)
- ⚠️ **Job storage เป็น in-memory dict** ใน `api/main.py` — ถ้า restart backend ประวัติ job หาย
  พอสำหรับเดโม ถ้าต้องการ persist จริงจังค่อยเปลี่ยนเป็น SQLite ทีหลัง

## วิธีรัน (ต้องมี Ollama รันอยู่ก่อนบนเครื่อง host)

```bash
# ขั้นตอนที่ต้องทำครั้งเดียวก่อน build (สำคัญ — Dockerfile.backend copy
# โฟลเดอร์นี้เข้า image ด้วย ถ้าไม่มี build จะ fail ทันทีที่ COPY promptmap/)
git clone https://github.com/utkusen/promptmap
# ให้ได้โฟลเดอร์ ./promptmap/ อยู่ที่ project root เดียวกับ docker-compose.yml

# เทอร์มินัลที่ 1 — เตรียม Ollama
ollama serve
ollama pull dolphin3

# เทอร์มินัลที่ 2 — รันทั้งระบบ
docker compose up --build
```

เปิดเบราว์เซอร์ไปที่ `http://localhost:8501`

**ถ้า backend/frontend หา Ollama ไม่เจอ**: ใน `ui/app.py` ให้เปลี่ยน Ollama Base URL จาก
`http://localhost:11434` เป็น `http://host.docker.internal:11434` เพราะทั้ง backend และ
frontend รันอยู่ใน container คนละ network กับ Ollama ที่รันบน host (ตั้งค่า `extra_hosts`
ไว้ให้ทั้งสอง service ใน `docker-compose.yml` แล้ว — ก่อนหน้านี้เคยตั้งไว้แค่ service
`backend` ทำให้ model dropdown บน UI ซึ่งยิง request หา Ollama เองจาก container `frontend`
ใช้งานไม่ได้ ตอนนี้แก้แล้ว)

ผลสแกนที่เซฟไว้ระหว่างรัน (`report.html`/`.json`/`.csv` + ไฟล์ดิบของแต่ละ tool) จะออกมาอยู่ที่
`./results/<scan_id>/` บนเครื่อง host ด้วย (ผ่าน volume mount ใน `docker-compose.yml`) ไม่หาย
ไปตอน container restart/rebuild อีกต่อไป

## รันแบบไม่ใช้ Docker (debug ง่ายกว่าตอนพัฒนา)

```bash
pip install -r requirements-backend.txt
uvicorn api.main:app --port 8000
# ⚠️ ไม่แนะนำ --reload ตอนทดสอบสแกนจริง — core/runners เขียนไฟล์ผลสแกนลง
# results/<scan_id>/ ระหว่างสแกน ถ้า reload watcher เฝ้าดูโฟลเดอร์นี้ด้วย ไฟล์ใหม่
# ที่โผล่ขึ้นมากลางสแกนจะทำให้ uvicorn รีสตาร์ทตัวเองกลางทาง (connection ที่
# Streamlit poll ค้างอยู่โดนตัด — เจอ ConnectionResetError/WinError 10054 จริงมาแล้ว)
# ถ้าอยากเก็บ --reload ไว้ ให้ exclude โฟลเดอร์ results ออก:
#   uvicorn api.main:app --reload --reload-exclude "results/*" --port 8000

# อีก terminal
pip install -r requirements-frontend.txt
streamlit run ui/app.py
```

ก่อนรันเต็มรูปแบบ แนะนำรัน smoke test ก่อน (ปุ่มในหน้า UI หรือรันตรงๆ):

```bash
python -m core.smoke_test
```

**หลังแก้ไฟล์ใน `core/` แล้วผลยังเหมือนเดิมไม่เปลี่ยน**: เช็คว่า (1) ไฟล์ถูกแทนที่จริงที่
path ที่ backend ใช้ (`findstr "<คำที่แก้>" core/<ไฟล์>.py` บน Windows) (2) ไม่มี uvicorn
process เก่าค้างอยู่ (`tasklist | findstr python` แล้ว `taskkill /F /IM python.exe` ถ้ามี
ซ้อน) (3) ลบ `core/__pycache__` ทิ้งเผื่อ bytecode ค้าง — เจอเคสจริงที่แก้ `propile` ออก
จาก `owasp_mapping.py` แล้วแต่ error เดิมยังขึ้นซ้ำ เพราะไฟล์ยังไม่ถูกแทนที่จริง

## Next steps

1. จำกัด `rule_types` ให้ `smoke_test_promptmap2()` เพื่อให้ smoke test เบาจริง (ดูบั๊กใน
   หัวข้อ Depth/Timeout ด้านบน) แทนที่จะพึ่งการปิด timeout อย่างเดียว
2. ยืนยัน `depth="deep"` ให้ผ่านจริงสักครั้ง (ดู ⚠️ ด้านบน) หลังตัด `propile` ออกแล้ว
3. เขียน `giskard_runner.py` + `pyrit_runner.py` (หรือ `promptfoo_runner.py`) ตาม pattern
   เดียวกับ `garak_runner.py`/`promptmap2_runner.py` แล้วเติม `"LLM08": ["pyrit"]` เข้า
   `CATEGORY_TOOL_MAP`
4. เติม target type `openai_compatible`/`matthew` ใน `selector.py` **และ** เติม input field
   ที่หายไปใน `ui/app.py` (ตอนนี้เลือก `openai_compatible` แล้วไม่มีช่องกรอก)
5. เพิ่ม OWASP category checkbox ให้ตรงกับ preset probe ที่เลือกเองได้ (ตอนนี้ preset
   `quick`/`deep` ของ garak ยังตายตัวใน `garak_runner.py`)
6. เปลี่ยน job storage จาก in-memory dict เป็น SQLite ถ้าจะใช้งานจริงจัง (ดู warning ด้านบน)
7. โชว์ `scan_id`/path ของ `results/<scan_id>/` บน UI (`ui/app.py`) ให้ user เห็นว่าไฟล์จริง
   อยู่ไหน + เช็คว่า `docker-compose.yml` mount `./results:/app/results` ไว้แล้วหรือยัง