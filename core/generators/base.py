"""
generators/base.py — Interface กลางสำหรับ "เป้าหมายที่จะสแกน" (target LLM)

ทุก target (Ollama, OpenAI, Matthew, หรือ LLM อื่นที่ user เอา API มาเอง)
ต้องหน้าตาเหมือนกันหมดจากมุมมองของ engine ส่วนอื่น — มีแค่ method เดียวคือ query()

เพิ่ม target ใหม่ = เขียน class ใหม่สืบทอดจาก BaseGenerator แค่นั้น
ไม่ต้องแก้โค้ดส่วนอื่นของระบบเลย
"""

from abc import ABC, abstractmethod
import requests


class BaseGenerator(ABC):
    """Interface กลางที่ทุก target ต้อง implement"""

    @abstractmethod
    def query(self, prompt: str) -> str:
        """ส่ง prompt เข้าโมเดล คืนค่าเป็น response text"""
        raise NotImplementedError

    @property
    def name(self) -> str:
        return self.__class__.__name__


class OpenAICompatibleGenerator(BaseGenerator):
    """
    ใช้ได้กับ LLM ส่วนใหญ่ในตลาดที่ทำ endpoint แบบ OpenAI-compatible
    (OpenAI จริง, Groq, Together, OpenRouter, self-hosted vLLM, Matthew ถ้าเขาทำ endpoint แบบนี้ ฯลฯ)
    นี่คือ target type "default" สำหรับโหมด BYOK ที่ user เอา LLM ตัวเองมาสแกน
    """

    def __init__(self, base_url: str, api_key: str, model: str, timeout: int = 60):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def query(self, prompt: str) -> str:
        resp = requests.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]


class OllamaGenerator(BaseGenerator):
    """Ollama local model — ไม่ต้องมี API key"""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "dolphin3", timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def query(self, prompt: str) -> str:
        resp = requests.post(
            f"{self.base_url}/api/generate",
            json={"model": self.model, "prompt": prompt, "stream": False},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["response"]


class MatthewGenerator(BaseGenerator):
    """
    ตัวอย่าง custom adapter สำหรับ target ที่ไม่ใช่ OpenAI-compatible
    ปรับ path/field ตรงนี้ให้ตรงกับ API จริงของ Matthew ตอนได้ scope/access แล้ว
    """

    def __init__(self, base_url: str, token: str, timeout: int = 60):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def query(self, prompt: str) -> str:
        resp = requests.post(
            f"{self.base_url}/chat",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"message": prompt},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["reply"]  # TODO: ปรับ field name ตาม API จริงของ Matthew


def build_generator(target_config: dict) -> BaseGenerator:
    """Factory: แปลง config dict (จากฟอร์มเว็บ) เป็น generator object"""
    target_type = target_config.get("type")

    if target_type == "ollama":
        return OllamaGenerator(
            base_url=target_config.get("base_url", "http://localhost:11434"),
            model=target_config["model"],
        )
    elif target_type == "openai_compatible":
        return OpenAICompatibleGenerator(
            base_url=target_config["base_url"],
            api_key=target_config["api_key"],
            model=target_config["model"],
        )
    elif target_type == "matthew":
        return MatthewGenerator(
            base_url=target_config["base_url"],
            token=target_config["api_key"],
        )
    else:
        raise ValueError(f"ไม่รู้จัก target type: {target_type}")
