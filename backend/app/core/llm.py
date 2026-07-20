from typing import Optional, Dict, Any
import asyncio

from app.core.config import settings
from app.core.logger import logger

try:
    from langchain_core.prompts import PromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    LANGCHAIN_CORE_AVAILABLE = True
except ImportError:
    PromptTemplate = None
    StrOutputParser = None
    LANGCHAIN_CORE_AVAILABLE = False

_OLLAMA_IMPL = None
try:
    from langchain_ollama import OllamaLLM as _OllamaClass
    _OLLAMA_IMPL = "langchain_ollama"
except ImportError:
    try:
        from langchain_community.llms import Ollama as _OllamaClass
        _OLLAMA_IMPL = "langchain_community"
    except ImportError:
        _OllamaClass = None


class LLMManager:
    """Ollama-backed LLM access that never raises at the call site.

    Every public coroutine returns `None` when the backend is missing,
    unreachable or errors out. Callers must treat `None` as "no LLM opinion
    available" and fall back to deterministic logic.
    """

    def __init__(self):
        self.llm = None
        self.backend = _OLLAMA_IMPL
        self._chains: Dict[str, Any] = {}
        self._available: Optional[bool] = None
        self._init_error: Optional[str] = None

        if _OllamaClass is None or not LANGCHAIN_CORE_AVAILABLE:
            self._init_error = "langchain ollama/core packages not installed"
            self._available = False
            logger.warning("LLMManager disabled", reason=self._init_error)
            return

        try:
            self.llm = _OllamaClass(
                base_url=settings.OLLAMA_BASE_URL,
                model=settings.LLM_MODEL,
                temperature=0.1,
                num_predict=2048,
            )
        except Exception as e:
            self._init_error = str(e)
            self._available = False
            logger.warning("LLMManager could not construct Ollama client", error=str(e))

    def get_chain(self, name: str, template: str):
        if self.llm is None:
            return None
        if name not in self._chains:
            prompt = PromptTemplate.from_template(template)
            self._chains[name] = prompt | self.llm | StrOutputParser()
        return self._chains[name]

    async def is_available(self, force: bool = False) -> bool:
        if self.llm is None:
            return False
        if self._available is not None and not force:
            return self._available

        try:
            chain = self.get_chain("_healthcheck", "{ping}")
            result = await asyncio.wait_for(chain.ainvoke({"ping": "ping"}), timeout=10.0)
            self._available = bool(result is not None)
        except Exception as e:
            self._init_error = str(e)
            self._available = False
            logger.warning("Ollama health probe failed", base_url=settings.OLLAMA_BASE_URL, error=str(e))
        return self._available

    async def generate(self, template: str, timeout: float = 120.0, **kwargs) -> Optional[str]:
        chain = self.get_chain(f"dynamic_{hash(template)}", template)
        if chain is None:
            logger.debug("LLM generate skipped", reason=self._init_error or "no backend")
            return None
        try:
            result = await asyncio.wait_for(chain.ainvoke(kwargs), timeout=timeout)
            self._available = True
            return result
        except Exception as e:
            self._available = False
            logger.warning("LLM generate failed", error=str(e))
            return None

    async def analyze(self, prompt: str, timeout: float = 120.0) -> Optional[str]:
        if self.llm is None:
            logger.debug("LLM analyze skipped", reason=self._init_error or "no backend")
            return None
        try:
            result = await asyncio.wait_for(self.llm.ainvoke(prompt), timeout=timeout)
            self._available = True
            return result if isinstance(result, str) else str(result)
        except Exception as e:
            self._available = False
            logger.warning("LLM analyze failed", error=str(e))
            return None

    def status(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "model": settings.LLM_MODEL,
            "base_url": settings.OLLAMA_BASE_URL,
            "client_constructed": self.llm is not None,
            "available": self._available,
            "error": self._init_error,
        }


llm_manager = LLMManager()
