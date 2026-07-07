from typing import Optional, List, Dict, Any
from langchain_community.llms import Ollama
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from app.core.config import settings


class LLMManager:
    def __init__(self):
        self.llm = Ollama(
            base_url=settings.OLLAMA_BASE_URL,
            model=settings.LLM_MODEL,
            temperature=0.1,
            num_predict=2048
        )
        self._chains: Dict[str, LLMChain] = {}

    def get_chain(self, name: str, template: str) -> LLMChain:
        if name not in self._chains:
            prompt = PromptTemplate.from_template(template)
            self._chains[name] = LLMChain(llm=self.llm, prompt=prompt)
        return self._chains[name]

    async def generate(self, template: str, **kwargs) -> str:
        chain = self.get_chain(f"dynamic_{hash(template)}", template)
        return await chain.arun(**kwargs)

    async def analyze(self, prompt: str) -> str:
        return await self.llm.agenerate([prompt])


llm_manager = LLMManager()
