from typing import List, Dict, Any, Optional
import httpx
from src.corpus.dataset import RetrievalResult, GoldQuery
from src.llm.openrouter_client import OpenRouterClient
from src.llm.async_openrouter_client import AsyncOpenRouterClient
from src.config import config

class RAGGenerator:
    """Generates answers using an LLM conditioned on retrieved context passages (Sync & Async)."""

    def __init__(
        self, 
        client: Optional[OpenRouterClient] = None, 
        async_client: Optional[AsyncOpenRouterClient] = None,
        model: Optional[str] = None
    ):
        self.client = client or OpenRouterClient()
        self.async_client = async_client or AsyncOpenRouterClient()
        self.model = model or config.GENERATOR_MODEL

    def format_context(self, retrieved_docs: List[RetrievalResult]) -> str:
        if not retrieved_docs:
            return "No relevant intelligence documents retrieved."

        context_blocks = []
        for i, doc in enumerate(retrieved_docs, 1):
            context_blocks.append(f"[Document {i}] (ID: {doc.doc_id}, Title: {doc.title})\n{doc.text}")
        return "\n\n".join(context_blocks)

    def _build_messages(self, query: str, retrieved_docs: List[RetrievalResult]) -> List[Dict[str, str]]:
        context_str = self.format_context(retrieved_docs)
        
        system_prompt = (
            "You are an expert Cyber Threat Intelligence (CTI) and vulnerability research analyst. "
            "Answer the technical security question accurately based strictly on the provided intelligence context documents. "
            "State findings clearly, citing relevant CVEs, weaknesses (CWE), threat groups, or techniques mentioned in the context."
        )

        user_prompt = (
            f"=== RETRIEVED INTELLIGENCE CONTEXT ===\n"
            f"{context_str}\n\n"
            f"=== SECURITY INQUIRY ===\n"
            f"{query}\n\n"
            f"=== ANALYST ASSESSMENT ===\n"
            f"Provide a concise, factual security assessment directly answering the inquiry based on the context above:"
        )

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

    def generate_response(self, query: str, retrieved_docs: List[RetrievalResult]) -> str:
        messages = self._build_messages(query, retrieved_docs)
        return self.client.chat(messages=messages, model=self.model, temperature=config.LLM_TEMPERATURE)

    async def generate_response_async(
        self, 
        http_client: httpx.AsyncClient, 
        query: str, 
        retrieved_docs: List[RetrievalResult]
    ) -> str:
        messages = self._build_messages(query, retrieved_docs)
        return await self.async_client.chat_async(
            client=http_client,
            messages=messages,
            model=self.model,
            temperature=config.LLM_TEMPERATURE
        )
