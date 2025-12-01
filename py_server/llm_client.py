"""
Unified LLM client with preference for LLMProxy; falls back to OpenAI.
"""
import os
import sys
from typing import Any, Dict, Optional

from main import LLMProxy


class LLMClient:
    def __init__(self) -> None:
        self.mode: Optional[str] = None
        self.llmproxy: Optional[LLMProxy] = None
        self.openai_client = None
        self.default_model = "gpt-4o-mini"

        # Prefer LLMProxy when both endpoint and key are present and not placeholders
        endpoint = os.getenv("LLMPROXY_ENDPOINT")
        api_key = os.getenv("LLMPROXY_API_KEY")

        if endpoint and api_key and endpoint != "test" and api_key != "test":
            try:
                self.llmproxy = LLMProxy()
                self.mode = "llmproxy"
                print("Using LLMProxy client", file=sys.stderr)
                return
            except Exception as e:
                print(f"LLMProxy init failed: {e}", file=sys.stderr)

        # Fallback to OpenAI if available
        openai_key = os.getenv("OPENAI_API_KEY") or os.getenv("openai_api_key")
        if openai_key:
            try:
                from openai import OpenAI

                self.openai_client = OpenAI(api_key=openai_key)
                self.mode = "openai"
                print("Using OpenAI client", file=sys.stderr)
                return
            except Exception as e:
                print(f"OpenAI init failed: {e}", file=sys.stderr)

        print("No LLM client configured; filtering will be bypassed", file=sys.stderr)

    def available(self) -> bool:
        return self.mode is not None

    def generate(
        self,
        model: str,
        system: str,
        query: str,
        temperature: Optional[float] = None,
        lastk: Optional[int] = None,
        rag_usage: Optional[bool] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        if not self.available():
            return {"error": "LLM client not configured"}

        if self.mode == "llmproxy" and self.llmproxy:
            return self.llmproxy.generate(
                model=model,
                system=system,
                query=query,
                temperature=temperature,
                lastk=lastk,
                rag_usage=rag_usage,
            )

        if self.mode == "openai" and self.openai_client:
            chosen_model = model or self.default_model
            try:
                resp = self.openai_client.chat.completions.create(
                    model=chosen_model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": query},
                    ],
                    temperature=temperature if temperature is not None else 0.0,
                )
                text = ""
                if resp and resp.choices:
                    msg = resp.choices[0].message
                    if msg and hasattr(msg, "content"):
                        text = msg.content or ""
                return {"result": text}
            except Exception as e:
                return {"error": f"OpenAI error: {e}"}

        return {"error": "LLM client not configured"}
