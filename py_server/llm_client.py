"""
LLM client using OpenAI API.
"""
import os
import sys
from typing import Any, Dict, Optional


class LLMClient:
    def __init__(self) -> None:
        self.openai_client = None
        self.default_model = "gpt-4o-mini"

        openai_key = os.getenv("OPENAI_API_KEY") or os.getenv("openai_api_key")
        if openai_key:
            try:
                from openai import OpenAI

                self.openai_client = OpenAI(api_key=openai_key)
                print("Using OpenAI client", file=sys.stderr)
                return
            except Exception as e:
                print(f"OpenAI init failed: {e}", file=sys.stderr)

        print("No LLM client configured; filtering will be bypassed", file=sys.stderr)

    def available(self) -> bool:
        return self.openai_client is not None

    def generate(
        self,
        model: str,
        system: str,
        query: str,
        temperature: Optional[float] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        if not self.available():
            return {"error": "LLM client not configured"}

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
