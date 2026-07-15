"""LLM client for generating field descriptions (provider-agnostic)."""

from __future__ import annotations
import os
import json
from typing import Protocol, Any

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None  # type: ignore

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # type: ignore


class LLMProvider(Protocol):
    """Provider-agnostic LLM interface."""

    def generate_structured(self, prompt: str, schema: dict) -> dict:
        """Generate structured output matching the given JSON schema.

        Args:
            prompt: System/user prompt
            schema: JSON schema for response structure

        Returns:
            Dict matching the schema
        """
        ...


class ClaudeLLMProvider:
    """Claude LLM provider using Anthropic SDK."""

    def __init__(self, api_key: str | None = None):
        if Anthropic is None:
            raise RuntimeError("anthropic package not installed. Install with: pip install anthropic")
        self.client = Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))

    def generate_structured(self, prompt: str, schema: dict) -> dict:
        """Generate structured output using Claude."""
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
            system="You are a data schema expert. Respond with valid JSON matching the provided schema."
        )

        # Extract JSON from response
        text = response.content[0].text
        return json.loads(text)


class OpenAILLMProvider:
    """OpenAI LLM provider using OpenAI SDK."""

    def __init__(self, api_key: str | None = None):
        if OpenAI is None:
            raise RuntimeError("openai package not installed. Install with: pip install openai")
        self.client = OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))

    def generate_structured(self, prompt: str, schema: dict) -> dict:
        """Generate structured output using GPT-4."""
        response = self.client.chat.completions.create(
            model="gpt-4-turbo-preview",
            messages=[
                {"role": "system", "content": "You are a data schema expert. Respond with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )

        text = response.choices[0].message.content
        return json.loads(text)


def get_llm_provider() -> LLMProvider:
    """Load LLM provider from environment configuration.

    Returns:
        LLM provider instance

    Raises:
        ValueError: If provider name is invalid
        RuntimeError: If provider SDK not installed or API key missing
    """
    provider_name = os.getenv("ADEF_LLM_PROVIDER", "claude").lower()

    if provider_name == "claude":
        return ClaudeLLMProvider()
    elif provider_name == "openai":
        return OpenAILLMProvider()
    else:
        raise ValueError(f"Unknown LLM provider: {provider_name}. Use 'claude' or 'openai'.")


def generate_field_descriptions(
    fields: list[Any],  # SchemaField, but avoiding circular import
    query_language: str,
    source: str
) -> dict[str, str]:
    """Generate descriptions for all fields in batch.

    Args:
        fields: List of SchemaField objects
        query_language: Query language (sql, spl, cql, kql)
        source: Data source name

    Returns:
        Dict mapping field name to description

    Raises:
        RuntimeError: If LLM call fails
    """
    prompt = f"""Generate concise descriptions for these data fields from a {query_language} {source} data source.

Fields to describe:
"""

    for field in fields:
        prompt += f"\n- {field.name} ({field.type}, {int(field.population * 100)}% populated)"
        if field.sample_values:
            samples = [str(v) for v in field.sample_values if v is not None][:2]
            prompt += f" examples: {', '.join(samples)}"

    prompt += "\n\nRespond with JSON: {\"descriptions\": [{\"name\": \"field_name\", \"description\": \"...\"}, ...]}"

    schema = {
        "type": "object",
        "properties": {
            "descriptions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "description": {"type": "string"}
                    },
                    "required": ["name", "description"]
                }
            }
        },
        "required": ["descriptions"]
    }

    try:
        provider = get_llm_provider()
        result = provider.generate_structured(prompt, schema)
        return {item["name"]: item["description"] for item in result["descriptions"]}
    except Exception as e:
        # ponytail: log to stderr in production
        raise RuntimeError(f"LLM description generation failed: {e}")
