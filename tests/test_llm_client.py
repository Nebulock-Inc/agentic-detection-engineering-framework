"""Tests for LLM client (provider protocol + implementations)."""

from unittest.mock import Mock, patch
from adef.core.schema import SchemaField
from adef.core.llm_client import (
    LLMProvider,
    ClaudeLLMProvider,
    OpenAILLMProvider,
    get_llm_provider,
    generate_field_descriptions
)


def test_llm_provider_protocol():
    """Test LLMProvider protocol can be implemented."""
    class MockProvider:
        def generate_structured(self, prompt: str, schema: dict) -> dict:
            return {"descriptions": []}

    provider: LLMProvider = MockProvider()
    result = provider.generate_structured("test", {})
    assert "descriptions" in result


def test_claude_provider_calls_api():
    """Test ClaudeLLMProvider calls Anthropic API."""
    with patch('adef.core.llm_client.Anthropic') as mock_anthropic:
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text='{"descriptions": []}')]
        mock_client.messages.create.return_value = mock_response
        mock_anthropic.return_value = mock_client

        provider = ClaudeLLMProvider()
        result = provider.generate_structured("test prompt", {"type": "object"})

        assert mock_client.messages.create.called
        assert "descriptions" in result


def test_openai_provider_calls_api():
    """Test OpenAILLMProvider calls OpenAI API."""
    with patch('adef.core.llm_client.OpenAI') as mock_openai:
        mock_client = Mock()
        mock_response = Mock()
        mock_choice = Mock()
        mock_choice.message.content = '{"descriptions": []}'
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        provider = OpenAILLMProvider()
        result = provider.generate_structured("test prompt", {"type": "object"})

        assert mock_client.chat.completions.create.called
        assert "descriptions" in result


def test_get_llm_provider_claude(monkeypatch):
    """Test get_llm_provider returns Claude by default."""
    monkeypatch.setenv("ADEF_LLM_PROVIDER", "claude")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    with patch('adef.core.llm_client.Anthropic') as mock_anthropic:
        mock_anthropic.return_value = Mock()
        provider = get_llm_provider()
        assert isinstance(provider, ClaudeLLMProvider)


def test_get_llm_provider_openai(monkeypatch):
    """Test get_llm_provider returns OpenAI when configured."""
    monkeypatch.setenv("ADEF_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    with patch('adef.core.llm_client.OpenAI') as mock_openai:
        mock_openai.return_value = Mock()
        provider = get_llm_provider()
        assert isinstance(provider, OpenAILLMProvider)


def test_generate_field_descriptions():
    """Test batch field description generation."""
    fields = [
        SchemaField(
            name="parent_image",
            in_rules=True,
            in_data=True,
            type="string",
            population=0.98,
            sample_values=["cmd.exe", "mshta.exe"],
            description="",
            description_source="generated"
        ),
        SchemaField(
            name="process_id",
            in_rules=False,
            in_data=True,
            type="integer",
            population=1.0,
            sample_values=[1234, 5678],
            description="",
            description_source="generated"
        )
    ]

    with patch('adef.core.llm_client.get_llm_provider') as mock_get_provider:
        mock_provider = Mock()
        mock_provider.generate_structured.return_value = {
            "descriptions": [
                {"name": "parent_image", "description": "Executable path of parent process"},
                {"name": "process_id", "description": "Process identifier"}
            ]
        }
        mock_get_provider.return_value = mock_provider

        descriptions = generate_field_descriptions(fields, "sql", "edr_process")

        assert descriptions["parent_image"] == "Executable path of parent process"
        assert descriptions["process_id"] == "Process identifier"
