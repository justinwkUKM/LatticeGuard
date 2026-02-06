import os
import json
import pytest
from unittest.mock import MagicMock, patch
from backend.ai_client import AIClient

# We patch the external libraries directly
# providing they are importable. Since we installed them, they should be.

def test_default_google_provider():
    with patch.dict(os.environ, {}, clear=True):
        client = AIClient()
        assert client.provider == "google"

def test_litellm_provider_init():
    # We strip env to ensure clean state, then set specific vars
    with patch.dict(os.environ, {"AI_PROVIDER": "litellm", "GEMINI_API_KEY": "fake_key"}, clear=True):
        # We need to mock litellm module import if it happens in __init__
        # But since we installed it, it should import fine.
        # We just want to check provider is set.
        client = AIClient()
        assert client.provider == "litellm"

def test_generate_json_google():
    client = AIClient() # Default Google
    
    # Patch google.genai.Client
    with patch("google.genai.Client") as MockClient:
        mock_client_instance = MagicMock()
        MockClient.return_value = mock_client_instance
        
        mock_response = MagicMock()
        mock_response.text = '{"key": "value"}'
        mock_response.usage_metadata.prompt_token_count = 10
        mock_response.usage_metadata.candidates_token_count = 5
        mock_client_instance.models.generate_content.return_value = mock_response
        
        # Force re-creation of client
        client._google_client = mock_client_instance
        
        result, usage = client.generate_json("test prompt")
        
        assert result == {"key": "value"}
        assert usage == {"input_tokens": 10, "output_tokens": 5}
        mock_client_instance.models.generate_content.assert_called_once()
        # Check json mode config
        call_kwargs = mock_client_instance.models.generate_content.call_args[1]
        assert call_kwargs['config'].response_mime_type == "application/json"

def test_generate_json_litellm():
    with patch.dict(os.environ, {"AI_PROVIDER": "litellm", "GEMINI_API_KEY": "fake"}, clear=True):
        # Patch litellm.completion
        with patch("litellm.completion") as mock_completion:
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = '{"foo": "bar"}'
            mock_response.usage.prompt_tokens = 15
            mock_response.usage.completion_tokens = 8
            mock_completion.return_value = mock_response
            
            client = AIClient()
            result, usage = client.generate_json("test prompt", model_name="gpt-4")
            
            assert result == {"foo": "bar"}
            assert usage == {"input_tokens": 15, "output_tokens": 8}
            mock_completion.assert_called_once()
            kwargs = mock_completion.call_args[1]
            assert kwargs['model'] == "gpt-4"
            assert kwargs['response_format'] == {"type": "json_object"}

def test_litellm_model_override():
    with patch.dict(os.environ, {"AI_PROVIDER": "litellm", "LITELLM_MODEL": "claude-3", "GEMINI_API_KEY": "fake"}, clear=True):
         with patch("litellm.completion") as mock_completion:
             mock_response = MagicMock()
             mock_response.choices = [MagicMock()]
             mock_response.choices[0].message.content = '{}'
             mock_completion.return_value = mock_response
             
             client = AIClient()
             # No model passed, should use env var
             client.generate_json("prompt")
             
             kwargs = mock_completion.call_args[1]
             # Note: default model from class init is 'gemini-2.0-flash'
             # logic: target_model = model_name or default
             # then if provider==litellm and env_model and not model_name -> target_model = env_model
             assert kwargs['model'] == "claude-3"

