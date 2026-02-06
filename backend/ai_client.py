import os
import json
import logging
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AIClient:
    def __init__(self):
        self.provider = os.getenv("AI_PROVIDER", "google").lower()
        self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        
        # Default models (can be overridden by env vars)
        self.default_flash_model = os.getenv("GEMINI_FLASH_MODEL", "gemini-2.0-flash")
        self.default_pro_model = os.getenv("GEMINI_PRO_MODEL", "gemini-2.0-pro-exp-02-05")
        
        if self.provider == "google":
            import google.generativeai as genai
            if self.api_key:
                genai.configure(api_key=self.api_key)
            else:
                logger.warning("GOOGLE_API_KEY not found. Native Gemini calls will fail.")
        elif self.provider == "litellm":
            try:
                import litellm
                # LiteLLM relies on standard env vars (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
                # But if using Google models via LiteLLM, we manually set it if provided
                if self.api_key and not os.getenv("GEMINI_API_KEY"):
                     os.environ["GEMINI_API_KEY"] = self.api_key
                     
                # Mute verbose litellm logs
                litellm.set_verbose = False
            except ImportError:
                raise ImportError("LiteLLM not installed. Run 'pip install litellm'")
        else:
            logger.warning(f"Unknown AI_PROVIDER: {self.provider}. Defaulting to Google.")
            self.provider = "google"

    def generate_json(self, prompt: str, model_name: Optional[str] = None) -> Any:
        """
        Generates content and parses as JSON.
        Handles provider-specific implementation details.
        """
        target_model = model_name or self.default_flash_model
        
        # If using LiteLLM, check if a specific LiteLLM model map is provided
        if self.provider == "litellm":
            # For LiteLLM, user might want to map "flash" to "gpt-4o-mini"
            # We check LITELLM_MODEL env var first if model_name wasn't explicitly passed
            # But if model_name IS passed (e.g. from the agent), we might need to map it.
            # Simplified approach: If it maps to a known Gemini model, prefix it.
            # Otherwise assume the user knows what they are doing or set LITELLM_MODEL.
            
            # Allow override via env for "generic" requests
            env_model = os.getenv("LITELLM_MODEL")
            if env_model and not model_name:
                target_model = env_model
            
            return self._generate_litellm(prompt, target_model, json_mode=True)
        
        else:
            return self._generate_google(prompt, target_model, json_mode=True)

    def _generate_google(self, prompt: str, model_name: str, json_mode: bool = False) -> Any:
        import google.generativeai as genai
        
        try:
            model = genai.GenerativeModel(model_name)
            config = {"response_mime_type": "application/json"} if json_mode else {}
            
            response = model.generate_content(prompt, generation_config=config)
            
            if json_mode:
                return json.loads(response.text)
            return response.text
            
        except Exception as e:
            logger.error(f"Google Native Generative AI Error: {e}")
            raise

    def _generate_litellm(self, prompt: str, model_name: str, json_mode: bool = False) -> Any:
        from litellm import completion
        
        messages = [{"role": "user", "content": prompt}]
        kwargs = {}
        
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
            
        try:
            response = completion(
                model=model_name, 
                messages=messages,
                **kwargs
            )
            content = response.choices[0].message.content
            
            if json_mode:
                # Robustly extract JSON from markdown blocks
                import re
                match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL | re.IGNORECASE)
                if match:
                    content = match.group(1)
                elif content.strip().startswith("```"):
                     # Fallback for unclosed blocks or other weirdness
                     content = content.strip("`").replace("json", "", 1).strip()
                
                return json.loads(content)
            
            return content
            
        except Exception as e:
            logger.error(f"LiteLLM Error: {e}")
            raise
