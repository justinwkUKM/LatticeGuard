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

    def generate_json(self, prompt: str, model_name: Optional[str] = None) -> tuple[Any, Dict[str, int]]:
        """
        Generates content and parses as JSON.
        Returns: (json_content, usage_dict)
        usage_dict keys: input_tokens, output_tokens
        """
        target_model = model_name or self.default_flash_model
        
        # If using LiteLLM, check if a specific LiteLLM model map is provided
        if self.provider == "litellm":
            env_model = os.getenv("LITELLM_MODEL")
            if env_model and not model_name:
                target_model = env_model
            
            return self._generate_litellm(prompt, target_model, json_mode=True)
        
        else:
            return self._generate_google(prompt, target_model, json_mode=True)

    def _generate_google(self, prompt: str, model_name: str, json_mode: bool = False) -> tuple[Any, Dict[str, int]]:
        import google.generativeai as genai
        
        try:
            model = genai.GenerativeModel(model_name)
            config = {"response_mime_type": "application/json"} if json_mode else {}
            
            response = model.generate_content(prompt, generation_config=config)
            
            # Extract usage
            usage = {
                "input_tokens": response.usage_metadata.prompt_token_count,
                "output_tokens": response.usage_metadata.candidates_token_count
            }
            
            if json_mode:
                return json.loads(response.text), usage
            return response.text, usage
            
        except Exception as e:
            logger.error(f"Google Native Generative AI Error: {e}")
            raise

    def _generate_litellm(self, prompt: str, model_name: str, json_mode: bool = False) -> tuple[Any, Dict[str, int]]:
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
            
            # Extract usage
            usage = {
                "input_tokens": response.usage.prompt_tokens,
                "output_tokens": response.usage.completion_tokens
            }
            
            if json_mode:
                # Robustly extract JSON from markdown blocks
                import re
                match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL | re.IGNORECASE)
                if match:
                    content = match.group(1)
                elif content.strip().startswith("```"):
                     # Fallback for unclosed blocks or other weirdness
                     content = content.strip("`").replace("json", "", 1).strip()
                
                return json.loads(content), usage
            
            return content, usage
            
        except Exception as e:
            logger.error(f"LiteLLM Error: {e}")
            raise
