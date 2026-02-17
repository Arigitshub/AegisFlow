"""
AegisFlow SafeGenerator (v3.0)
Secure LLM wrapper with input/output rails and async support.
"""

from typing import Any, Dict, Optional, Type

from .core import SecurityLiaison
from .scanners import BehavioralScanner
from .scrubber import KeyScrubber
from .sentinel import ThreatLevel


class SafeGenerator:
    """
    Wraps LLM calls with AegisFlow's full security pipeline:
    1. Input rail chain execution
    2. Pre-flight scan (injection detection via plugins)
    3. Key scrubbing
    4. LLM execution
    5. Post-flight scan (dangerous output detection)
    6. Output rail chain execution
    7. Optional: Pydantic structured output validation
    """

    def __init__(self, liaison: SecurityLiaison = None):
        self.liaison = liaison or SecurityLiaison()
        self.scanner = BehavioralScanner()
        self.scrubber = KeyScrubber()

    def generate(self, prompt: str, model: str = "gpt-3.5-turbo",
                 response_model: Optional[Type] = None, **kwargs) -> Any:
        """
        Generate a response from an LLM with full security pipeline.
        
        Args:
            prompt: The user prompt
            model: LLM model name (any litellm-supported model)
            response_model: Optional Pydantic model for structured output validation
            **kwargs: Additional args passed to litellm.completion
        
        Returns:
            String response (or Pydantic model instance if response_model provided)
        """
        import litellm

        # Step 1: Input Rails
        input_result = self.liaison.input_rails.run(prompt, {"source": "llm_prompt"})
        if not input_result.passed:
            return f"[AegisFlow] Prompt blocked: {input_result.reason}"
        
        working_prompt = input_result.modified_content or prompt

        # Step 2: Pre-Flight Scan (Plugin-based injection detection)
        if self.scanner.scan_text(working_prompt):
            try:
                self.liaison.mediate(
                    "prompt_injection_attempt", 
                    {"content": working_prompt}, 
                    lambda: True
                )
            except PermissionError:
                return "[AegisFlow] Request blocked (Injection Detected)."

        # Step 3: Scrub Keys
        clean_prompt = self.scrubber.scrub(working_prompt)

        # Step 4: Execute LLM
        try:
            response = litellm.completion(
                model=model,
                messages=[{"role": "user", "content": clean_prompt}],
                **kwargs
            )
            content = response.choices[0].message.content
        except Exception as e:
            return f"[AegisFlow] LLM Error: {str(e)}"

        # Step 5: Post-Flight Scan
        if self.scanner.scan_behavior("shell_exec", {"content": content}):
            try:
                def return_content():
                    return content
                content = self.liaison.mediate(
                    "dangerous_content_generated", 
                    {"content": content}, 
                    return_content
                )
            except PermissionError:
                return "[AegisFlow] Response blocked (Dangerous Content)."

        # Step 6: Output Rails
        output_result = self.liaison.output_rails.run(content, {"source": "llm_response"})
        if not output_result.passed:
            return f"[AegisFlow] Response blocked: {output_result.reason}"
        
        final_content = output_result.modified_content or content

        # Step 7: Structured Output Validation
        if response_model is not None:
            try:
                from pydantic import BaseModel
                if issubclass(response_model, BaseModel):
                    import json
                    try:
                        data = json.loads(final_content)
                        return response_model(**data)
                    except (json.JSONDecodeError, Exception) as e:
                        return f"[AegisFlow] Structured output validation failed: {e}"
            except ImportError:
                pass

        return final_content

    async def async_generate(self, prompt: str, model: str = "gpt-3.5-turbo",
                             response_model: Optional[Type] = None, **kwargs) -> Any:
        """
        Async version of generate() using litellm.acompletion.
        Does NOT support interactive HIGH-risk approval (will block instead).
        """
        import litellm

        # Input Rails
        input_result = self.liaison.input_rails.run(prompt, {"source": "llm_prompt"})
        if not input_result.passed:
            return f"[AegisFlow] Prompt blocked: {input_result.reason}"
        
        working_prompt = input_result.modified_content or prompt

        # Pre-flight scan
        if self.scanner.scan_text(working_prompt):
            return "[AegisFlow] Async request blocked (Injection Detected)."

        # Scrub
        clean_prompt = self.scrubber.scrub(working_prompt)

        # Async LLM call
        try:
            response = await litellm.acompletion(
                model=model,
                messages=[{"role": "user", "content": clean_prompt}],
                **kwargs
            )
            content = response.choices[0].message.content
        except Exception as e:
            return f"[AegisFlow] LLM Error: {str(e)}"

        # Post-flight scan
        if self.scanner.scan_behavior("shell_exec", {"content": content}):
            return "[AegisFlow] Async response blocked (Dangerous Content)."

        # Output rails
        output_result = self.liaison.output_rails.run(content, {"source": "llm_response"})
        final_content = output_result.modified_content or content

        # Structured output
        if response_model is not None:
            try:
                from pydantic import BaseModel
                if issubclass(response_model, BaseModel):
                    import json
                    try:
                        data = json.loads(final_content)
                        return response_model(**data)
                    except Exception as e:
                        return f"[AegisFlow] Validation failed: {e}"
            except ImportError:
                pass

        return final_content
