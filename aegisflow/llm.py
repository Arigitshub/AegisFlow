import litellm
import os
from .core import SecurityLiaison, ThreatLevel

class SafeGenerator:
    """
    Universal LLM Wrapper with integrated AegisFlow security checks.
    """
    def __init__(self):
        self.liaison = SecurityLiaison()
        self.scrubber = self.liaison.scrubber
        self.scanner = self.liaison.scanner

    def generate(self, prompt: str, model: str = "gpt-3.5-turbo", **kwargs):
        """
        Securely generates text from an LLM.
        
        Steps:
        1. Pre-Flight: Scan prompt for injections.
        2. Scrub: Redact PII/Keys.
        3. Execute: Call LiteLLM.
        4. Post-Flight: Scan response for dangerous commands.
        """
        
        # Step 1: Pre-Flight Scan (Injection)
        if self.scanner.scan_text(prompt):
            # We treat "prompt_injection" as a specific threat type
            def allow_injection():
                return True # If user overrides, we proceed
                
            try:
                # This mediates the *attempt*. If user says NO, it raises PermissionError.
                self.liaison.mediate("prompt_injection_attempt", {"content": prompt}, allow_injection)
            except PermissionError:
                return "Request blocked by AegisFlow (Prompt Injection Detected)."

        # Step 2: Scrub Keys
        clean_prompt = self.scrubber.scrub(prompt)
        if clean_prompt != prompt:
             print("[AegisFlow] Sensitive keys redacted from prompt.")

        # Step 3: Execute (LiteLLM)
        try:
            # We wrap the actual API call in mediate just in case we want to govern "cost" or "network" later
            # For now, we assume calling the LLM itself is "Low Risk" unless the prompt was bad.
            
            # Using litellm completion (synchronous for simplicity in v1)
            response = litellm.completion(
                model=model, 
                messages=[{"role": "user", "content": clean_prompt}], 
                **kwargs
            )
            content = response.choices[0].message.content
            
        except Exception as e:
            # Check if it's an auth error (likely missing key in test env)
            if "AuthenticationError" in str(e) or "api_key" in str(e):
                 # Fail gracefully in test/CI
                 return f"LLM Error: {str(e)}"
            return f"LLM Error: {str(e)}"

        # Step 4: Post-Flight Scan (Dangerous Commands in Response)
        # Scan content for dangerous behavior (e.g., rm -rf)
        if self.scanner.scan_behavior("shell_exec", {"content": content}):
             try:
                 # If response contains dangerous commands, we mediate.
                 # Context is the response content.
                 def return_dangerous_content():
                     return content
                     
                 return self.liaison.mediate("dangerous_content_generated", {"content": content}, return_dangerous_content)
             except PermissionError:
                 return "Response blocked by AegisFlow (Dangerous Content Detected)."

        return content
