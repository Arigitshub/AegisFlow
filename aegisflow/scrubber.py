import re

class KeyScrubber:
    """
    Detects and masks strings resembling API keys, EMV data, or PII.
    """
    
    # Heuristics for common keys
    PATTERNS = {
        "sk_live": r"sk_live_[0-9a-zA-Z]{24}", # Stripe-ish
        "api_key": r"(?i)api_?key\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
        "generic_secret": r"(?i)secret\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
        "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        # "credit_card": r"\b(?:\d[ -]*?){13,16}\b" # Simplified, can be prone to false positives
    }

    def scrub(self, text: str) -> str:
        """
        Replaces sensitive data with [REDACTED].
        """
        scrubbed_text = text
        for name, pattern in self.PATTERNS.items():
            # For regexes with groups, we replace the group. 
            # For simple matches (email), we replace the whole match.
            
            regex = re.compile(pattern)
            
            def replace_callback(match):
                if match.groups():
                    # If we captured a specific group (the key value), redact just that
                    full_match = match.group(0)
                    key_value = match.group(1)
                    return full_match.replace(key_value, "[REDACTED]")
                else:
                    return "[REDACTED]"

            scrubbed_text = regex.sub(replace_callback, scrubbed_text)
            
        return scrubbed_text
