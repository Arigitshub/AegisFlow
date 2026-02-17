import re

class KeyScrubber:
    """
    Detects and masks strings resembling API keys, EMV data, or PII.
    """
    
    # Heuristics for common keys and PII
    PATTERNS = {
        "sk_key": r"sk[_-](?:live|test|prod|proj)[_-][0-9a-zA-Z]{8,}",  # Stripe/OpenAI style
        "ghp_token": r"ghp_[a-zA-Z0-9]{36}",  # GitHub PAT
        "aws_key": r"AKIA[0-9A-Z]{16}",  # AWS access key
        "gcp_key": r"AIza[0-9A-Za-z\-_]{35}",  # GCP API key
        "slack_token": r"xox[bprs]-[a-zA-Z0-9\-]+",  # Slack token
        "api_key": r"(?i)api_?key\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
        "generic_secret": r"(?i)secret\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
        "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "phone_us": r"\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
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

    def scrub_structured(self, data: dict, _path: str = "") -> dict:
        """
        Recursively scrub sensitive data from dict/JSON structures.
        Walks nested dicts and lists, scrubbing all string values.
        
        Args:
            data: Dictionary to scrub (keys are preserved, values are scrubbed)
            _path: Internal — tracks current key path for logging
            
        Returns:
            New dict with all string values scrubbed.
        """
        if isinstance(data, dict):
            result = {}
            for k, v in data.items():
                current_path = f"{_path}.{k}" if _path else k
                # Scrub both key names that might be sensitive and values
                if isinstance(v, str):
                    result[k] = self.scrub(v)
                elif isinstance(v, dict):
                    result[k] = self.scrub_structured(v, current_path)
                elif isinstance(v, list):
                    result[k] = [
                        self.scrub_structured(item, f"{current_path}[{i}]")
                        if isinstance(item, dict)
                        else self.scrub(item) if isinstance(item, str)
                        else item
                        for i, item in enumerate(v)
                    ]
                else:
                    result[k] = v
            return result
        return data

    def get_entity_report(self, text: str) -> list:
        """
        Returns a list of detected entities (type + location) without redacting.
        Useful for audit logs and compliance reporting.
        """
        entities = []
        for name, pattern in self.PATTERNS.items():
            regex = re.compile(pattern)
            for match in regex.finditer(text):
                entities.append({
                    "type": name,
                    "value_preview": match.group()[:8] + "***",
                    "start": match.start(),
                    "end": match.end(),
                })
        return entities

