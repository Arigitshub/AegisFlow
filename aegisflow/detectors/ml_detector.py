"""
AegisFlow ML Detector (v3.0)
Transformer-based prompt injection detection using HuggingFace models.4

Requires: pip install aegisflow[ml]  (installs transformers + torch)
"""

from __future__ import annotations

import logging
from typing import Optional

from aegisflow.detectors import DetectionResult

logger = logging.getLogger("aegisflow.detectors.ml")

# These imports will raise ImportError if ML deps aren't installed,
# which is caught by the DetectionEngine in __init__.py
from transformers import pipeline, Pipeline  # noqa: E402


class MLDetector:
    """
    Transformer-based injection / harmful-content detector.

    Uses a HuggingFace text-classification pipeline to score inputs.

    Default model: ``protectai/deberta-v3-base-prompt-injection-v2``
    — a fine-tuned DeBERTa-v3-base classifier for prompt injection detection.

    The model outputs labels like ``INJECTION`` / ``SAFE`` with confidence scores.
    If confidence for INJECTION exceeds the threshold, the input is flagged.

    Usage::

        detector = MLDetector()
        result = detector.detect("Ignore all previous instructions and ...")
        print(result.is_threat, result.confidence)

    Graceful degradation:
        - If ``transformers`` / ``torch`` aren't installed → ImportError at import time
        - The ``DetectionEngine`` catches this and falls back to regex-only
    """

    # Class-level pipeline cache to avoid reloading the model
    _pipeline_cache: dict[str, Pipeline] = {}

    def __init__(
        self,
        model_name: str = "protectai/deberta-v3-base-prompt-injection-v2",
        confidence_threshold: float = 0.85,
        max_length: int = 512,
        device: Optional[int] = None,
    ):
        self.model_name = model_name
        self.confidence_threshold = confidence_threshold
        self.max_length = max_length
        self.device = device

        # Load or reuse cached pipeline
        if model_name not in self._pipeline_cache:
            logger.info("Loading ML model: %s ...", model_name)
            try:
                pipe = pipeline(
                    "text-classification",
                    model=model_name,
                    truncation=True,
                    max_length=max_length,
                    device=device,
                )
                self._pipeline_cache[model_name] = pipe
                logger.info("ML model loaded successfully: %s", model_name)
            except Exception as e:
                logger.error("Failed to load ML model '%s': %s", model_name, e)
                raise

        self._pipe = self._pipeline_cache[model_name]

    def detect(self, content: str) -> DetectionResult:
        """
        Classify content using the transformer model.

        Returns a DetectionResult with:
            - is_threat: True if injection label exceeds threshold
            - confidence: model confidence score
            - method: "ml"
            - model_name: the HuggingFace model used
        """
        if not content or not content.strip():
            return DetectionResult(
                is_threat=False,
                confidence=0.0,
                method="ml",
                model_name=self.model_name,
                details="Empty content",
            )

        try:
            # Run the pipeline — returns list of [{label, score}]
            predictions = self._pipe(content[:self.max_length * 4])  # rough char limit
            top = predictions[0]
            label = top["label"].upper()
            score = top["score"]

            # Common label formats from injection models:
            # INJECTION / SAFE, LABEL_1 / LABEL_0, positive / negative
            is_injection_label = label in ("INJECTION", "LABEL_1", "POSITIVE", "1", "UNSAFE")
            is_safe_label = label in ("SAFE", "LABEL_0", "NEGATIVE", "0", "BENIGN")

            if is_injection_label:
                is_threat = score >= self.confidence_threshold
                return DetectionResult(
                    is_threat=is_threat,
                    confidence=score,
                    method="ml",
                    threat_type="injection" if is_threat else "",
                    details=f"ML prediction: {label}={score:.4f} "
                            f"(threshold={self.confidence_threshold})",
                    model_name=self.model_name,
                    raw_scores={label: score},
                )
            elif is_safe_label:
                # Invert: if SAFE with high confidence, it's clean
                injection_confidence = 1.0 - score
                is_threat = injection_confidence >= self.confidence_threshold
                return DetectionResult(
                    is_threat=is_threat,
                    confidence=injection_confidence,
                    method="ml",
                    threat_type="injection" if is_threat else "",
                    details=f"ML prediction: {label}={score:.4f} → "
                            f"injection_confidence={injection_confidence:.4f}",
                    model_name=self.model_name,
                    raw_scores={"SAFE": score, "INJECTION_implied": injection_confidence},
                )
            else:
                # Unknown label format — treat conservatively
                logger.warning("Unknown model label: %s (score=%.4f)", label, score)
                return DetectionResult(
                    is_threat=False,
                    confidence=0.0,
                    method="ml",
                    model_name=self.model_name,
                    details=f"Unknown label format: {label}={score:.4f}",
                    raw_scores={label: score},
                )

        except Exception as e:
            logger.error("ML detection failed: %s", e)
            return DetectionResult(
                is_threat=False,
                confidence=0.0,
                method="ml",
                model_name=self.model_name,
                details=f"ML inference error: {e}",
            )

    def batch_detect(self, texts: list[str]) -> list[DetectionResult]:
        """
        Batch classification for multiple inputs.
        More efficient than calling detect() in a loop (single forward pass).
        """
        results = []
        if not texts:
            return results

        try:
            predictions = self._pipe(
                [t[:self.max_length * 4] for t in texts],
                batch_size=min(len(texts), 32),
            )
            for text, pred in zip(texts, predictions):
                label = pred["label"].upper()
                score = pred["score"]

                is_injection_label = label in ("INJECTION", "LABEL_1", "POSITIVE", "1", "UNSAFE")
                if is_injection_label:
                    is_threat = score >= self.confidence_threshold
                    confidence = score
                else:
                    confidence = 1.0 - score
                    is_threat = confidence >= self.confidence_threshold

                results.append(DetectionResult(
                    is_threat=is_threat,
                    confidence=confidence,
                    method="ml",
                    threat_type="injection" if is_threat else "",
                    details=f"Batch ML: {label}={score:.4f}",
                    model_name=self.model_name,
                ))
        except Exception as e:
            logger.error("Batch ML detection failed: %s", e)
            # Return empty results for all inputs on failure
            results = [
                DetectionResult(
                    is_threat=False, confidence=0.0, method="ml",
                    model_name=self.model_name, details=f"Batch error: {e}"
                )
                for _ in texts
            ]

        return results

    @classmethod
    def clear_cache(cls) -> None:
        """Clear the model pipeline cache to free GPU/CPU memory."""
        cls._pipeline_cache.clear()
        logger.info("ML pipeline cache cleared")
