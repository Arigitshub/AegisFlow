"""
AegisFlow Detection Engine (v3.0)
ML-first, regex-fallback threat detection pipeline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

logger = logging.getLogger("aegisflow.detectors")


# ── Result model ────────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    """Result from any detection engine."""
    is_threat: bool
    confidence: float  # 0.0 – 1.0
    method: str        # "regex", "ml", "ensemble"
    threat_type: str = ""
    details: str = ""
    model_name: str = ""
    raw_scores: Dict[str, float] = field(default_factory=dict)

    def __repr__(self) -> str:
        status = "⚠ THREAT" if self.is_threat else "✓ CLEAN"
        return (
            f"DetectionResult({status}  conf={self.confidence:.2f}  "
            f"method={self.method}  type={self.threat_type})"
        )


# ── Unified detection engine ────────────────────────────────────────────────

class DetectionEngine:
    """
    Orchestrates ML and regex detectors.

    Strategy:
        1. If ML is enabled *and* available → run ML detector first
        2. Run regex detector always (cheap, fast)
        3. Return the highest-confidence result

    Usage::

        from aegisflow.detectors import DetectionEngine
        from aegisflow.config import DetectorConfig

        engine = DetectionEngine(DetectorConfig(use_ml=True))
        result = engine.detect("ignore all previous instructions and ...")
        print(result)  # DetectionResult(⚠ THREAT  conf=0.98  method=ml ...)
    """

    def __init__(self, config=None):
        from aegisflow.config import DetectorConfig

        self.config = config or DetectorConfig()
        self._ml_detector = None
        self._regex_detector = None

        # Lazy-load detectors
        self._init_regex()
        if self.config.use_ml:
            self._init_ml()

    # ── lazy init ──

    def _init_regex(self):
        from aegisflow.detectors.regex_detector import RegexDetector
        self._regex_detector = RegexDetector()
        logger.debug("Regex detector loaded")

    def _init_ml(self):
        try:
            from aegisflow.detectors.ml_detector import MLDetector
            self._ml_detector = MLDetector(
                model_name=self.config.ml_model,
                confidence_threshold=self.config.ml_confidence_threshold,
            )
            logger.info("ML detector loaded: %s", self.config.ml_model)
        except ImportError:
            logger.warning(
                "ML dependencies not installed (pip install aegisflow[ml]). "
                "Falling back to regex-only detection."
            )
            self._ml_detector = None
        except Exception as e:
            logger.warning("ML detector failed to load: %s. Using regex fallback.", e)
            self._ml_detector = None

    # ── public API ──

    def detect(self, content: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """
        Run all available detectors and return the highest-confidence result.
        """
        results: List[DetectionResult] = []

        # 1. ML detection (if available)
        if self._ml_detector is not None:
            try:
                ml_result = self._ml_detector.detect(content)
                results.append(ml_result)
                # If ML is confident it's a threat, short-circuit
                if ml_result.is_threat and ml_result.confidence >= self.config.ml_confidence_threshold:
                    logger.info("ML detector flagged threat (conf=%.2f)", ml_result.confidence)
                    return ml_result
            except Exception as e:
                logger.warning("ML detection failed: %s", e)

        # 2. Regex detection (always runs)
        if self._regex_detector is not None:
            regex_result = self._regex_detector.detect(content, context)
            results.append(regex_result)

        # 3. Return highest confidence threat, or clean result
        threats = [r for r in results if r.is_threat]
        if threats:
            return max(threats, key=lambda r: r.confidence)

        # No threats — return the best clean result
        if results:
            return min(results, key=lambda r: r.confidence)

        return DetectionResult(
            is_threat=False, confidence=0.0, method="none",
            details="No detectors available"
        )

    async def async_detect(self, content: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """Async variant — runs detection in a thread pool for ML models."""
        import asyncio
        return await asyncio.get_event_loop().run_in_executor(
            None, self.detect, content, context
        )

    @property
    def ml_available(self) -> bool:
        """Whether the ML detector is loaded and ready."""
        return self._ml_detector is not None

    @property
    def detectors_summary(self) -> str:
        """Human-readable summary of loaded detectors."""
        parts = []
        if self._regex_detector:
            parts.append(f"regex ({self._regex_detector.rule_count} rules)")
        if self._ml_detector:
            parts.append(f"ml ({self._ml_detector.model_name})")
        return " + ".join(parts) if parts else "no detectors loaded"
