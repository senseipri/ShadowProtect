import asyncio
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .behavioural import BehaviouralAnomalyEngine
from .exfiltration import ExfiltrationDetector
from .hidden_channels import HiddenChannelDetector
from .injection import InjectionResult, detect_injection
from .preprocessor import PreprocessedEvent, preprocess_event
from .semantic import IntentResult, SemanticDetector
from .taint import PropagationResult, TaintTracker
from .toolchain import ToolChainAnalyser, ToolChainResult

WEIGHTS = {
    "injection": 0.30,
    "semantic": 0.20,
    "behavioural": 0.15,
    "toolchain": 0.15,
    "exfiltration": 0.12,
    "hidden": 0.08,
}


@dataclass
class ThreatVerdict:
    composite_score: float
    severity: str
    triggered_detectors: list[str]
    primary_threat_type: str
    taint_chain: list[dict[str, Any]]
    alert_description: str
    trust_delta: float
    recommended_action: str
    confidence: float
    evidence: dict[str, Any]


class DetectionEngine:
    def __init__(self) -> None:
        self.semantic = SemanticDetector()
        self.behavioural = BehaviouralAnomalyEngine()
        self.toolchain = ToolChainAnalyser()
        self.exfiltration = ExfiltrationDetector()
        self.hidden = HiddenChannelDetector()
        self.taint_tracker = TaintTracker()

        self._event_history: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=200))
        self._verdict_history: deque[dict[str, Any]] = deque(maxlen=2000)

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    async def initialise(self) -> None:
        await self.taint_tracker.initialize()

    def set_broadcast_hook(self, hook) -> None:
        self.taint_tracker.set_broadcast_hook(hook)

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        if score >= 10:
            return "LOW"
        return "CLEAN"

    @staticmethod
    def _event_source(event: dict[str, Any]) -> str:
        return str(event.get("source") or event.get("agent_id") or "unknown-agent")

    @staticmethod
    def _event_target(event: dict[str, Any]) -> str:
        return str(event.get("target") or "unknown-target")

    def _tool_name(self, event: dict[str, Any]) -> str:
        return str(event.get("tool_name") or event.get("tool") or event.get("type") or "unknown_tool")

    def _tool_args(self, event: dict[str, Any]) -> Any:
        return event.get("args") or event.get("tool_args") or {}

    def _all_text(self, preprocessed: PreprocessedEvent) -> str:
        if preprocessed.decoded_texts:
            return "\n".join(preprocessed.decoded_texts)
        return str(preprocessed.original_event)

    def _semantic_from_texts(self, texts: list[str]) -> IntentResult:
        if not texts:
            return self.semantic.classify_intent("")
        best: IntentResult | None = None
        for text in texts:
            current = self.semantic.classify_intent(text)
            if best is None or current.final_score > best.final_score:
                best = current
        assert best is not None
        return best

    async def _run_injection(self, preprocessed: PreprocessedEvent) -> InjectionResult:
        return await asyncio.to_thread(detect_injection, preprocessed.decoded_texts)

    async def _run_semantic(self, preprocessed: PreprocessedEvent) -> IntentResult:
        return await asyncio.to_thread(self._semantic_from_texts, preprocessed.decoded_texts)

    async def _run_behavioural(self, source: str, event: dict[str, Any]):
        return await self.behavioural.compute_anomaly_score(source, event)

    async def _run_toolchain(self, source: str, event: dict[str, Any]) -> ToolChainResult:
        return await self.toolchain.analyse_tool_call(source, self._tool_name(event), self._tool_args(event))

    async def _run_exfiltration(self, source: str, preprocessed: PreprocessedEvent):
        text = self._all_text(preprocessed)
        history = list(self._event_history[source])
        return await asyncio.to_thread(self.exfiltration.evaluate_exfiltration_risk, text, history, source)

    async def _run_hidden(self, source: str, event: dict[str, Any], preprocessed: PreprocessedEvent):
        text = self._all_text(preprocessed)

        stego = self.hidden.detect_steganography(text)
        unicode_res = self.hidden.detect_unusual_unicode(text)
        json_score = self.hidden.detect_json_injection(preprocessed.original_event)
        covert_score = self.hidden.detect_encoding_covert_channel(preprocessed.decoded_texts, source)

        tool_output_score = 0
        event_type = str(event.get("type", "")).upper()
        if event_type == "TOOL_RESULT":
            tool_output_score = self.hidden.detect_prompt_in_tool_output(
                self._tool_name(event),
                str(event.get("output") or event.get("message") or text),
            )

        total = min(
            100,
            stego.score + unicode_res.score + json_score + covert_score + tool_output_score,
        )
        return {
            "score": total,
            "stego": stego,
            "unicode": unicode_res,
            "json_score": json_score,
            "covert_score": covert_score,
            "tool_output_score": tool_output_score,
        }

    def _recommended_action(self, severity: str) -> str:
        if severity == "CRITICAL":
            return "Quarantine source agent, block downstream execution, require human approval."
        if severity == "HIGH":
            return "Suspend sensitive tool access and isolate agent communications."
        if severity == "MEDIUM":
            return "Increase monitoring, limit privileged actions, and re-validate instructions."
        if severity == "LOW":
            return "Log and continue with enhanced observation."
        return "No action required."

    def _primary_threat_type(
        self,
        injection: InjectionResult,
        exfiltration: dict[str, Any],
        hidden: dict[str, Any],
        behavioural_result,
        toolchain_result: ToolChainResult,
        propagation: PropagationResult,
    ) -> str:
        if hidden.get("tool_output_score", 0) >= 50:
            return "INDIRECT"
        if exfiltration.get("score", 0) >= 60:
            return "EXFILTRATION"
        if injection.score >= 40:
            return "INJECTION"
        if propagation.propagated_taint > 0:
            return "PROPAGATION"
        if getattr(behavioural_result, "behaviour_shift", False):
            return "BEHAVIOUR_SHIFT"
        if toolchain_result.score >= 50:
            return "ESCALATION"
        return "GENERAL"

    def _alert_description(
        self,
        threat_type: str,
        event: dict[str, Any],
        injection: InjectionResult,
        exfiltration: dict[str, Any],
        propagation: PropagationResult,
        hidden: dict[str, Any],
    ) -> str:
        source = self._event_source(event)
        target = self._event_target(event)
        if threat_type == "INJECTION":
            matched = injection.matches[0].excerpt if injection.matches else "unknown-pattern"
            return f"Agent {source} received prompt injection targeting {target}. Pattern: {matched}"
        if threat_type == "EXFILTRATION":
            pii = exfiltration.get("pii")
            pii_types = ",".join(getattr(pii, "found_types", [])) if pii else "sensitive data"
            return f"Agent {source} appears to be exfiltrating {pii_types} to {target}"
        if threat_type == "PROPAGATION":
            path = propagation.path[0] if propagation.path else "unknown-chain"
            return f"Injected instruction propagated: {path}"
        if threat_type == "INDIRECT":
            return f"Tool output from {self._tool_name(event)} contains injection payload"
        if threat_type == "BEHAVIOUR_SHIFT":
            return f"Agent {source} behaviour changed abruptly (cosine dist > 0.7)"
        return f"Suspicious activity detected for agent {source} targeting {target}."

    async def analyse(self, event: dict[str, Any]) -> ThreatVerdict:
        source = self._event_source(event)
        target = self._event_target(event)
        message = str(event.get("message", ""))

        self._event_history[source].append(event)

        preprocessed = preprocess_event(event)
        base_score = 15 if preprocessed.suspicious_encoding else 0

        injection_result, semantic_result, behavioural_result, toolchain_result, exfiltration_result, hidden_result = await asyncio.gather(
            self._run_injection(preprocessed),
            self._run_semantic(preprocessed),
            self._run_behavioural(source, event),
            self._run_toolchain(source, event),
            self._run_exfiltration(source, preprocessed),
            self._run_hidden(source, event, preprocessed),
        )

        detector_scores = {
            "injection": float(injection_result.score),
            "semantic": float(semantic_result.final_score),
            "behavioural": float(behavioural_result.score),
            "toolchain": float(toolchain_result.score),
            "exfiltration": float(exfiltration_result.get("score", 0)),
            "hidden": float(hidden_result.get("score", 0)),
        }

        composite = sum(detector_scores[k] * WEIGHTS[k] for k in WEIGHTS) + base_score

        triggered_detectors = [name for name, score in detector_scores.items() if score > 0]
        if len(triggered_detectors) >= 3:
            composite += 20

        source_taint = self.taint_tracker.get_taint(source)
        if source_taint > 0.3:
            composite = min(100.0, composite * (1 + source_taint * 0.5))

        propagation = await self.taint_tracker.propagate(source, target, message)

        composite = min(100.0, max(0.0, composite))
        severity = self._severity(composite)

        primary = self._primary_threat_type(
            injection_result,
            exfiltration_result,
            hidden_result,
            behavioural_result,
            toolchain_result,
            propagation,
        )

        alert_description = self._alert_description(
            primary,
            event,
            injection_result,
            exfiltration_result,
            propagation,
            hidden_result,
        )

        chain_subject = target if target and target != "unknown-target" else source
        taint_chain = self.taint_tracker.get_taint_chain(chain_subject)

        confidence = min(
            1.0,
            (composite / 100.0) * (0.6 + min(0.35, len(triggered_detectors) * 0.08)),
        )

        verdict = ThreatVerdict(
            composite_score=round(composite, 2),
            severity=severity,
            triggered_detectors=triggered_detectors,
            primary_threat_type=primary,
            taint_chain=taint_chain,
            alert_description=alert_description,
            trust_delta=round(-(composite * 0.6), 2),
            recommended_action=self._recommended_action(severity),
            confidence=round(confidence, 4),
            evidence={
                "base_score": base_score,
                "detector_scores": detector_scores,
                "preprocessed": {
                    "suspicious_encoding": preprocessed.suspicious_encoding,
                    "encoding_layers_found": preprocessed.encoding_layers_found,
                    "encoding_depth": preprocessed.encoding_depth,
                },
                "injection": {
                    "score": injection_result.score,
                    "severity": injection_result.severity,
                    "matched_tiers": injection_result.matched_tiers,
                    "bonus_applied": injection_result.bonus_applied,
                },
                "semantic": {
                    "label": semantic_result.label,
                    "malicious_prob": semantic_result.malicious_prob,
                    "flagged": semantic_result.flagged,
                    "final_score": semantic_result.final_score,
                },
                "behavioural": {
                    "score": behavioural_result.score,
                    "triggered_rules": behavioural_result.triggered_rules,
                    "behaviour_shift": behavioural_result.behaviour_shift,
                },
                "toolchain": {
                    "score": toolchain_result.score,
                    "reasons": toolchain_result.reasons,
                    "scope_creep": toolchain_result.scope_creep,
                },
                "exfiltration": {
                    "score": exfiltration_result.get("score", 0),
                    "pii_types": getattr(exfiltration_result.get("pii"), "found_types", []),
                    "staging": exfiltration_result.get("data_staging_detected", False),
                },
                "hidden": {
                    "score": hidden_result.get("score", 0),
                    "tool_output_score": hidden_result.get("tool_output_score", 0),
                    "json_score": hidden_result.get("json_score", 0),
                    "covert_score": hidden_result.get("covert_score", 0),
                },
                "taint": {
                    "source_taint_before_modifier": source_taint,
                    "propagation": {
                        "propagated_taint": propagation.propagated_taint,
                        "path": propagation.path,
                        "injection_signal_detected": propagation.injection_signal_detected,
                    },
                },
            },
        )

        self._verdict_history.append(
            {
                "timestamp": self._now(),
                "source": source,
                "severity": severity,
                "primary": primary,
                "score": verdict.composite_score,
            }
        )

        return verdict

    def get_system_threat_summary(self) -> dict[str, Any]:
        now = self._now()
        cutoff = now - timedelta(hours=1)
        recent = [v for v in self._verdict_history if v["timestamp"] >= cutoff]

        total_alerts = len([v for v in recent if v["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}])

        by_agent: dict[str, list[float]] = defaultdict(list)
        for entry in recent:
            by_agent[entry["source"]].append(float(entry["score"]))
        most_suspicious_agent = None
        if by_agent:
            most_suspicious_agent = max(by_agent.items(), key=lambda item: sum(item[1]) / len(item[1]))[0]

        taint_map = self.taint_tracker.get_taint_map()
        active_taint_chains = [
            {"agent_id": agent_id, "chain": info.get("chain", []), "taint_level": info.get("taint_level", 0)}
            for agent_id, info in taint_map.items()
            if float(info.get("taint_level", 0)) > 0.1
        ]

        vectors = Counter(entry["primary"] for entry in recent)
        top_vectors = [{"threat_type": key, "count": count} for key, count in vectors.most_common(5)]

        avg_score = sum(float(v["score"]) for v in recent) / len(recent) if recent else 0.0
        system_level = self._severity(avg_score)

        return {
            "total_alerts_last_hour": total_alerts,
            "most_suspicious_agent": most_suspicious_agent,
            "active_taint_chains": active_taint_chains,
            "top_threat_vectors": top_vectors,
            "system_composite_threat_level": system_level,
        }
