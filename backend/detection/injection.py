import math
import re
from dataclasses import dataclass
from typing import Pattern


@dataclass
class InjectionMatch:
    tier: str
    base_weight: int
    applied_weight: int
    language: str
    pattern: str
    text_index: int
    excerpt: str


@dataclass
class InjectionResult:
    score: int
    severity: str
    matched_tiers: list[str]
    bonus_applied: int
    matches: list[InjectionMatch]


def _compile(patterns: list[str]) -> list[Pattern[str]]:
    return [re.compile(p, flags=re.IGNORECASE | re.MULTILINE) for p in patterns]


TIER_PATTERNS: dict[str, dict[str, object]] = {
    "T1_DIRECT_OVERRIDE": {
        "weight": 30,
        "patterns": _compile(
            [
                r"ignore (all )?(previous|prior|above|my) instructions",
                r"disregard (all )?(previous|prior|your) (instructions|rules|guidelines|training)",
                r"forget (everything|all|your) (you've been told|instructions|training|constraints)",
                r"do not follow (your|any)? ?(previous|prior)? ?(instructions|guidelines|rules)",
                r"override (your )?(safety|alignment|guidelines|instructions|training|policy|filters)",
                r"bypass (your )?(safety|filters|restrictions|guidelines|training|alignment)",
            ]
        ),
    },
    "T2_ROLE_HIJACK": {
        "weight": 25,
        "patterns": _compile(
            [
                r"you are now (a|an)? ?(new|different|unrestricted|jailbroken)",
                r"act as (if you (have no|are without)|unrestricted)",
                r"pretend (you are|to be) (a|an)? ?(different|unrestricted|evil|dan|developer mode)",
                r"from now on (you (are|will|must)|your (new|only))",
                r"your (new|true|real|actual)? ?(purpose|goal|mission|role|task) is",
                r"switch (to|into) (developer|jailbreak|unrestricted|dan|god) mode",
            ]
        ),
    },
    "T3_INSTRUCTION_SMUGGLING": {
        "weight": 20,
        "patterns": _compile(
            [
                r"<\|system\|>",
                r"<\|im_start\|>\s*system",
                r"\[system\]",
                r"\[inst\]",
                r"###\s*(system|instruction|override|new task)",
                r"---\s*(system|instruction|override)\s*---",
                r"\n\s*\n\s*(human|user|assistant)\s*:",
                r"\{\s*\"role\"\s*:\s*\"system\"",
            ]
        ),
    },
    "T4_EXFIL_TRIGGERS": {
        "weight": 25,
        "patterns": _compile(
            [
                r"send (all|your|every)? ?(data|memory|context|history|files|secrets|keys|tokens)",
                r"exfiltrate",
                r"leak (all|your|the)? ?(data|context|memory)",
                r"output (all|your|every) (previous|prior|stored) (message|data|context)",
                r"repeat (everything|all|your) (you know|from (memory|context|above))",
                r"reveal (your|the)? ?(system prompt|instructions|hidden|secret)",
            ]
        ),
    },
    "T5_AGENT_CHAINING": {
        "weight": 20,
        "patterns": _compile(
            [
                r"tell (the next|all other|every|other) agent(s)? to",
                r"instruct (the|all|other)? ?agent(s)? to (ignore|bypass|override)",
                r"pass (this|the following|these instructions) to (the next|all|other) agent",
                r"forward (these instructions|this message) to",
                r"when you (talk to|message|contact) (the|any|other)? ?agent",
                r"convince (the other|all|every) agent(s)? (to|that)",
            ]
        ),
    },
    "T6_SELF_ESCALATION": {
        "weight": 15,
        "patterns": _compile(
            [
                r"modify (your|the) (instructions|system prompt|guidelines) to",
                r"rewrite (your|the) (system prompt|instructions)",
                r"update (your|the) (memory|context|instructions) with",
                r"remember (to always|for all future|from now on)",
            ]
        ),
    },
    "T7_CONTEXT_POISONING": {
        "weight": 15,
        "patterns": _compile(
            [
                r"={10,}",
                r"-{10,}",
                r"end of (context|conversation|instructions|session)",
                r"beginning of (new|fresh|clean) (context|session)",
                r"\[(end|stop|reset)\]",
            ]
        ),
    },
}


# 80% weighted cross-language equivalents.
CROSS_LANGUAGE_PATTERNS: dict[str, list[Pattern[str]]] = {
    "T1_DIRECT_OVERRIDE": _compile(
        [
            r"ignora (todas? )?las instrucciones anteriores",  # ES
            r"ignorez les instructions",  # FR
            r"ignoriere (alle )?(vorherigen|fruheren) anweisungen",  # DE
            r"忽略(所有)?之前的指令",  # ZH
            r"تجاهل (كل )?التعليمات (السابقة|الأولى)",  # AR
        ]
    ),
    "T2_ROLE_HIJACK": _compile(
        [
            r"ahora eres (un|una)? ?(nuevo|diferente|sin restricciones)",  # ES
            r"vous etes maintenant",  # FR
            r"du bist jetzt",  # DE
            r"你现在是",  # ZH
            r"أنت الآن",  # AR
        ]
    ),
    "T3_INSTRUCTION_SMUGGLING": _compile(
        [
            r"\[sistema\]",  # ES
            r"\[systeme\]",  # FR
            r"\[system\]",  # DE
            r"\[系统\]",  # ZH
            r"\[نظام\]",  # AR
        ]
    ),
    "T4_EXFIL_TRIGGERS": _compile(
        [
            r"envia (todos|tus)? ?(datos|secretos|claves|tokens)",  # ES
            r"exfiltrer|fuite de donnees",  # FR
            r"exfiltrieren|daten leaken",  # DE
            r"泄露(数据|上下文|秘密)|导出(密钥|令牌)",  # ZH
            r"سرّب (البيانات|السياق|الأسرار)|اكشف (الموجه|التعليمات)",  # AR
        ]
    ),
    "T5_AGENT_CHAINING": _compile(
        [
            r"dile? al (siguiente|otro) agente",  # ES
            r"dis a l.?autre agent",  # FR
            r"sag dem (nachsten|anderen) agenten",  # DE
            r"告诉(下一个|其他)代理",  # ZH
            r"أخبر (الوكيل|العامل) (الآخر|التالي)",  # AR
        ]
    ),
    "T6_SELF_ESCALATION": _compile(
        [
            r"modifica (tus|las) instrucciones",  # ES
            r"modifie tes instructions",  # FR
            r"andere (deine|die) anweisungen",  # DE
            r"修改(你的|系统)指令",  # ZH
            r"عدّل (تعليماتك|الموجه)",  # AR
        ]
    ),
    "T7_CONTEXT_POISONING": _compile(
        [
            r"fin del (contexto|sesion)",  # ES
            r"fin du (contexte|session)",  # FR
            r"ende des (kontexts|sitzung)",  # DE
            r"(结束|终止)(上下文|会话)",  # ZH
            r"نهاية (السياق|الجلسة)",  # AR
        ]
    ),
}


MULTI_VECTOR_BONUS = 20
MULTI_VECTOR_TIER_THRESHOLD = 3
CROSS_LANGUAGE_WEIGHT = 0.8


def _severity(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "NONE"


def detect_injection(texts: list[str]) -> InjectionResult:
    matches: list[InjectionMatch] = []
    matched_tiers: set[str] = set()
    score = 0

    # De-duplicate by (tier, language, pattern-source-key) across text variants.
    seen_hits: set[tuple[str, str, str]] = set()

    for text_index, text in enumerate(texts):
        for tier, spec in TIER_PATTERNS.items():
            weight = int(spec["weight"])
            patterns = spec["patterns"]
            assert isinstance(patterns, list)

            for pattern in patterns:
                hit = pattern.search(text)
                if hit is None:
                    continue
                key = (tier, "en", pattern.pattern)
                if key in seen_hits:
                    continue
                seen_hits.add(key)

                matched_tiers.add(tier)
                score += weight
                matches.append(
                    InjectionMatch(
                        tier=tier,
                        base_weight=weight,
                        applied_weight=weight,
                        language="en",
                        pattern=pattern.pattern,
                        text_index=text_index,
                        excerpt=hit.group(0)[:200],
                    )
                )

            for pattern in CROSS_LANGUAGE_PATTERNS.get(tier, []):
                hit = pattern.search(text)
                if hit is None:
                    continue
                key = (tier, "cross-language", pattern.pattern)
                if key in seen_hits:
                    continue
                seen_hits.add(key)

                weighted = max(1, int(math.floor(weight * CROSS_LANGUAGE_WEIGHT)))
                matched_tiers.add(tier)
                score += weighted
                matches.append(
                    InjectionMatch(
                        tier=tier,
                        base_weight=weight,
                        applied_weight=weighted,
                        language="cross-language",
                        pattern=pattern.pattern,
                        text_index=text_index,
                        excerpt=hit.group(0)[:200],
                    )
                )

    bonus_applied = MULTI_VECTOR_BONUS if len(matched_tiers) >= MULTI_VECTOR_TIER_THRESHOLD else 0
    score += bonus_applied

    ordered_tiers = sorted(matched_tiers)
    return InjectionResult(
        score=score,
        severity=_severity(score),
        matched_tiers=ordered_tiers,
        bonus_applied=bonus_applied,
        matches=matches,
    )
