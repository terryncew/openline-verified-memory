#!/usr/bin/env python3
"""
OpenLine Verified Memory demo.

A tiny dependency-free ranker for receipt-backed agent memory.

Run:
    python verified_memory_map_demo.py "agent retry loop with no error handling"
"""

from __future__ import annotations

import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


NEGATION_WORDS = {"no", "not", "never", "without", "none", "nothing"}
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "from",
    "in", "into", "is", "it", "of", "on", "or", "so", "that", "the", "then",
    "this", "to", "was", "were", "with"
}

WITNESS_QUALITY = {
    "none": 0.00,
    "self": 0.05,
    "human review": 0.12,
    "checkpoint receipt": 0.18,
    "runtime monitor": 0.22,
    "unit test": 0.26,
    "pytest": 0.30,
    "github actions": 0.34,
}


@dataclass(frozen=True)
class MemoryReceipt:
    rid: str
    title: str
    text: str
    status: str
    survived: int
    witness: str
    reuse: str
    tags: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict) -> "MemoryReceipt":
        required = {"rid", "title", "text", "status", "survived", "witness", "reuse", "tags"}
        missing = required - set(data)
        if missing:
            raise ValueError(f"missing required fields: {sorted(missing)}")

        return cls(
            rid=str(data["rid"]),
            title=str(data["title"]),
            text=str(data["text"]),
            status=str(data["status"]),
            survived=int(data["survived"]),
            witness=str(data["witness"]),
            reuse=str(data["reuse"]),
            tags=tuple(str(tag) for tag in data["tags"]),
        )


def raw_tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def tokenize(text: str) -> set[str]:
    """
    Tokenize text while preserving local negation.

    Example:
        "no error handling" produces:
        {"no", "error", "handling", "NEG_error", "NEG_handling"}

    That keeps "with error handling" from being treated as identical to
    "no error handling."
    """
    words = raw_tokens(text)
    tokens: set[str] = set()

    for i, word in enumerate(words):
        if word not in STOPWORDS or word in NEGATION_WORDS:
            tokens.add(word)

        if word in NEGATION_WORDS:
            for next_word in words[i + 1 : i + 4]:
                if next_word not in STOPWORDS:
                    tokens.add(f"NEG_{next_word}")

    return tokens


def load_receipts(path: Path) -> list[MemoryReceipt]:
    receipts: list[MemoryReceipt] = []

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            try:
                data = json.loads(stripped)
                receipts.append(MemoryReceipt.from_dict(data))
            except Exception as exc:
                raise ValueError(f"{path}:{line_no}: invalid receipt JSONL: {exc}") from exc

    return receipts


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def survival_score(survived: int) -> float:
    return min(math.log1p(max(survived, 0)) / math.log1p(30), 1.0)


def status_adjustment(receipt: MemoryReceipt, semantic: float) -> float:
    if receipt.status == "inherited":
        return 0.12
    if receipt.status == "candidate":
        return 0.02
    if receipt.status == "questioned":
        return -0.02
    if receipt.status == "quarantined":
        # Relevant quarantined memories are useful as warnings.
        # Irrelevant quarantined memories should not dominate.
        return 0.36 if semantic >= 0.18 else -0.30
    return 0.0


def score_receipt(query_tokens: set[str], receipt: MemoryReceipt) -> tuple[float, float]:
    receipt_text = " ".join([receipt.title, receipt.text, receipt.reuse, *receipt.tags])
    memory_tokens = tokenize(receipt_text)

    semantic = jaccard(query_tokens, memory_tokens)

    # Relevance gate: unrelated high-survival memories should not dominate.
    if semantic == 0:
        survival_weight = 0.03
        witness_weight = 0.04
    elif semantic < 0.10:
        survival_weight = 0.08
        witness_weight = 0.08
    else:
        survival_weight = 0.24
        witness_weight = 0.16

    witness = WITNESS_QUALITY.get(receipt.witness.lower(), 0.08)

    score = (
        1.65 * semantic
        + survival_weight * survival_score(receipt.survived)
        + witness_weight * witness
        + status_adjustment(receipt, semantic)
    )

    # Boost directly relevant negation matches.
    negation_overlap = len({t for t in query_tokens if t.startswith("NEG_")} & memory_tokens)
    score += 0.08 * negation_overlap

    return round(score, 3), round(semantic, 3)


def rank(query: str, receipts: Iterable[MemoryReceipt]) -> list[tuple[float, float, MemoryReceipt]]:
    query_tokens = tokenize(query)
    ranked: list[tuple[float, float, MemoryReceipt]] = []

    for receipt in receipts:
        score, semantic = score_receipt(query_tokens, receipt)
        ranked.append((score, semantic, receipt))

    return sorted(
        ranked,
        key=lambda item: (
            item[0],
            item[2].status == "quarantined",
            item[2].survived,
        ),
        reverse=True,
    )


def format_results(query: str, ranked: list[tuple[float, float, MemoryReceipt]], limit: int = 5) -> str:
    lines = [f"Query: {query}", ""]

    for i, (score, semantic, receipt) in enumerate(ranked[:limit], start=1):
        lines.append(f"{i}. {receipt.status} — {receipt.title}")
        lines.append(
            f"   score={score:.3f} | semantic={semantic:.3f} | survived={receipt.survived} | "
            f"witness={receipt.witness} | reuse={receipt.reuse}"
        )
        lines.append(f"   {receipt.text}")
        lines.append("")

    return "\n".join(lines).rstrip()


def main(argv: list[str]) -> int:
    query = " ".join(argv).strip() or "agent retry loop with no error handling"
    path = Path(__file__).parent / "examples" / "sample_receipts.jsonl"

    receipts = load_receipts(path)
    ranked = rank(query, receipts)
    print(format_results(query, ranked))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
