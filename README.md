# OpenLine Verified Memory

**Vector search finds nearby text. Verified Memory finds tested work.**

OpenLine Verified Memory is a tiny, dependency-free demo of receipt-shaped memory for AI agents.

The point is simple: a useful memory should not only remember what sounds relevant. It should remember what worked, what failed, who checked it, and what should stay quarantined.

## Scope

This repo is a small quickstart for the memory shape, not the full OpenLine trust layer.

It demonstrates how receipt-shaped records can help an agent surface a known trap before a tested fix. The current demo assumes the JSONL records are trusted input. It does not yet verify signatures, witness proofs, survival counts, or external provenance.

In production OpenLine, fields like `witness`, `survived`, and `status` should be earned by signed receipts, tests, audit trails, or other external checks. In this quickstart, they are kept simple so the memory behavior is easy to inspect.

## Why this exists

AI agents get stuck in loops when they keep reaching for a move that already failed.

A normal memory system might pull back old context because it looks relevant. But relevant is not the same as safe.

In this demo, the agent asks about a retry loop with no error handling. The first thing it sees is the known trap. Then it sees the tested fix.

A failure is not neutral. A failure is a warning that earned its place.

## Run the demo

```bash
python verified_memory_map_demo.py "agent retry loop with no error handling"
```

Expected shape:

```text
1. quarantined — Infinite while-loop agent wrapper with no error handling
2. inherited — Add bounded retries and explicit failure receipts
```

The known failure appears first because it is relevant to the query and should be treated as a warning, not forgotten.

The tested fix appears second because it is reusable work.

## What the demo shows

Each memory record is a small receipt-shaped object with a lesson, status, survival count, witness, and reuse rule.

The ranker uses simple token overlap, negation awareness, survival score, witness quality, status, and quarantine behavior to show the memory pattern.

This is not meant to replace vector search. It shows what should sit above it.

Vector search can be the index.

Verified Memory is the record of tested work.

## Example output

```text
Query: agent retry loop with no error handling

1. quarantined — Infinite while-loop agent wrapper with no error handling
   score=1.027 | semantic=0.286 | survived=0 | witness=runtime monitor | reuse=warning only
   A prompt wrapped in an unbounded loop kept retrying after tool failure and produced duplicate actions with no error handling or useful failure record.

2. inherited — Add bounded retries and explicit failure receipts
   score=0.679 | semantic=0.185 | survived=18 | witness=pytest | reuse=safe for agent reliability work
   An agent wrapper with max retries, timeout handling, and a signed failure receipt prevented runaway loops in a coding workflow.
```

Scores may change as the ranker is hardened. The important behavior is the ordering: known trap first, tested fix second.

## Test it

```bash
python -m unittest discover -s tests -v
```

## Known limitations

This is a dependency-free demo, so the trust and language handling are intentionally minimal.

Unsigned JSONL records can currently claim high-trust fields such as `witness` or `survived`. A hardened version should verify those fields before giving them scoring weight.

The tokenizer handles simple negation such as “no error handling,” but it does not fully understand compound negation or sentence meaning. A hardened version should add negation-depth tests or use a stronger parser.

## v0.2 hardening targets

The next version should verify trust fields before scoring them. A record should not get high witness or survival weight just because a JSONL line says so.

The next version should also improve negation handling. Single negation is useful for the demo, but compound negation needs explicit tests before the ranker can claim stronger language understanding.

## How this fits OpenLine

OpenLine is a portable receipt layer for AI work.

This repo shows one small behavior OpenLine enables: future agents can learn from records of what actually happened instead of rediscovering the same failure.

The full trust layer belongs in the broader OpenLine stack: signed receipts, witnesses, verification, wallet-held records, and coherence checks.

This quickstart is the doorway.

## License

MIT
