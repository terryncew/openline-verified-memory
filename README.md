# OpenLine Verified Memory

**Vector search finds nearby text. Verified Memory finds tested work.**

OpenLine Verified Memory is a tiny, dependency-free demo of receipt-backed memory for AI agents.

The point is simple:

A useful memory should not only remember what sounds relevant. It should remember what worked, what failed, who checked it, and what should stay quarantined.

## Why this exists

AI agents get stuck in loops for the same reason people do: they keep reaching for the move that already failed.

This quickstart shows a small memory map where a known trap surfaces first, then the tested repair appears underneath it.

A skill tells an agent what to try.

A receipt tells it what earned the right to be tried again.

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

Each memory record is a small receipt with:

- a claim or lesson
- the text of what happened
- status: `candidate`, `inherited`, `questioned`, or `quarantined`
- survival count
- witness
- reuse rule

The ranker uses:

- semantic token overlap
- negation awareness
- relevance gate
- survival score
- witness quality
- quarantine warning behavior

This is not meant to replace vector search. It shows what should sit above it.

Vector search can be the index.

Verified Memory is the record of tested work.

## Example output

```text
Query: agent retry loop with no error handling

1. quarantined — Infinite while-loop agent wrapper with no error handling
   score=1.370 | semantic=0.533 | survived=0 | witness=runtime monitor | reuse=warning only
   A prompt wrapped in an unbounded loop kept retrying after tool failure and produced duplicate actions with no error handling or useful failure record.

2. inherited — Add bounded retries and explicit failure receipts
   score=1.053 | semantic=0.224 | survived=18 | witness=pytest | reuse=safe for agent reliability work
   An agent wrapper with max retries, timeout handling, and a signed failure receipt prevented runaway loops in a coding workflow.
```

## Test it

```bash
python -m unittest discover -s tests -v
```

## How this fits OpenLine

OpenLine is a portable receipt layer for AI work.

Receipts can become:

- audit records
- reusable memory
- wallet-held user records
- exchangeable verified lessons
- training filters
- agent handoff objects

This repo is the small doorway: one demo showing how receipt-backed memory can surface a known trap before an agent repeats it.

## License

MIT
