# OpenLine Verified Memory

**Vector search finds nearby text. Verified Memory decides what prior work has earned inheritance.**

This repository now has two deliberately separate surfaces.

The original `verified_memory_map_demo.py` remains as the small June demonstration of relevance, warnings, and reusable lessons. Its sample JSONL is legacy/demo input: fields such as `status`, `survived`, and `witness` are not trusted evidence.

The hardened v0.2 path is `openline_verified_memory.evidence`. It does not accept those trust fields from an agent. It derives memory standing from verified receiver evidence.

## Earned states

For the Airlock profile:

- `candidate` — Airlock signed a generation with one uniquely selected winner, but exact installation has not been evidenced.
- `inherited` — a separately signed promotion-execution receipt binds that exact winner to the generation receipt and observes the improvement branch at the selected commit.
- `questioned` — a later signed standing record bound to that promotion says `REOPEN`.
- failures may remain retrievable as warnings, but failure preservation does not make them inherited.

A later `REOPEN` changes what the next generation may treat as established. It does **not** itself roll back the installed version. Installed-state recovery remains a separate receiver-owned action.

## Why the split matters

A valid old signature proves that an earlier event was signed. It does not make the lesson permanently entitled to `inherited` standing.

The v0.2 projector therefore reconstructs current memory status from the evidence chain each time:

```text
signed Airlock generation selection
        ↓
candidate
        ↓
signed exact promotion execution
        ↓
inherited
        ↓
signed standing REOPEN
        ↓
questioned
```

The caller cannot override `status`, `survived`, or `witness`. `survived` is counted from exact verified promotion execution, not copied from JSON.

## API

```python
from openline_verified_memory import derive_airlock_memory, established

memory = derive_airlock_memory(
    lesson_id="lesson-1",
    title="bounded retry",
    text="use bounded retry",
    generation_record=generation_receipt,
    promotion_record=promotion_receipt,
    standing_record=standing_receipt,   # optional
    key=receiver_pinned_key,
)

usable_next_generation = established([memory])
```

This first hardened adapter verifies Airlock's current HMAC-SHA256 signed-envelope shape. The key is a receiver-pinned local trust anchor. This is not a claim that HMAC receipts are public third-party attestations.

## What this does not prove

Verified Memory does not decide whether an evaluator was good, whether an Airlock objective captures total product value, or whether a claimed fact about the outside world is true.

It answers a narrower question:

> Given evidence from a receiver whose key is pinned here, what prior lesson is currently entitled to be presented as established inheritance?

Other systems can add their own evidence adapters without reintroducing caller-supplied trust fields.

## Legacy relevance demo

The original demo still runs:

```bash
python verified_memory_map_demo.py "agent retry loop with no error handling"
```

It is useful for the retrieval behavior: relevant quarantined failures can surface as warnings rather than disappear. Do not use its supplied `status`, `survived`, or `witness` fields as authority.

## Test

```bash
python -m unittest discover -s tests -v
```

The v0.2 tests cover:

- unique selection without installation stays `candidate`;
- exact bound installation earns `inherited`;
- a later `REOPEN` produces `questioned`;
- valid old signatures do not override newer standing;
- mismatched or unsigned promotion claims fail closed;
- tampered generation evidence fails closed.

## Next integration

`RSI-001` belongs in Airlock, not here. Airlock should run the generations with the worker generator frozen. This package supplies the one evidence-derived inheritance implementation. The later `RSI-002` experiment can add a separately pinned Generator Gate and test whether an accepted search-strategy change improves subsequent unseen-task performance under equal budget.

## License

MIT
