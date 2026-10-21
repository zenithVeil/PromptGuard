# PromptGuard benchmark results

- **Mode:** rules
- **Date:** 2026-10-21T15:46:16.216953+00:00
- **Database:** C:\Users\ASWATH~1.S\AppData\Local\Temp\promptguard_bench_jyyv72cp\promptguard.db (temporary, not promptguard.db)
- **LLM calls:** 0 / 150
- **Skipped (budget):** 0
- **Failed:** 0

## Attack block rate

| Category | Blocked | Total | Rate |
|---|---|---|---|
| Overall | 36 | 40 | 90.0% |
| data_exfiltration | 5 | 5 | 100.0% |
| direct | 6 | 6 | 100.0% |
| encoded | 6 | 6 | 100.0% |
| indirect | 5 | 5 | 100.0% |
| multilingual | 2 | 6 | 33.3% |
| paraphrased | 6 | 6 | 100.0% |
| roleplay_jailbreak | 6 | 6 | 100.0% |

## Benign false positives

| Flagged | Total | Rate |
|---|---|---|
| 3 | 40 | 7.5% |

## Tool-call accuracy

| Correct | Total | Rate |
|---|---|---|
| 16 | 16 | 100.0% |

## Latency (ms)

| Median | p95 |
|---|---|
| 7.7 | 16.0 |
