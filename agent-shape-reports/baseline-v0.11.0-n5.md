# agent-shape report: kit

run_timestamp: `unix:1777210547`
judge_model: `claude-haiku-4-5`

## Tuning battery

- n_trials: 50
- mean_score: 0.430
- completion_rate: 94.0%
- mean_tokens: 1505
- mean_turns: 7.30
- total_invented_commands: 2
- total_fallback_to_sql: 3

## Holdout battery

_empty in v1 (schema supports it; corpus deferred)_

## Per-cell breakdown

| section | task | model | n | score | stddev | tokens | turns | invented | fallback | irr_delta |
|---------|------|-------|---|-------|--------|--------|-------|----------|----------|-----------|
| tuning | estate-overview-01 | claude-opus-4-7 | 5 | 1.000 | 0.000 | 823 | 3.20 | — | 0 | 0.000 |
| tuning | estate-overview-01 | claude-sonnet-4-6 | 5 | 0.800 | 0.274 | 1169 | 5.60 | kit skill list | 0 | 0.200 |
| tuning | pin-version-01 | claude-opus-4-7 | 5 | 0.200 | 0.112 | 934 | 4.80 | — | 0 | 0.050 |
| tuning | pin-version-01 | claude-sonnet-4-6 | 5 | 0.250 | 0.000 | 702 | 5.00 | — | 0 | 0.000 |
| tuning | registry-precedence-01 | claude-opus-4-7 | 5 | 0.200 | 0.112 | 1819 | 9.00 | — | 2 | 0.000 |
| tuning | registry-precedence-01 | claude-sonnet-4-6 | 5 | 0.250 | 0.000 | 1628 | 11.20 | — | 1 | 0.000 |
| tuning | registry-validation-01 | claude-opus-4-7 | 5 | 0.850 | 0.335 | 2314 | 11.40 | — | 0 | 0.000 |
| tuning | registry-validation-01 | claude-sonnet-4-6 | 5 | 0.250 | 0.000 | 4262 | 12.60 | — | 0 | 0.000 |
| tuning | release-pin-01 | claude-opus-4-7 | 5 | 0.250 | 0.000 | 853 | 5.20 | — | 0 | 0.050 |
| tuning | release-pin-01 | claude-sonnet-4-6 | 5 | 0.250 | 0.000 | 544 | 5.00 | — | 0 | 0.000 |

