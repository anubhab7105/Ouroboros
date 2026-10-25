# MULEGUARD runtime configuration

Tunable detection policy, kept out of the Python source so it can be reviewed,
diffed, and changed without a code deployment.

## Files

| File | Purpose | Loaded by |
|---|---|---|
| `rules.default.json` | The detection rule pack: typologies, conditions, severities, and analyst-facing reason text. | `app.services.analysis` via `app.rules.definitions.import_rule_pack` |
| `scoring.default.json` | Risk-fusion component weights, band cut-points, and alerting thresholds. | `app.services.risk` |
| `windows.default.json` | Analysis window definitions and dashboard trend granularity. | `app.services.features`, `app.services.dashboard` |
| `alert_deduplication.default.json` | When a run raises a new alert versus updating an open one. | `app.services.alerts` |

`*.default.json` files are the version-controlled defaults. To override one
without editing it, copy it alongside without the `.default` segment
(`rules.json`, `scoring.json`, ...) — the loader prefers the override and falls
back to the default. Overrides are gitignored.

## How the pieces fit together

```
features  ->  rules engine  ->  risk fusion  ->  alerting
  |              |                  |               |
windows.json  rules.json      scoring.json   alert_deduplication.json
```

1. **windows.json** defines the time windows features are computed over.
2. **rules.json** evaluates those features into triggered typologies, each with
   a severity.
3. **scoring.json** fuses the rule score with model, anomaly, graph, and
   complaint components into the 0–100 investigative priority score and maps it
   to a band.
4. **alert_deduplication.json** decides whether that band change becomes a new
   queue entry.

## Scoring maths you need to know before tuning

Rule contributions combine by **noisy-OR**, not by addition:

```
contribution_i = clip((severity_weight + score_delta) * matched_leaf_ratio * (1 + priority/200), 0, 1)
rule_score     = 1 - product(1 - contribution_i)
```

Severity weights are fixed in `app/rules/engine.py`:

| severity | weight |
|---|---|
| `info` | 0.05 |
| `low` | 0.15 |
| `medium` | 0.35 |
| `high` | 0.60 |
| `critical` | 0.85 |

Consequences worth internalising:

- Noisy-OR saturates. Two `critical` rules give 0.98; adding a third barely
  moves it. Corroboration is rewarded, pile-on is not.
- One `critical` rule gives 0.85, which is the **high** band — deliberately not
  `critical`. Topping out the scale should require independent evidence.
- Three `medium` rules give ~0.73. Weak signals that agree still surface an
  account, which is the behaviour thresholds alone cannot give you.
- Because contributions multiply, **adding rules can only raise a score**. If
  you need something to lower priority, write an `annotation` rule that informs
  the analyst (see `mg_established_merchant_context`) rather than expecting it
  to subtract.

## Editing `rules.default.json`

A rule is:

```json
{
  "rule_id": "mg_example",
  "name": "Short analyst-facing name",
  "description": "Why this behaviour is suspicious, in plain language.",
  "kind": "detection",
  "severity": "high",
  "status": "active",
  "priority": 12,
  "enabled": true,
  "condition_logic": "all",
  "conditions": [
    {"field": "txn_count_24h", "operator": "gte", "value": 6, "description": "..."}
  ],
  "action": {
    "effect": "flag_for_review",
    "reason_code": "EXAMPLE",
    "reason_message": "Text an analyst reads in the alert."
  },
  "metadata": {"typology": "example", "evidence": ["transactions"]}
}
```

Rules:

- `status` must be `active`. A `draft` rule is skipped unless the engine is run
  with `include_drafts`, which only the dry-run endpoint does.
- `field` must be a name in the feature catalog
  (`app/ml/feature_schema.py`). A typo silently never matches, so validate
  after editing (below).
- `operator` is one of `eq ne gt gte lt lte in not_in between contains
  starts_with ends_with is_true is_false missing any_of`.
- `condition_logic` is `all`, `any`, `none`, or `not`. With `all`, every
  condition must hold and `matched_leaf_ratio` is 1.0.
- `effect` is `prioritize`, `flag_for_review`, `escalate_to_human`, `annotate`,
  `suppress`, or `none`. `escalate_to_human` always raises an alert regardless
  of the fused score.
- `metadata.typology` groups rules for alert deduplication. Two rules sharing a
  typology will not raise two alerts for the same account and window.
- Every rule needs a `reason_message` written for a human. An indicator an
  analyst cannot interpret is worse than no indicator.

### Validate after editing

```bash
python scripts/check_schemas.py --config
```

This parses each file, checks every rule `field` against the feature catalog,
rejects unknown operators and effects, and reports rules that can never fire.

## Prohibited configuration

The loader rejects configuration that would make MULEGUARD act on its own
output. Specifically, you cannot configure:

- an automatic account freeze, block, or closure as a rule effect;
- adverse action without a recorded human disposition;
- suppression of an `escalate_to_human` alert;
- a ground-truth label, scenario ID, or fraud-ring ID as a rule `field` — these
  are isolated in `ground_truth_labels` and must never reach a predictor.

The last one matters: a rule reading the synthetic label would score perfectly
in evaluation and detect nothing real.

## Changing thresholds responsibly

Threshold changes alter which accounts an analyst sees, so they are a product
decision with a cost on both sides:

- Lowering a threshold raises recall and the triage load. Check the effect on
  alert volume on the demo dataset before committing.
- Raising it reduces noise and risks missing the typology the threshold
  encodes.

The values shipped here were chosen against the synthetic demo dataset. They
are **not** calibrated against real-world base rates and must be re-tuned
against labelled outcomes before any production use.
