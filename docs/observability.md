# Observability

What the system tells you about itself, and the one identifier that makes the
rest of it usable.

## The request id

Every response carries `X-Request-ID`. Send one and it comes back; send
nothing and one is generated. It appears in the response header, in the body
of an error, in every log line for that request, and in any audit row the
request wrote.

That is the whole observability story in one sentence: it is the thread
between a user's screenshot, an access log line, an application log line and
an audit row. Without it, "it failed this afternoon" is unanswerable.

Forward it from your reverse proxy:

```nginx
proxy_set_header X-Request-ID $request_id;
```

Inbound values are **validated against a character set rather than reflected**.
The id reaches log lines, audit rows and report filenames, so an unvalidated
one is a log-injection parameter. A rejected value is replaced rather than
dropped.

## Health

| Endpoint | Answers |
|---|---|
| `/health` | Is the process up? |
| `/api/v1/health/live` | The same, under the API prefix |
| `/api/v1/health/ready` | Is it up **and** are its dependencies? |
| `/api/v1/health` | Which dependency, and what did each check say? |

Use `ready` as the readiness probe, and **read the body rather than the status
code**. It answers 200 with `ready: false` while a dependency check is
failing, because a process that is listening is not a backend that can serve a
request — and that distinction is exactly what a readiness probe is for.

`/api/v1/health` lists the checks individually, which is where to look before
guessing. It also reports `data_classification: synthetic` and
`production_ready: false`, and `scripts/smoke_test.sh` asserts both. If that
assertion ever fails, something has been configured to look like a production
system.

Health payloads deliberately contain no configuration values, no connection
strings and no versions of anything but the application itself.

## Logging

Structured. `BACKEND_LOG_FORMAT=json` for anything that ships logs,
`console` for a terminal.

Each line carries the request id, the method and path, the status, the
duration, the actor when authenticated, and the action for a workflow
mutation.

### What is deliberately not logged

| Not logged | Why |
|---|---|
| Request bodies (`BACKEND_LOG_REQUEST_BODY=false`) | A body here can contain a complaint narrative |
| Response bodies | A response can contain a page of them |
| Complaint narratives | Truncated to `BACKEND_MAX_NARRATIVE_LOG_CHARS` if one somehow reaches a line |
| Raw client addresses | Hashed (`PRIVACY_IP_LOG_MODE=hashed`) |
| Raw identifiers | Phone numbers and device ids exist as hashes |
| Secrets, tokens, database URLs | Redacted by the log filter |
| Tracebacks in responses | They go to the log; the response carries a code and the request id |

Leave the body-logging settings false. They exist for a local debugging
session and nothing else.

`BACKEND_LOG_SQL=false` likewise: statement logging at this verbosity is
mostly parameter values, and the parameter values are the data.

### Levels

`INFO` is the right default. `DEBUG` is noisy rather than dangerous;
`BACKEND_LOG_SQL` is the one to be careful with.

## Metrics

`PROMETHEUS_ENABLED=true` exposes `/metrics`. **Do not expose it publicly** —
route labels are a complete map of the API surface.

Request count, duration and status by route, plus the in-process performance
middleware's own counters. `PERFORMANCE_SLOW_REQUEST_THRESHOLD_MS` (2000 by
default) decides what gets logged as slow.

### What to watch

**Analysis run duration.** The run is synchronous and holds a worker for its
duration. This is the metric that will tell you first that the architecture
needs a background worker (ADR 0001 says what the next move would be).

**Readiness check failures.** A flapping database check usually means pool
exhaustion rather than a database problem.

**401 rate on `/auth/login`.** A rise is either a credential-stuffing attempt
or an expiry somebody should have been told about.

**403 rate.** A steady trickle is the permission matrix doing its job — an
analyst trying to close a case. A sudden rise means somebody's role changed,
or an endpoint's permission did.

**429 rate.** Remember the limiter is in-process: with four workers the
effective limit is roughly four times the configured one, and nothing is
shared across instances.

### What is not instrumented

- No tracing spans. `OTEL_ENABLED` exists and the integration is not wired up.
- No per-stage detection metrics in Prometheus. Stage timings are recorded on
  the `analysis_runs` row instead, which is queryable but not scrapeable.
- No business metrics as gauges. Open alerts, cases by status and correlation
  review backlog come from `/api/v1/dashboard/metrics`, not from `/metrics`.

That last split is deliberate. Those numbers are investigative state rather
than system state, they need authentication and a role, and an unauthenticated
scrape endpoint reporting "137 open alerts" is a disclosure rather than a
metric.

## The audit trail is not telemetry

Worth stating because they look similar.

Logs are operational and disposable. The audit trail is a record of human
decisions, it is append-only, it is queryable through
`GET /api/v1/audit` under `AUDITOR` or `ADMIN`, and refused actions are
recorded as well as permitted ones.

They share the request id, which is what lets you move between them.

The audit trail is append-only **by convention** — no code deletes — and not
by database enforcement. If it needs to be evidence rather than a record, that
is the gap to close first.

## Investigating a failure

### A user reports an error

Get the request id from the error body. They are looking at it: it is in the
response, which is why it is in the response.

```bash
grep '<request-id>' /var/log/muleguard/backend.log
```

One request id gives you the route, the actor, the status, the duration and
the traceback.

### A request is slow

Slow requests are logged with their duration above the threshold. The
candidates, in order of likelihood:

1. An analysis run. Synchronous, and bounded by `ANALYSIS_MAX_ACCOUNTS`.
2. A graph traversal near its limits. Check whether the response was
   truncated — a traversal that hit its budget took the whole budget.
3. A report generation. Bounded by `REPORT_MAX_GENERATION_SECONDS`.
4. An unindexed query on a large table. `DB_ECHO=true` locally, never in a
   deployment.

### Nothing is being scored

Read the analysis run's response rather than the database. It reports
`account_count`, `assessment_count` and per-stage timings, and a run over zero
accounts is a filter problem rather than a scoring problem.

If accounts were scored and no alerts raised, that may well be correct: an
alert needs a score at or above the threshold or a rule effect that always
escalates.

### A score is null

Not a failure. An unavailable signal is reported as unavailable because a zero
would assert that the account scored well on something nothing looked at.

Check `scoring_mode` (`HEURISTIC_FALLBACK` means no trained model), the
`components_json` availability flags, and whether a rule pack registered —
`no_rules_available` is reported rather than scoring every account zero.

## Dashboards worth building

If you are putting this behind Grafana:

**One request-id search box.** Everything else is secondary.

**Analysis run duration over time**, with the account count alongside. The two
together tell you whether a slowdown is load or regression.

**The three queue depths** from `/api/v1/dashboard/metrics`: unassigned
alerts, cases in TRIAGED, unreviewed correlations. These are the ones that grow
silently when nobody is working them, and none of them is a system problem —
which is why they are worth a dashboard rather than an alert.
