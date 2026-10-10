# Changelog

## Improved training build

- Removed fabricated random dashboard telemetry and made dashboard metrics derive from the active simulated shift.
- Replaced empty threat-feed states with clear training-oriented messages and populated feeds from released alerts.
- Renamed the trend chart to reflect alerts released in the current shift.
- Marked unfinished sidebar workspaces as Coming Soon instead of presenting them as implemented features.
- Added a persistent Beginner Hints preference and an investigation checklist that does not expose model answers.
- Associated investigation activity with the active alert and correlated pre-detail searches by alert identifiers, so one unrelated search does not count as investigation for every alert.
- Preserved evidence activity for alerts left open at shift end.
- Hardened scenario validation for unique IDs, valid release minutes, severity values, and required truth fields.
- Added next-practice recommendations and JSON report export.
- Added automatic local checkpoints, a Save shift control, and resume/discard flow after reload.
- Persisted analyst decisions, investigation activity, response actions, and simulated effect records in shift checkpoints.
- Added a simulated environment-state ledger to Context and explanatory effects on recorded response actions.
- Added checkpoint restore tests and clarified the client-side storage/security limitations in the README.
- Added Node.js tests and a GitHub Actions workflow for tests and JavaScript syntax checks.
- Rewrote README and included supplied screenshots.

## V6 — rule-based log-to-response assessment

- Added a pure response assessment module that correlates supported simulated controls with log fields and timestamps.
- Distinguishes matching activity observed after a simulated control, events that predate the control, and events with no supported match.
- Added a log-to-response summary to shift-end reports and included per-log assessments in exported JSON.
- Uses action-specific matching for host isolation, account controls, IP/domain/hash blocks, and selected email actions; unsupported action types do not claim log impact.
- Added regression tests for temporal ordering, action/target matching, normalization of defanged domains, unsupported controls, and summary counts.

### Scope note

The assessment is rule-based correlation over the scenario's existing logs. It does not remove or synthesize telemetry, prove prevention, or model the full causal evolution of an incident.

## Scope notes

This remains a client-side educational simulator. Scores and scenario truth are not tamper-resistant and must not be used as a standalone hiring or certification decision. PDF export, fully implemented sidebar workspaces, and browser end-to-end tests remain future work. The response-state ledger is explanatory state, not a full causal simulation of how containment changes later telemetry.

## V3 — simulated response consequences

- Unified response-action effect recording across the Toolkit and inline Alert Response panel.
- Added a shared simulated-action handler that records typed environment states and an audit activity entry associated with the active alert.
- Annotated matching log rows that occur after a response action with relevant simulated consequences, so learners can see how their actions relate to later evidence without pretending to affect real systems.
- Added tests for effect recording, alert attribution, matching later evidence, and unrelated log rows.

### Scope note

This is a deterministic, explanatory consequence layer, not a full causal attack/defense simulator. It annotates matching log evidence and records state; it does not rewrite scenario truth or synthesize new telemetry.


## V4 — response impact in shift reports

- Added a simulated response-impact section to the end-of-shift report so trainees can review the state changes their actions recorded.
- Included simulated effects and response-action audit entries in exported JSON reports.
- Added visual distinction for explanatory impact notes attached to matching log rows.
- Reiterated in the report that response actions are simulated and never contact real infrastructure.


## V5 — response timing and alert correlation

- Correlate expected response actions with the most recent matching released alert when indicators or accounts recur across a scenario.
- Assess response timing against the related alert's SLA and flag late or premature actions in findings.
- Apply modest response-score deductions for late or premature expected actions while retaining coverage, harmful-action, and unnecessary-action scoring.
- Show response timing, related alert IDs, and SLA context in the shift report and include timing assessment in JSON exports.
- Added regression tests for late and premature response actions.

### Scope note

This is a heuristic training assessment, not a full causal simulation. When the same entity appears in multiple alerts, correlation chooses the most recent matching alert at or before action time; review the report in context.


## V7 (in progress)

- Added evidence-gated incident lifecycle model with guarded status transitions.
- Added response-action verification and residual-risk gates for containment/resolution.
- Added per-incident evidence, audit history, analyst notes, summary metrics, and checkpoint persistence.
- Added automated lifecycle tests. Existing UI and prior workflows are retained; lifecycle APIs are available for future UI integration.
