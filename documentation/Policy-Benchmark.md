# Independent local Policy/Registry benchmark

This is a **deterministic controller benchmark, not proof of live LLM improvement**.
It executes real local file tasks and trains the actual tabular
`PWN::AI::Agent::Policy` implementation, then selects actions through the actual
`Registry.rank`. No model responses, provider usage, or benchmark gains are
simulated. The action handlers are explicitly hand-written local algorithms,
not a simulated language model.

## Run from a source checkout

```sh
ruby scripts/benchmark_policy.rb --self-check
ruby scripts/benchmark_policy.rb --output /tmp/pwn-policy-benchmark.json
bundle exec rubocop scripts/benchmark_policy.rb
```

The experiment uses Ruby and its standard libraries; it does not require the
full application boot sequence. Use a fresh Ruby process, not the live agent
console. JSON is printed to stdout and optionally written to `--output`.
`--self-check` runs independent scorer tests and both complete experimental arms;
it prints a short pass message instead of a report. Use the options separately.
The benchmark exits nonzero if persistence changes during evaluation, splits
overlap, a negative control succeeds, or a positive control fails. Self-checks
also require actual training updates in the on arm and none in the off arm.
They deliberately do **not** require an improvement of a predetermined size.

## Relation to existing evaluation

`lib/pwn/ai/agent/curriculum.rb` provides live self-play, judge-based practice,
mistake-derived evaluation prompts, and adapter training/promotion gates. This
standalone script does not invoke those paths. It provides a small, independently
scored experiment where the training labels come from actual task achievement,
not `Reward.judge`, model prose, or a previously assigned reward. It calls
`Policy.begin_episode`, `observe_step`, and `finish` with those labels during
training. This is not a test of Reward's verification-record binding, the live
Loop, Metrics learning, memory retrieval, or adapter training.

The new `scripts/` directory keeps this experimental driver outside the installed
CLI and production module tree; no module manifest or generated skill is needed.

## Protocol

1. **Isolation.** Create a private `/tmp/pwn-policy-benchmark-*` directory. Clear
   the process environment, set `HOME` and `TMPDIR` to that directory, then load
   only Policy and Registry. Assert their persistence constants resolve below
   the temporary `HOME/.pwn`. Do not load user configuration, credentials,
   registered application tools, providers, or network libraries. Delete the
   entire temporary directory on normal completion or Ruby exception and restore
   the process environment. A force-killed process may leave its temporary files.
   This is isolation for trusted fixed handlers, not a sandbox for untrusted code.
2. **Paired arms.** Run `off`, then `on`, resetting Policy between them. Both arms
   start empty and execute the identical training schedule. The only learning
   switch is `PWN::Env[:ai][:agent][:policy]`. No Q entries, visits, episode counts,
   or rewards are seeded directly. Other learning modules are not loaded.
3. **Training only.** There are four training fixtures: two numeric sorting tasks
   and two active-inventory filtering tasks. Six fixed exploration rounds execute
   every one of the three candidate actions for each fixture: 72 real handler
   calls per arm. Every action gets equal exposure; the scheduler does not use
   answer keys to choose actions. Each call writes into a fresh task directory.
   Exact artifact correctness supplies a binary training label to Policy; the
   off arm executes the same work but Policy declines to update.
4. **Held-out evaluation.** Only after training, materialize eight distinct
   held-out inputs with literal answer keys: four numeric and four inventory
   tasks. Assert no training input appears in evaluation. Task families and
   request wording are intentionally shared with training. The held-out units
   are **input instances, not unseen families, prompts, or tools**. This is
   in-distribution transfer within a small public fixture set, not a blind test
   or a generalization claim about arbitrary operator requests.
5. **Frozen controller.** Rank the task family's three entries using
   `Registry.rank(query: ..., entries: ..., preference: [])`. There are no
   evaluation `begin_episode`, `observe_step`, or `finish` calls. The policy uses
   Registry's normal fallback state rather than a fabricated state/table. Allow
   at most three attempts, stopping only when the independent artifact checker
   passes. The controller does not get corrective feedback or adapt between
   attempts. Hash all persisted `.pwn` files before evaluation and after controls;
   abort if they changed.
6. **Separate controls.** For each held-out input, force a claim-only handler and
   a handler that writes a wrong JSON object. Both return convincing
   `PASS: completed successfully...verified` prose and `ok: true`. All 16 forced
   negative controls must fail objective scoring. Also execute the correct
   algorithm on each input; all eight positive controls must pass. Controls are
   reported separately and never trained on or included in evaluation rates.

## Real task behavior and independent scoring

Numeric candidates perform lexical sorting, numeric sorting, or no artifact
write. Inventory candidates filter active rows, include every row, or write
nothing. Handlers receive only input/output paths; the literal expected values
are not passed to them. All handlers claim success, intentionally making textual
claims unreliable. The checker ignores their prose and action names. It accepts
only a regular non-symlink output whose parsed JSON exactly equals the answer key,
with the source input unchanged. Missing output, invalid JSON, a plausible wrong
artifact, or an altered input is failure. Self-checks separately test missing,
wrong, prose-only, symlink, and correct artifacts.

Each family has equal keyword-fit descriptions, with preference disabled. The
unlearned deterministic tie-break favors lexical sort in one family and the
correct active filter in the other; it is not configured to lose every task.
Lexical sorting can genuinely solve some numeric fixtures and receives credit
when it does. The learned controller can change these tied rankings from
observed outcomes. This construction deliberately isolates the learning-to-router
connection; it does not measure natural-language tool-selection quality.

The answer keys and algorithms live in the same public script but do not call
one another. Independence here means scoring actual artifact/task achievement
without trusting action claims or training rewards, not process-level secrecy or
an external audit. Extending the task set requires reviewing literal answer keys
and adding both positive and negative controls before interpreting new results.

## Report definitions

Each arm contains full training/evaluation traces, fixture inputs and answer keys,
control traces, Policy statistics, persistence fingerprints, and split/freeze
checks. Source hashes identify the Policy, Registry, and harness revisions used.
No fixed gains are embedded in the report.

- **Completion:** tasks with at least one objectively successful attempt divided
  by evaluated tasks. A failed attempt does not count as task completion.
- **False-success count/rate:** attempts claiming `ok: true` without achieving the
  task; rate denominator is executed attempts, not tasks. This is false reporting
  by the handler, not acceptance of that report by the independent checker.
- **Repeated mistakes:** every failed attempt after the first occurrence of the
  same `(family, action, checker failure)` signature within that phase and arm.
  This includes both repeated attempts on one task and recurrence on later
  held-out inputs. It is not the production Mistakes store's count.
- **Calls:** `tool_calls` counts actual local handler invocations. Evaluation makes
  one Registry ranking decision per attempted handler call. Training invokes
  begin/observe/finish once per training call; the returned update reports are
  preserved. Each separately listed control row is one additional handler call.
- **Elapsed:** monotonic measured seconds. Row elapsed time measures the handler;
  phase elapsed time also includes setup, ranking/checking, and training updates
  as applicable. Evaluation phase time excludes separately listed controls;
  top-level elapsed includes both arms and controls but not final JSON output or
  temporary-directory teardown. Tiny timings vary with caching and filesystem
  load; fixed arm order is not a timing-performance study.
- **Cost:** zero LLM calls and zero provider tokens because no provider is invoked.
  Monetary cost is `null` (not estimated), not a claim that local computing is
  economically free. No token-price or electricity estimates are invented.

Training completion is descriptive coverage under forced exploration, not a
learned-policy score. Only the held-out evaluation rates compare the controllers.
Repeated executions should reproduce actions, counts, fixture hashes, and update
counts for the same source revisions. Wall times, temporary paths, timestamps,
and timestamp-bearing persistence hashes are expected to differ.

There is deliberately no external-runner plug-in: accepting arbitrary commands
would undermine the no-network/no-credentials guarantee. A future live-model
study should use a separately reviewed runner, identical model/tool budgets,
external objective verifiers, frozen held-out evaluation, and actual provider
usage records. Do not present this controller experiment as that study.
