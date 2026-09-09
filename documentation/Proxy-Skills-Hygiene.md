# Native HTTP capture and skill hygiene

## Native HTTP proxy (P16)

`PWN::Plugins::MitmProxy` uses WEBrick's native proxy/CONNECT transport and
Net::HTTP for interception. It does not require mitmproxy, Burp, or ZAP.
Only backend `native` is accepted. HTTPS CONNECT tunnels work, but their
contents are **not decrypted**: captured entries explicitly have
`_capture: opaque_connect`. HTTP requests and responses are captured to HAR 1.2.

```ruby
require 'pwn/plugins/mitm_proxy'
proxy = PWN::Plugins::MitmProxy.start(har_path: '/tmp/engagement.har')
browser = PWN::Plugins::TransparentBrowser.open(
  browser_type: :headless_chrome, capture_proxy: proxy
)
# Navigate the browser using its normal API. Chrome loopback bypass is disabled.
entries = PWN::Plugins::MitmProxy.entries(proxy: proxy)
entry = PWN::Plugins::MitmProxy.http_replay(
  proxy: proxy, request_id: entries.first[:_request_id],
  mutations: { method: 'POST', path: '/fixture', headers: { 'X-Test' => 'yes' }, body: 'sample' }
)
# Close the browser separately, then stop its caller-owned proxy:
PWN::Plugins::MitmProxy.stop(proxy: proxy)
```

Agent toolset `http`: `http_proxy_start`, `http_proxy_entries`,
`http_proxy_rules`, `http_replay`, `http_proxy_stop`. Lifecycle tools return
JSON descriptors; subsequent calls use `proxy_id: descriptor[:id]`.
The plugin also accepts `proxy:` descriptors. IDs are process-local, not
persistent replay handles after restart.

Replace the entire active rule list with `rules(proxy:, rules:)`. Rules are
literal substitutions (not regex):

```ruby
[{ phase: 'request', field: 'header:x-test', match: 'old', replace: 'new' },
 { phase: 'response', field: 'body', match: 'old', replace: 'new' }]
```

Fields are `body`, request-only `url`, or `header:NAME`. Replay mutations are
`method`, `url`, `path`, `query`, `headers`, `body`; null header values remove
headers. Hop-by-hop/framing headers are regenerated. Binary HAR bodies use
base64 encoding. Replay does not mutate the original captured entry.

HAR files contain **unredacted traffic**, including any cookies and credentials
sent by the operator. They are created mode 0600; use engagement storage and
retention controls. Only loopback fixtures are used by the regression tests.
There is no built-in scope policy for proxy traffic; enforcement belongs in
engagement network isolation or the central scope layer. Binding is loopback
by default. Upstream HTTP timeout defaults to 30 seconds. Bodies and the
session capture collection are currently buffered in memory, not streamed.

## On-demand skills consolidation (P19)

`PWN::AI::Agent::SkillConsolidation.consolidate(content:, evidence: {}, now:,
stale_days: 90)` returns a pure proposal: `content`, `version`, `changed`,
`deduplicated`, `promoted`, and `review`.

- Deduplicates RL notes, ignoring leading date annotations and whitespace.
- Conflicting text for one feedback ID, explicit negation against a SOP line,
  regressed proofs, and stale verification move to a **not active SOP** review
  section. Unmanaged SOP prose is never automatically deleted or rewritten.
- Promotions require resolved status, three distinct explicitly successful
  verification sessions, and recent non-future verification. Failure counts
  and failure-session IDs do not count as successful evidence.
- Managed promoted procedures are rechecked for stale or regressed proofs.
- Stamps `<!-- pwn-skill-version: HASH12 updated: ISO8601 -->` after YAML
  frontmatter; unchanged content remains byte-identical on subsequent passes.

`consolidate_file(path:)` previews by default. Applying requires
`dry_run: false, confirm: true, expected_sha256: preview[:source_sha256]`.
It serializes cooperating consolidation writers, checks the original content,
keeps a content-addressed backup, atomically replaces the file, and verifies
readback. Symlink files are rejected. No weekly job is installed.

Agent tool `skills_consolidate(name:, dry_run: true)` targets an already
installed skill; it does not accept model-provided verification evidence.
It reloads the skill index after an explicitly confirmed write.

## Precise correction evidence (P20) and integration hooks

Docker socket permissions, registry pull denial and template parsing remain
distinct classes/signatures. Generic path fixes cannot resolve non-path
failures; raw-socket fixes cannot resolve ordinary filesystem/daemon
permissions. Legacy incompatible fixes are excluded from KNOWN FIXES.

For promotion evidence, the successful verification hook should call:

```ruby
PWN::AI::Agent::Mistakes.note_hint_outcome(
  signature: signature, helped: true, session_id: verified_session_id
)
```

Failed hints clear that stability evidence. `skills_consolidate` consumes
`verified_sessions` and `last_verified` keyed by the existing RL signature.
The parent loop must pass `session_id` only after real verification; callers
that omit it cannot promote notes merely by incrementing a counter.
Session-recall/index consumers can read the `pwn-skill-version` stamp and
prefer current installed content over historical SOP text. This module does
not modify central loop or session-recall selection behavior.
