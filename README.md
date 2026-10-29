# appsec-semgrep-rules

[![CI](https://github.com/Young-Syre/appsec-semgrep-rules/actions/workflows/test.yml/badge.svg)](https://github.com/Young-Syre/appsec-semgrep-rules/actions/workflows/test.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![semgrep](https://img.shields.io/badge/semgrep-1.164.0-00a67d.svg)](https://semgrep.dev)
[![rules](https://img.shields.io/badge/rules-13-informational.svg)](#rules)

Semgrep rules written from the defect end rather than the taxonomy end.

Most public rulesets start from a taxonomy: someone reads the CWE list and writes
a pattern per entry. These start from the other end. Each rule generalises a
specific, mechanical mistake — the thing that made a bug of that class
exploitable rather than merely present. The question each one answers is not
"does this code contain a known-bad API call" but "does this code repeat the
mistake that made the protection useless".

That shows up in three places:

- **The messages explain mechanisms.** A rule that only tells you the category of
  the bug makes you do the analysis again. Every message here says what the code
  actually does, why that is exploitable, and what to write instead.
- **The fixtures are the specification.** Each rule ships a fixture carrying the
  vulnerable shape next to the fixed shape, so the rule's boundary is written
  down rather than implied. They are what the rule was tuned against, and what CI
  checks on every push.
- **The limits are written down.** Three of these rules are heuristics and say so
  in their own metadata, in the table below, and in
  [False positives](#false-positives). A rule whose precision you cannot predict
  is a rule you will end up ignoring.

Every fixture is synthetic. No client, vendor, program, product or report
identifier appears anywhere in this repository, and none will — including in the
fixtures, whose receiver and module names are deliberately generic so that no
rule can be read as an accusation against a named codebase.

## Rules

| Rule | Language | Severity | CWE | What it catches |
| --- | --- | --- | --- | --- |
| [`ssrf-rebind-protection-disabled`](rules/ruby/ssrf-rebind-protection-disabled.yaml) | Ruby | ERROR | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | An HTTP call that opts out of the client's SSRF/DNS-rebinding protection (`dns_rebind_protection: false`, `allow_local_requests: true`, `allow_localhost: true`), reopening the TOCTOU window between validating a host and connecting to it. |
| [`vm-sandbox-denylist-missing-realm-escape-module`](rules/javascript/vm-sandbox-unsound-denylist.yaml) | JS/TS | ERROR | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | A module denylist that blocks `child_process` and friends but leaves `vm`, `module`, `repl`, `inspector` or `worker_threads` reachable — any one of which returns a host realm. |
| [`vm-sandbox-denylist-missing-node-prefix-alias`](rules/javascript/vm-sandbox-unsound-denylist.yaml) | JS/TS | ERROR | [CWE-184](https://cwe.mitre.org/data/definitions/184.html) | A denylist that blocks `"fs"` but not `"node:fs"`. Node resolves both to the same builtin; a string comparison does not. |
| [`vm-run-in-this-context-untrusted-code`](rules/javascript/vm-sandbox-unsound-denylist.yaml) | JS/TS | ERROR | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | `vm.runInThisContext` on a non-literal, which compiles code into the calling realm — there is no sandbox to escape from. |
| [`postmessage-handler-missing-origin-check`](rules/javascript/postmessage-origin-unchecked.yaml) | JS/TS | WARNING | [CWE-346](https://cwe.mitre.org/data/definitions/346.html) | A `message` handler that reads `event.data` without ever referencing `event.origin`. |
| [`postmessage-wildcard-target-origin`](rules/javascript/postmessage-origin-unchecked.yaml) | JS/TS | WARNING | [CWE-1385](https://cwe.mitre.org/data/definitions/1385.html) | `postMessage(payload, "*")` where the payload is computed rather than constant, so the receiver can navigate itself and collect it. |
| [`template-context-exposes-host-capability`](rules/javascript/template-sandbox-escape-surface.yaml) | JS/TS | ERROR | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | `require`, `process`, `global`, `module`, `Function` or a `.constructor` accessor passed into a server-side template context, which turns a template sandbox into an SSRF or RCE primitive. |
| [`attacker-controlled-preallocation`](rules/rust/attacker-controlled-preallocation.yaml) | Rust | ERROR | [CWE-789](https://cwe.mitre.org/data/definitions/789.html) | A length decoded off the wire reaching `with_capacity` / `reserve` / `resize` with no cap. Taint-mode; a four-byte prefix drives a multi-gigabyte reservation from a sixteen-byte request. |
| [`attacker-controlled-preallocation-vec-macro`](rules/rust/attacker-controlled-preallocation.yaml) | Rust | WARNING | [CWE-789](https://cwe.mitre.org/data/definitions/789.html) | The same defect in `vec![0u8; n]`. Function-scoped rather than taint-based, because Semgrep does not trace taint through macro arguments. *Heuristic.* |
| [`non-constant-time-secret-compare`](rules/go/non-constant-time-compare.yaml) | Go | WARNING | [CWE-208](https://cwe.mitre.org/data/definitions/208.html) | `==`, `!=`, `bytes.Equal` or `strings.EqualFold` on a value named like a secret, MAC, signature or token, where `subtle.ConstantTimeCompare` is required. *Heuristic (name-based).* |
| [`postgres-view-missing-security-invoker`](rules/sql/postgres-view-missing-security-invoker.yaml) | SQL | ERROR | [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | A view created without `WITH (security_invoker = on)`. The view runs as its owner, so RLS policies on the base table are evaluated against an RLS-exempt role and every row is returned to every caller. |
| [`postgres-security-definer-function-in-public-schema`](rules/sql/postgres-view-missing-security-invoker.yaml) | SQL | WARNING | [CWE-269](https://cwe.mitre.org/data/definitions/269.html) | A `SECURITY DEFINER` function in `public`, which PostgREST publishes as `POST /rpc/<name>` running with the owner's privileges. |
| [`secret-share-range-validation-missing`](rules/multi/secret-range-validation-missing.yaml) | JS/TS | WARNING | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | A secret-sharing `combine()` that checks x-coordinates are distinct but not that they are in range, accepting x = 0 — the secret itself — which the matching `split()` correctly refuses to emit. *Heuristic.* |

<details>
<summary><b>Why these bug classes are worth a rule each</b></summary>

Several of them are not in the mainstream rulesets, and each is missed for a
different reason.

**The SSRF one is a config flag, not an API.** Static analysis that looks for
dangerous *functions* cannot see this: the function is the hardened wrapper
everyone is supposed to use, and the bug is an option that switches the
hardening off. The protection it disables exists specifically because validating
a hostname and connecting to it are two separate DNS lookups, so an attacker who
controls the zone answers the first with a public address and the second with
`169.254.169.254`. One keyword argument on a route reachable without
authentication is the whole vulnerability.

**The denylist rules check a set for what is absent.** This is an awkward shape
for a pattern language, which is probably why it is rarely attempted: you are not
matching a bad call, you are asserting a property of a literal. Both failure
modes are real — the realm-escape omission and the `node:` alias omission — and
they are independent, so the fixtures keep them separate to prove the rules do
not mask each other.

**The Postgres view rule covers a default that is wrong for the common case.**
`security_invoker` was added in Postgres 15, and the default is still off, so
every view written without it inherits owner-rights evaluation. On a project that
has carefully written RLS policies and exposes its schema over PostgREST, one
`CREATE VIEW` silently undoes the policy layer — and because `CREATE OR REPLACE
VIEW` does not preserve options you forget to restate, a view can lose the fix in
a later migration without anyone touching the security model.

**The Rust rule is about amplification, not just a large number.** `with_capacity`
is not a dangerous function; it becomes one when its argument is a length prefix
the peer chose. The interesting property is the ratio: a sixteen-byte request
whose four header bytes name a four-gigabyte buffer, with the attacker never
obliged to send the bytes the header promised.

**The Go rule carries an honest severity caveat, in the message itself.** A timing
leak on an HMAC over request-bound data leaks that one request's signature, not
the signing key. That is still a defect, but it is not the same finding as a
timing leak on an API key or a session token, where recovery is total. A rule that
flattened both into "timing attack" would be training its users to stop reading
the message.

</details>

## Usage

Scan with a single rule file straight from this repository:

```bash
semgrep --config https://raw.githubusercontent.com/Young-Syre/appsec-semgrep-rules/main/rules/ruby/ssrf-rebind-protection-disabled.yaml .
```

Semgrep can fetch a rule *file* over HTTP but not a directory listing, so for the
whole set, clone it and point `--config` at `rules/`:

```bash
git clone https://github.com/Young-Syre/appsec-semgrep-rules
semgrep --config appsec-semgrep-rules/rules .
```

Scan one language only:

```bash
semgrep --config appsec-semgrep-rules/rules/rust .
```

The SQL rules run in Semgrep's `generic` mode and restrict themselves to `*.sql`,
`*.psql` and `*.pgsql` via `paths.include`. If your migrations live under a path
your `.semgrepignore` excludes — `tests/` and `migrations/` are both easy to
exclude by accident — pass them explicitly:

```bash
semgrep --config appsec-semgrep-rules/rules/sql supabase/migrations/
```

### CI

```yaml
name: semgrep
on: [push, pull_request]

permissions:
  contents: read

jobs:
  appsec-rules:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: Young-Syre/appsec-semgrep-rules
          path: .semgrep-rules
          ref: main
      - run: pipx install semgrep==1.164.0
      - run: semgrep --config .semgrep-rules/rules --error --metrics=off .
```

`--error` makes Semgrep exit non-zero on any finding. Pin the ruleset to a tag or
commit rather than `main` if you want the check to stay stable as rules are added.

## Development

```bash
make validate   # every rule parses and its patterns compile
make lint       # validate, then check metadata completeness
make test       # run the fixture suite
make all        # all three
```

`make lint` runs [`scripts/lint_metadata.py`](scripts/lint_metadata.py), which
enforces this repository's own contract rather than Semgrep's. `semgrep
--validate` tells you a rule compiles; it does not tell you the rule is
documented. The linter requires a lower-kebab-case id, a severity, a declared
language, a message of at least forty words, a `CWE-<id>: <title>` string that is
formatted correctly, two or more `https://` references, and a non-empty
`technology` list — and it rejects duplicate rule ids across files.

### Writing your own

Rules live at `rules/<language>/<name>.yaml` and their fixtures at
`tests/<language>/<name>.<ext>`. Semgrep pairs the two by basename, so the names
have to match; a rule file may hold several rules, and they all test against the
same fixture.

Annotate the line *above* each interesting line — above the line Semgrep reports,
which is the expression, not the enclosing function:

```javascript
// ruleid: postmessage-handler-missing-origin-check
window.addEventListener('message', (event) => {
  render(event.data.html);
});

// ok: postmessage-handler-missing-origin-check
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://app.example.com') return;
  render(event.data.html);
});
```

Then `make test`. Every rule in this repository has at least two true positives
and two safe counter-examples, and CI fails on a single mismatch in either
direction — a missed `ruleid` or a flagged `ok`.

<details>
<summary><b>Two things that will cost you an hour if nobody tells you</b></summary>

**`metavariable-regex` is anchored at the start.** It behaves like `re.match`, not
`re.search`. `(?i)(hmac|mac)` does not match `expectedMAC`; you need
`(?i)^.*(hmac|mac).*$`. Nothing warns you — the rule simply never fires.

**PCRE lookarounds are atomic, so backreferences across them do not backtrack.**
The obvious way to express "this list names a module but not its `node:` alias" is
`(?=.*['"](\w+)['"])(?!.*node:\1)`, capturing in one lookahead and referring to it
in the next. It does not work: once the first lookahead succeeds it will not be
re-entered, so the engine never tries the other names in the list. The rule here
spells out one positive/negative lookahead pair per module instead
([`vm-sandbox-unsound-denylist.yaml`](rules/javascript/vm-sandbox-unsound-denylist.yaml)).

Two smaller ones, both visible in the fixtures:

- `...` does not descend through a closure boundary. A range check written as
  `shares.some((s) => s.x === 0)` is invisible to a pattern that expects the
  comparison in the enclosing function body, which is why
  [`secret-range-validation-missing.yaml`](rules/multi/secret-range-validation-missing.yaml)
  spells the predicate forms out.
- Taint does not flow into macro arguments, so `vec![0u8; n]` cannot be a taint
  sink even though a search pattern matches it. Hence the two Rust rules.

</details>

## False positives

Precision is a property of each rule, not of the ruleset, so here is the honest
breakdown. Ten of the thirteen rules match a construct that is unambiguous. Three
are heuristics, and these are the cases they will get wrong.

| Rule | Where it over-reports | Where it under-reports |
| --- | --- | --- |
| `non-constant-time-secret-compare` | Identifier names drive it, so `macAddress`, `tokenizer` and similar will match. Comparing a value to a constant for routing rather than for authentication is flagged too. | A secret in a variable whose name does not look like one. Comparison through a helper function. |
| `attacker-controlled-preallocation-vec-macro` | Function-scoped: a function that decodes a length and separately allocates something unrelated and un-capped is flagged. | Any bound check against a constant anywhere in the function suppresses the finding, including one that does not actually guard this allocation. Caps applied in a different function are invisible. |
| `secret-share-range-validation-missing` | Any comparison against `0` or `1` in the same function is read as a range check, so a routine that compares something unrelated looks validated. | Only function declarations are in scope; arrow-assigned and class-method implementations are skipped deliberately rather than covered badly. |

Two deliberate scope decisions in the non-heuristic rules, so that a quiet result
is not mistaken for a clean one:

- **`template-context-exposes-host-capability` is narrow on purpose.** It fires
  only on values that are *themselves* host capabilities. A context entry such as
  `{ utils: utils }` is the same bug class whenever `utils` reaches anything
  privileged, but from one call site there is no way to tell a privileged bean
  from a date formatter, and guessing would mean a finding in every Express
  codebase. Audit hand-written helper objects passed into template contexts
  yourself.
- **`postmessage-handler-missing-origin-check` only recognises an `if` on the
  event's origin as a check.** `if (event.origin !== ALLOWED) return;` and
  `if (!ALLOWED.includes(event.origin)) return;` both count. A check written
  some other way — a boolean assigned first, a helper called — is not
  recognised, and the handler is reported anyway; that is a false positive a
  reader can dismiss in a second, which is the direction to err in.

  The check is structural rather than textual on purpose. Testing the handler's
  source text for `.origin` meant a comment reading
  `// TODO: validate event.origin` suppressed the finding entirely.

  Within the checks it does recognise it is still only asking whether one
  exists. `event.origin.startsWith('https://example.com')` passes, and is still
  exploitable, because an attacker registers `example.com.evil.net`. Reviewing
  the checks that exist is a separate pass.

Suppress an individual finding with `// nosemgrep: <rule-id>` and a reason, or
drop a rule from a scan with `--exclude-rule <rule-id>`. If a rule is wrong in a
way that generalises, that is worth an issue — the fixture that reproduces it is
the useful half of the report.

## References

Primary sources behind the rules, rather than a reading list:

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html) and [PortSwigger's SSRF material](https://portswigger.net/web-security/ssrf), including the DNS-rebinding variant.
- [Node `vm` documentation](https://nodejs.org/api/vm.html#vm-executing-javascript) — "the `vm` module is not a security mechanism", stated by the maintainers.
- [Node core modules and the `node:` prefix](https://nodejs.org/api/modules.html#core-modules).
- [`Window: message` event](https://developer.mozilla.org/en-US/docs/Web/API/Window/message_event) and [`postMessage` security concerns](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns).
- [`CREATE VIEW`](https://www.postgresql.org/docs/current/sql-createview.html) and [function security attributes](https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY) in the Postgres manual; [Supabase on row-level security](https://supabase.com/docs/guides/database/postgres/row-level-security); [PostgREST on exposing functions](https://docs.postgrest.org/en/stable/references/api/functions.html).
- [CWE-789: Memory Allocation with Excessive Size Value](https://cwe.mitre.org/data/definitions/789.html) and [`Read::take`](https://doc.rust-lang.org/std/io/trait.Read.html#method.take).
- [`crypto/subtle.ConstantTimeCompare`](https://pkg.go.dev/crypto/subtle#ConstantTimeCompare) and [`crypto/hmac.Equal`](https://pkg.go.dev/crypto/hmac#Equal).
- [Server-side template injection](https://portswigger.net/research/server-side-template-injection) — the original research on utility objects as sandbox-escape surface.
- [Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) and [the TSS draft](https://datatracker.ietf.org/doc/html/draft-mcgrew-tss-03) on share validity.
- [Semgrep rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax) and [testing rules](https://semgrep.dev/docs/writing-rules/testing-rules).

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 David Nichols.
