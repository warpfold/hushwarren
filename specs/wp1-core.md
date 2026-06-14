# WP1 — `hush-core`: pure decision & blocklist logic

Implements: `docs/architecture.md` §4 (crate layout), §5 (decision engine), §6
(blocklist pipeline, compile side). Binding standards: `specs/standards.md`.

**Scope guard:** this crate does NO I/O beyond the explicit artifact save/load
functions (which take paths). No network, no tokio, no OS APIs. Everything here is
unit-testable in milliseconds.

Dependencies allowed: `fst`, `arc-swap`, `serde` (+derive), `toml`, `thiserror`.
Dev-deps: `tempfile`, `proptest` (optional, see §8).

---

## 1. Module `domain` — canonical domain names

```rust
/// A canonicalized DNS name: lowercase ASCII, no trailing dot, no empty labels.
/// Invariant: passed `validate()` at construction. Construction is the ONLY way
/// to get one (newtype over `String`, no pub field).
pub struct Domain(String);

impl Domain {
    pub fn parse(input: &str) -> Result<Domain, DomainError>;
    pub fn as_str(&self) -> &str;
    /// Labels in reversed order joined with '.': "ads.example.com" -> "com.example.ads".
    /// This is the fst key encoding (suffix match == prefix scan, but we use
    /// exact-contains per suffix — see rules module).
    pub fn reversed(&self) -> String;
    /// Iterator over this domain and each parent: "a.b.com" -> ["a.b.com","b.com","com"].
    pub fn self_and_ancestors(&self) -> impl Iterator<Item = &str>;
}
```

Canonicalization rules (in order):
1. Trim whitespace; strip ONE trailing dot if present.
2. Lowercase ASCII. Non-ASCII bytes ⇒ `DomainError::NotAscii` (IDNA/punycode
   conversion is out of P0 scope; already-punycoded `xn--` labels pass through).
3. Reject: empty; total length > 253; any label empty, > 63 chars, or containing
   chars outside `[a-z0-9_-]` (underscore is real-world DNS: `_dmarc.` etc.);
   label starting or ending with `-` is ACCEPTED (seen in the wild on blocklists;
   we are a filter, not a registrar).
4. A single label IS valid (`localhost`) — local-name policy lives in `decision`,
   not here.
5. Reject anything that parses as an IPv4 address (`1.2.3.4`) ⇒
   `DomainError::IsIpAddress` (hosts-file lines sometimes have bare IPs in the
   hostname column; blocking IPs is not DNS's job).

`DomainError` is a `thiserror` enum: `Empty | TooLong | BadLabel(String) | NotAscii | IsIpAddress`.

## 2. Module `parse` — unified blocklist line parser

One line-oriented parser handles all three real-world formats (sources mix them);
no per-file format detection.

```rust
pub enum Line {
    Block(Domain),
    Allow(Domain),       // AdBlock exception @@||domain^
    Skip(SkipReason),    // counted, never an error
}
pub fn parse_line(line: &str) -> Line;

pub struct ParseSummary { pub blocked: u64, pub allowed: u64, pub skipped: u64 }
/// Feed many lines into a builder (see rules); returns summary. Never errors.
pub fn parse_list(text: &str, sink: &mut impl RuleSink) -> ParseSummary;
```

Per-line algorithm:
1. Strip comments: everything from `#` or `!` **when at start-of-line or preceded
   by whitespace** (don't split `domain#fragment`-style garbage — that whole line
   just fails domain parse and skips). Trim. Empty ⇒ `Skip(Empty)`.
2. `@@||<d>^` or `@@||<d>^$...` ⇒ `Allow(d)` if `d` parses.
3. `||<d>^` or `||<d>^$...` ⇒ `Block(d)`. Any OTHER AdBlock syntax (cosmetic `##`,
   regex `/…/`, plain-pattern without `||`, options needing path matching) ⇒
   `Skip(UnsupportedSyntax)`.
4. Hosts form: first token parses as an IP in {`0.0.0.0`, `127.0.0.1`, `::`,
   `::1`, `0`} ⇒ each subsequent whitespace-separated token is a candidate domain
   (hosts lines may carry several). Hostnames in the built-in localhost set
   {`localhost`, `localhost.localdomain`, `local`, `broadcasthost`,
   `ip6-localhost`, `ip6-loopback`, `ip6-allnodes`, `ip6-allrouters`} ⇒
   `Skip(LocalhostEntry)`. A hosts line whose IP is anything else (real DNS
   mappings, e.g. `192.168.1.5 nas`) ⇒ `Skip(NonBlockingHostsEntry)`.
5. Otherwise: the whole line must be a single domain ⇒ `Block(d)`;
   parse failure ⇒ `Skip(BadDomain)`.

Semantics note (matches `docs/architecture.md` §5): every Block/Allow entry covers
the domain **and all subdomains**. This is AdBlock `||` semantics, applied also to
hosts/plain entries — modern lists (OISD/Hagezi) assume it.

## 3. Module `rules` — compiled rule sets (fst)

```rust
pub trait RuleSink { fn block(&mut self, d: Domain); fn allow(&mut self, d: Domain); }

pub struct RulesBuilder { /* BTreeSet<String> of reversed keys, block + allow */ }
impl RuleSink for RulesBuilder { ... }
impl RulesBuilder {
    pub fn build(self) -> Result<CompiledRules, RulesError>;  // fst build
}

pub struct CompiledRules { block: fst::Set<Vec<u8>>, allow: fst::Set<Vec<u8>>, pub meta: RulesMeta }
pub struct RulesMeta { pub block_count: u64, pub allow_count: u64, pub built_unix_ms: u64, pub source_names: Vec<String> }

pub enum RuleMatch { Allowed, Blocked, None }
impl CompiledRules {
    /// Walk d.self_and_ancestors(); if ANY suffix is in `allow` -> Allowed
    /// (allow wins over block at any specificity — zero-touch-ux.md §7).
    /// Else if any suffix in `block` -> Blocked. Else None.
    /// Zero allocation: reuse a scratch buffer for reversed keys via
    /// `Domain::reversed_into(&self, buf: &mut String)` (add this helper).
    pub fn match_domain(&self, d: &Domain) -> RuleMatch;
    pub fn empty() -> CompiledRules;   // matches nothing; daemon cold-start state
}
```

Key encoding: reversed-label string (`com.example.ads`). Lookup = exact
`set.contains(key)` for each of the query's suffixes (≤ 127 labels, real-world ≤
~10). **No range/prefix scans** — exact contains per suffix is simpler and cannot
produce partial-label false positives (`ample.com` vs `example.com`) by
construction. State this invariant in a comment and prove it with a test.

### Artifact persistence (the only I/O in this crate)

```rust
impl CompiledRules {
    /// Writes <dir>/block.fst, <dir>/allow.fst, <dir>/meta.json atomically
    /// (write to tempfile in same dir, fsync, rename).
    pub fn save(&self, dir: &Path) -> Result<(), RulesError>;
    /// Validates fst headers (fst::Set::new errors on corrupt bytes) and meta
    /// counts; ANY failure -> RulesError::CorruptArtifact (caller rebuilds from
    /// raw sources — docs/architecture.md §6 failure mode).
    pub fn load(dir: &Path) -> Result<CompiledRules, RulesError>;
}
```

## 4. Module `decision` — per-query verdict

Replaces the placeholder `Verdict` in the current `lib.rs` stub.

```rust
pub enum Verdict { Block, Forward, ForwardLocal }
pub enum Reason  { Snoozed, UserAllowed, ListAllowed, ListBlocked, LocalName, NoMatch }

pub struct DecisionEngine {
    rules: arc_swap::ArcSwap<CompiledRules>,        // list-sourced
    user_allow: arc_swap::ArcSwap<UserAllowSet>,     // one-click allows; small
    snooze_until_unix_ms: AtomicU64,                 // 0 = armed
}
impl DecisionEngine {
    pub fn decide(&self, d: &Domain, now_unix_ms: u64) -> (Verdict, Reason);
    pub fn swap_rules(&self, r: Arc<CompiledRules>);
    pub fn set_user_allow(&self, domains: Vec<Domain>);
    pub fn snooze_until(&self, unix_ms: u64);        // 0 clears
    pub fn snoozed(&self, now_unix_ms: u64) -> bool;
}
```

`decide` precedence (exactly this order — it IS the product contract):
1. snoozed ⇒ `(Forward, Snoozed)`
2. local name ⇒ `(ForwardLocal, LocalName)` — single label, or suffix in
   {`local`, `localdomain`, `lan`, `home`, `internal`, `home.arpa`, `arpa`}.
   Local names are checked BEFORE allow/block: blocking your printer is never
   correct, and lists occasionally contain garbage `.lan` entries.
3. user allow (suffix-scoped, same matching as rules) ⇒ `(Forward, UserAllowed)`
4. `CompiledRules::match_domain`: Allowed ⇒ `(Forward, ListAllowed)`;
   Blocked ⇒ `(Block, ListBlocked)`
5. ⇒ `(Forward, NoMatch)`

Threading contract: `decide` is called from many tokio workers concurrently; it
takes `&self`, never blocks, never allocates beyond the reversed-key scratch
(thread-local or stack buffer), and sees rule swaps atomically (`ArcSwap::load`).

`UserAllowSet`: sorted `Vec<String>` of reversed keys + binary-search suffix check
(it's user-clicked, ≤ hundreds — no fst needed). Dedup + include a `to_lines()`
serialization (daemon persists it as a plain text file, WP3).

## 5. Module `config` — `HushConfig`

serde + toml model; users never hand-edit it (API-written), but it must be
forgiving to read and stable to write. `#[serde(default, deny_unknown_fields)]`
on every struct; `Default` = fully working Local Guard config.

```toml
[listen]
udp = ["127.0.0.1:53", "[::1]:53"]     # tests override with port 0
tcp = ["127.0.0.1:53", "[::1]:53"]

[upstream]
# Order = ladder order (architecture §5). bootstrap_ips REQUIRED for doh —
# never resolve the DoH hostname through the system (loop hazard).
doh = [
  { url = "https://cloudflare-dns.com/dns-query", bootstrap_ips = ["1.1.1.1", "1.0.0.1"] },
  { url = "https://dns.quad9.net/dns-query",      bootstrap_ips = ["9.9.9.9", "149.112.112.112"] },
]
do53_fallback = []                      # P1 Sentinel fills with DHCP resolver

[lists]
sources = [ { name = "oisd-small", url = "https://small.oisd.nl/domainswild2" } ]
refresh_hours = 24
jitter_minutes = 60

[block]
action = "null_ip"                      # or "nxdomain"
ttl_secs = 10

[api]
listen = "127.0.0.1:5380"

[runtime]
state_dir = ""                          # "" -> platform default (daemon resolves)
```

Provide `HushConfig::{from_toml_str, to_toml_string, default()}` + round-trip
test. Validation method `validate()` returns all problems at once
(`Vec<ConfigProblem>`), not first-error.

## 6. Module `querylog` — types + ring buffer

```rust
pub struct QueryRecord {
    pub ts_unix_ms: u64, pub qname: String, pub qtype: u16,
    pub verdict: Verdict, pub reason: Reason, pub upstream_ms: Option<u32>,
}
/// Fixed-capacity overwrite-oldest ring. Push from the DNS path must be O(1)
/// and never block queries: std Mutex is acceptable (push is nanoseconds; no
/// .await inside), document the choice.
pub struct QueryRing { ... }
impl QueryRing {
    pub fn new(capacity: usize) -> Self;
    pub fn push(&self, r: QueryRecord);
    pub fn recent(&self, n: usize) -> Vec<QueryRecord>;        // newest first
    pub fn recent_blocked(&self, n: usize) -> Vec<QueryRecord>;
    pub fn stats(&self) -> RingStats;  // total, blocked, since_unix_ms (saturating counters)
}
```

## 7. Errors

One `thiserror` enum per concern (`DomainError`, `RulesError`, `ConfigError`).
No `anyhow` in this crate (libraries expose typed errors).

## 8. Mandatory test cases (floor, not ceiling)

Unit tests, colocated. Use `proptest` ONLY if it stays fast (<2s total); otherwise
hand-rolled fuzz-ish tables are fine.

**domain:** trailing dot; uppercase→lower; 253/254 length boundary; 63/64 label
boundary; empty label (`a..b`); underscore label ok; `xn--` passthrough; non-ASCII
rejected; bare IPv4 rejected; single label ok; `reversed()` correctness;
`self_and_ancestors` order and count.

**parse:** each format happy path; `@@||x^` → Allow; `||x^$third-party` → Block
(options ignored); cosmetic `##.ad` skipped; hosts line with 3 hostnames → 3
Blocks; `127.0.0.1 localhost` skipped as LocalhostEntry; `192.168.1.5 nas` skipped
as NonBlockingHostsEntry; inline `# comment` stripped; `!` comment; whitespace
soup; 0-byte and 10MB-of-garbage inputs don't panic and return sane summaries;
CRLF line endings.

**rules:** exact match; subdomain match (`a.b.example.com` blocked by
`example.com`); **label-boundary non-match (`notexample.com` NOT blocked by
`example.com`, `ample.com` NOT blocked)**; allow-beats-block at different
specificities (allow `cdn.example.com` + block `example.com` ⇒ `x.cdn.example.com`
Allowed, `other.example.com` Blocked — wait, allow wins only on its own suffix
chain: verify exactly this asymmetry); empty rules match nothing; save→load
round-trip equality; corrupt block.fst ⇒ CorruptArtifact; meta counts.

**decision:** full precedence ladder — one test per rung proving it beats all
lower rungs (snooze beats block; local beats block even when blocklisted; user
allow beats list block; list allow beats list block); snooze expiry at exact
boundary ms; concurrent decide-during-swap_rules smoke (spawn threads, no torn
reads — this is what ArcSwap guarantees, test documents the contract).

**config:** default validates clean; round-trip; unknown field rejected; missing
bootstrap_ips on a doh entry ⇒ validation problem; bad listen addr ⇒ problem
(collect-all behavior: a config with 3 problems reports 3).

**querylog:** wraparound at capacity; recent(n) ordering; stats counters;
push-from-8-threads smoke.

## 9. Deliverable shape

- Replace `crates/core/src/lib.rs` stub: `lib.rs` declares modules + re-exports
  the public API listed above; one file per module.
- Update `crates/core/Cargo.toml` deps; add `[workspace.dependencies]` entries in
  the root `Cargo.toml` for anything WP2/3 will share (serde, thiserror, arc-swap,
  toml, tracing, tempfile).
- Gate green per `standards.md` §1, run summary per §7.
