# Research: "Since when, and why?" — change attribution and forecasting for doctor

*2026-10-11 · research-lab-feature · status: proposal, prototype validated*

## TL;DR

doctor already answers **what is wrong** and **how to fix it**. No consumer system tool answers the two
questions a professional troubleshooter asks next:

1. **Since when, and what changed to cause it?** ("`foo.service` started failing Oct 4, right after
   `libfoo` was upgraded. Undo: `apt install libfoo=1.2.3`.")
2. **What is about to go wrong?** ("`storage` will be full in ~38 days at the current rate.")

The recommended feature is a **change-attribution engine**: doctor keeps a compact memory of every check-up,
joins it with change evidence the system already logs (apt/dpkg, snap, boots/kernels, `/etc`, systemd unit
files, doctor's own fixes), and ranks the likely cause of each *new* issue. It also closes the loop on fixes
("fix 3 held" / "came back after 2 days") and forecasts resource exhaustion with robust statistics.

It follows the "do much with less" rule: **no new command is needed**. Each finding just gains one line
(`started Oct 4 · likely after: libfoo 1.2.3→1.2.4 upgrade · undo available`). `doctor why 3` gives
the full ranked evidence for anyone who wants it.

The method is a synthesis of four peer-reviewed systems: Strider (LISA '03), PeerPressure (OSDI '04),
Chronus (OSDI '04) and NetMedic (SIGCOMM '09), together with disk-reliability and software-aging research. Each was
built for enterprise fleets, VMs or Windows registries. None works on a single Linux desktop, from logs
that already exist, with no agent and no fleet. That gap is where the novelty is.

---

## 1. Problem intake

### Where doctor stands today (from the code)

- `cli.scan()` writes `last.json`, **overwriting** the previous one. `reports/` keeps 30 plain-text renders.
  doctor has no machine-readable memory across runs.
- `finding()` has an optional `key`, but **37 of 38 findings in the current `last.json` have `key=None`**.
  The same issue has no stable identity from one run to the next, and every kind of temporal reasoning needs one.
- `fixes.log` records what doctor changed, with undo commands. That data already makes a change ledger,
  but nothing reads it back to check whether a fix worked.
- Some checks already reason about time in an ad-hoc way: `app-kills` says "all before the fix on Oct 11",
  and `startup-items` says "added in the last 3 days". So the need is real, but each check solves it on its own.

### Formal specification

- **Input.**
  - Snapshots `S = [(t_i, boot_i, {fp → level})]`, one per check-up.
  - Change ledger `C = [(t, kind, subject, before, after, undo)]`.
  - Optional per-finding evidence time `since` (earliest log/crash timestamp of the current episode).
  - Optional resource series `R_m = [(t, used, capacity)]` per mount and for memory.
- **Output, per active finding `F`.**
  - The onset interval `(t_lo, t_hi]`.
  - A ranked list of changes `c` with posterior weight `p(c | F)`, each with its undo command when one is known.
  - Optionally, "resolved by" for findings that disappeared.
- **Output, per resource.** Time-to-exhaustion, or `None` when there is no statistically significant trend.
- **Invariants.**
  - **I1 (admissibility).** A change whose effect began at or before `t_lo` cannot be the sole cause, because the
    system was healthy with it in place. Strider used this "known-good vs known-bad state" rule.
  - **I2 (effect time).** Kernel, driver, firmware, microcode and libc changes take effect at the **next boot**,
    not at install time. Service packages take effect at the next service restart.
  - **I3 (honesty).** Never present a cause with certainty the evidence does not support. When there is no
    discriminating evidence, show "N changes in that window" rather than a guess.
- **Performance envelope.** It adds under 50 ms to a check-up that takes about 3 s. Storage stays under 5 MB per year.
  It needs no daemon, no network and no root beyond what the checks already use.
- **Failure modes to design against.**
  - Blaming a change that came *after* the issue. This happens on this machine today: see §5.3.
  - False exhaustion alarms from noisy disk usage.
  - Fingerprint drift, where the title wording changes between versions and splits one issue into two.
  - A sparse run cadence that makes the onset window too wide to be useful.

## 2. Landscape: what exists and why it falls short

| Tool | Tells you what | Since when | Caused by what | Will fail when |
|---|---|---|---|---|
| doctor (today) | ✓ (+ fixes) | partial, per check | ✗ | ✗ |
| netdata / Glances / btop | metrics | graphs only | ✗ | netdata has ML anomaly alerts, no cause |
| Cockpit | services, logs | ✗ | ✗ | ✗ |
| Windows Reliability Monitor | failures **and** installs on one timeline | ✓ | **left to the user to eyeball** | ✗ |
| `needrestart`, `debsums` | single facets | ✗ | ✗ | ✗ |
| Enterprise AIOps (Dynatrace, etc.) | ✓ | ✓ | ✓ via topology + agents, fleet-scale | ✓ |

The closest consumer precedent is Windows Reliability Monitor. It puts failures and installs side by side
and leaves the correlation to a human. doctor would do that correlation itself and add proof that a fix worked.
That is exactly the user's design rule: absorb the hard part.

## 3. Research foundations

| Source | Key idea | What we take | What we change |
|---|---|---|---|
| **Strider**, Wang, Verbowski et al., LISA '03 (award paper) | Diff a known-good state against a known-bad one, intersect with the change trace, and filter noise statistically. Reports cutting problem complexity by orders of magnitude | Admissibility rule I1, and the intersection of "changed in the window" with "related to the failure" | We have no registry snapshots. Changes come from existing logs, and "good/bad" comes from doctor's own runs |
| **Chronus**, Whitaker, Cox, Gribble, OSDI '04 | Search *time* for the moment a system went from working to failing. A probe tells good from bad, and a binary search over snapshots costs O(log n) | Model the onset as an interval, and treat every doctor check as the probe | We can't boot past disk states. The interval comes from existing run history plus journal timestamps (§4.3) |
| **PeerPressure**, H. Wang, Platt et al., OSDI '04 | Rank suspect settings with empirical-Bayes estimation against a population of healthy machines. Found the root cause in 12 of 20 real cases, and otherwise cut candidates by about 1000× | A Bayesian ranking over candidates instead of a yes/no rule | No fleet. The "population" is **this machine's own past** (the temporal peer) |
| **NetMedic**, Kandula et al., SIGCOMM '09 | Weight dependency edges by how often component states co-varied in history. Needs little application-specific knowledge | The history likelihood ratio: a (finding, change-kind) pair that co-occurred before weighs more | Fine-grained components → packages/units/binaries |
| **EnCore**, Zhang, Xu, Zhou et al., ASPLOS '14 | Misconfigurations show up as interactions between config and the *environment* | Use structural links (unit → binary → package, crash → executable → package) as evidence | Only the ownership links, with no learned config rules |
| **Pinheiro, Weber, Barroso**, FAST '07 (Google), and **Backblaze** SMART stats | SMART 5/187/197/198 correlate strongly with failure. SMART alone predicts individual drives poorly. The **rate** of growth matters more than the absolute count (Backblaze: 20 new 187 errors in one day ≫ 60 over five years) | Track SMART raw counters over time and alert on *deltas* | — |
| **Garg, van Moorsel, Vaidyanathan, Trivedi** 1998 (software aging); Mann-Kendall + Sen's slope studies | Trend tests and a robust slope give an "estimated time to exhaustion". Caveat: Mann-Kendall alone produces false positives on short series | Mann-Kendall as a gate, Theil–Sen for the slope, a minimum of 8 samples | — |

## 4. Synthesis and design

### 4.1 Atomic ideas recombined

```
Strider admissibility ──┐
Chronus onset interval ─┼─► onset window (t_lo, t_hi] ──► candidate set C_w ⊂ C
journal/crash timestamps┘        (§4.3 sharpening)               │
                                                                 ▼
EnCore structural links ──► likelihood ratios ──► PeerPressure-style Bayesian ranking (temporal peer)
NetMedic co-occurrence ───┘                                        │
                                                                   ▼
                                    "likely after: X" · undo · "resolved by: Y" · fix held/failed
Garg/Trivedi + MK/Theil–Sen ──► time-to-exhaustion (disk, inodes, memory growth, SMART deltas)
```

The novel combination, as far as this survey found: **population-free statistical attribution, where the
machine's own history is the reference population, built entirely from logs a stock Linux install already
keeps, with boot-gated effect times.** No cited system has that combination. `[conjecture: novelty claim
limited to the sources surveyed here]`

### 4.2 Data model (append-only, stdlib only)

`~/.local/state/doctor/ledger.jsonl`, one line per check-up, about 1–2 KB:

```json
{"t": 1760180000, "boot": "149f6531…", "v": 2,
 "f": {"a1b2c3d4e5f6": "warn", "…": "info"},
 "since": {"a1b2c3d4e5f6": 1759587846},
 "m": {"/": [412e9, 500e9], "/media/…/storage": [1.0e12, 1.1e12], "mem_avail": 11e9}}
```

- **Fingerprint:** `blake2s(check | key or normalize(title))`, 6 bytes. `core.normalize()` already collapses
  numbers and IDs, so "3 crash reports" and "4 crash reports" map to the same issue. Checks whose titles name
  a subject (a unit, a port, a mount) should set `key=` explicitly. That is a one-line change per check, and it
  removes fingerprint drift (§1).
- **Change ledger** is **not stored**. It is rebuilt on demand from the sources below. Each source parses in
  milliseconds (measured in §5.1), so there is nothing to keep in sync:

| Source | Parsed from | Effect time |
|---|---|---|
| apt/dpkg | `/var/log/apt/history.log*` (incl. `.gz`) | install time; next boot for kernel/driver/firmware/libc/systemd (I2) |
| snap | `snap changes` | install time |
| boots/kernel | `journalctl --list-boots`, running vs installed kernel | boot time |
| systemd units | unit file mtimes under `/etc/systemd`, `~/.config/systemd` | file mtime |
| `/etc` edits | `find /etc -newermt` (bounded to the window) | file mtime |
| doctor fixes | `fixes.log` (already has undo commands) | fix time |
| Docker images | `docker image ls --format '{{.CreatedAt}}'` for running containers | container start |

### 4.3 Onset window, sharpened by evidence time

The stress test (§5.2) shows that window width decides accuracy. The window therefore comes from two
independent clocks, and the tighter of the two wins:

- **Observation clock:** `t_lo` is the last run where the fingerprint was absent, and `t_hi` is the first run where it was present.
- **Evidence clock:** many checks are journal-derived (failed units, OOM kills, segfaults, Xid, crash files).
  They already know the timestamp of the first event of the current episode. They report it as
  `finding(..., since=ts)`. Then `t_hi = min(t_hi, since)` and the window is `(t_lo, since]`. This is usually
  hours wide, even when the user runs doctor only once a month.

```
onset(fp):                                         # O(k), k = runs in current episode
    walk ledger backwards while fp present → t_first
    t_lo = time of first run (going back) without fp, or None
    t_hi = min(t_first, since[fp]) if since else t_first
```

When `t_lo` is `None` (the issue existed at the first-ever run), attribution is limited to `since − 30 d`
and labelled "existed before doctor started remembering".

### 4.4 Ranking

For each change `c` with effect time `τ(c) ∈ (t_lo, t_hi]` (I1 and I2 applied):

```
w(c) = 1                                       # uniform prior over admissible changes
     × 20  if c.subject owns the failing binary/unit/executable   (dpkg -S on ExecStart / crash ExecutablePath)
     ×  6  if c.subject name appears in the finding text
     ×  2  if c is boot-gated and area ∈ {hardware, stability}
     ×  4  if (fp, c.kind/subject) co-occurred in a past episode    (NetMedic history)
p(c|F) = w(c) / Σ w
```

The likelihood ratios are hand-set `[conjecture]`. §7 says how to calibrate them. Presentation rule (I3):

- `p ≥ 0.6` → "likely after: X"
- several candidates with `p ≥ 0.2` → "one of: X, Y, Z"
- otherwise → "began between Oct 3 and Oct 5 · 82 changes in that window · `doctor why 3`"

**Complexity:** the ledger is sorted by time, so finding the window costs O(log |C|) by bisection. Scoring costs
O(|C_w|), plus one batched `dpkg -S` call for every owned path, about 0.3 s per call, run in parallel with the
checks. Total stays well under the 50 ms budget except for the one `dpkg -S` batch, which runs in the
thread pool doctor already uses.

### 4.5 The same machinery, three more answers

1. **Resolved by.** When a fingerprint disappears, run the same ranking over the window `(last present, first
   absent]`. If a doctor fix from `fixes.log` lands there, the result is **"fix 3 held"**. If the issue reappears
   later, the result is **"fix 3 didn't hold (came back after 2 days)"**. No consumer tool proves its fixes work.
2. **Recurrence.** Count past episodes per fingerprint. "This is the 4th time since August" turns an annoyance into a pattern.
3. **Exhaustion forecast.** For every mount, inodes, and the SMART 5/187/197/198 raw counters, use the resource
   series from the ledger. Only when the Mann-Kendall test gives `z ≥ 2.33` (one-sided p < 0.01) with n ≥ 8 samples,
   fit a Theil–Sen line and report the time-to-full. For SMART, alert on **rate** (Backblaze), not on a count above zero.

### 4.6 What the user sees

The default report needs no new command:

```
DISK
  ! /media/eligapris/storage is 90% full (111G free of 1.1T)          [fix 4]
      at the current rate (+1.9G/day since Sep 20) it fills in ~58 days
SERVICES
  ✗ foo.service keeps failing                                        [fix 5]
      started Oct 4 14:02 · likely after: libfoo 1.2.3 → 1.2.4 (apt, 13 min earlier)
      undo: sudo apt install libfoo=1.2.3
STABILITY
  ! Samepad crashed (Oct 4)
      samepad was upgraded after this crash (1.4.3 → 1.4.6, Oct 11): may already be fixed
  ✓ fix 3 (oomd tuning, Oct 11) held: no low-memory kills since
```

`doctor why 3` shows the full window, every candidate with its weight and the evidence behind it, and the
undo command. In `doctor i`, the same lines go on issue cards. `o` (Learn with Claude) gets the attribution
in its context, so the tutor can explain *why* the system thinks the upgrade is to blame.

## 5. Validation

The prototype is [`prototype/proto.py`](prototype/proto.py) and [`prototype/stress.py`](prototype/stress.py). They are about 200 lines of stdlib
Python and could be copied into `src/doctor/` as the starting point.

### 5.1 Cost on this machine (measured)

| Operation | Time |
|---|---|
| Parse full apt history (13 rotated files) → **3,122 package changes** | < 10 ms |
| `journalctl --list-boots` | 19 ms |
| `find /etc -newermt '-7 days'` | 10 ms |
| `snap changes` | 160 ms (run in pool) |
| `dpkg -S` batch for owned paths | ~300 ms (run in pool) |
| Onset + ranking, per issue (synthetic: 1 year, 2 runs/day, 2,000 changes) | **0.07 ms** |
| Mann-Kendall + Theil–Sen on 30 samples | 0.15 ms |

The added cost is dominated by two subprocess calls that overlap with the existing checks. It passes the budget.

### 5.2 Stress test: accuracy against how often doctor runs (500 Monte Carlo trials each)

The simulated year has upgrade batches of 40 packages about twice a week plus ad-hoc installs, roughly 12,000
changes in total, and one injected culprit.

| Runs every | Ownership evidence | Culprit in candidate set | Top-1 | Top-3 | Median candidates |
|---|---|---|---|---|---|
| 1 day | yes | 100% | 100% | 100% | 1 |
| 1 day | no | 100% | 68% | 74% | 1 |
| 7 days | yes | 100% | 100% | 100% | 82 |
| 7 days | **no** | 100% | **21%** | 30% | 82 |
| 30 days | **no** | 100% | **5%** | 6% | 367 |

What this shows:

- **Admissibility never lost the culprit** (100% recall in every configuration). Time-windowing alone cuts the
  search space about 150× at weekly cadence, consistent with the orders-of-magnitude reductions Strider and
  PeerPressure report.
- **Time alone is not enough.** Without structural evidence, accuracy collapses as runs get sparse. This is
  why the design needs both §4.3 (evidence-clock sharpening) and the ownership links in §4.4. A design
  that only looked at "what changed recently" would be wrong most of the time for a monthly user.
- The "with evidence" rows use oracle ownership, so they are an upper bound. Real coverage is the main open
  question (C1 in §6).

### 5.3 Real case on this machine

`/var/crash` holds a crash of `/opt/samepad/bin/Samepad`, dated **2026-10-04 08:24**. The apt log shows
**samepad 1.4.3 → 1.4.6 on 2026-10-11 15:39**.

- A naive "what changed recently" heuristic blames the upgrade. **That would be wrong**: the upgrade came after the crash.
- Admissibility (I1) correctly excludes it. The resolved-by direction gives the useful answer instead: "upgraded
  after this crash, may already be fixed".
- Crash → `ExecutablePath` → `dpkg -S` resolved the owning package for **3 of 3** real crash reports
  (samepad, google-chrome-stable, vlc-bin).

### 5.4 Forecast check (synthetic)

- A disk filling at 0.4 GB/day with ±2 GB noise and a one-day cleanup dip: the forecast ETA was 195 days
  against a true 221 days. That is 12% low, which errs early, the safe direction.
- A flat, noisy disk: the Mann-Kendall gate suppressed the forecast. No false alarm.

## 6. Conjecture register

| # | Conjecture | How to test |
|---|---|---|
| C1 | Most actionable findings can be linked to a package (units via ExecStart, crashes via ExecutablePath, segfaults via binary name, Xid via nvidia packages) | Instrument: share of WARN/CRIT findings with a resolved owner across a few machines. Target ≥ 60% |
| C2 | The likelihood ratios 20/6/2/4 rank well | Log every "likely after" plus whether the user applied the undo or the issue cleared. Fit the ratios by maximum likelihood once there are about 50 episodes |
| C3 | Evidence-clock `since` makes windows hours wide for journal-derived findings | Measure the median window width with and without `since` on real ledgers |
| C4 | The fingerprint (`check` + `key`/normalized title) is stable across doctor versions | Bump the ledger schema `v` when titles change. Test: fingerprint every finding in a fixture set across commits |
| C5 | Novelty: no existing consumer Linux tool does population-free change attribution | A wider survey: the GNOME/KDE system monitors, Ubuntu `apport`/`whoopsie`, Fedora ABRT/`retrace`, `sosreport` |
| C6 | Users trust attribution more when it is framed probabilistically ("likely", "one of") | Dogfood. Watch whether `undo` gets used after "likely" vs "one of" |

## 7. Recommended delivery plan

Each step ships on its own value:

1. **Stable identity and memory** (small): add `fingerprint()` and set `key=` on the checks that name a subject.
   Append to `ledger.jsonl` in `scan()` with 1-year rotation. This unlocks "new since last check-up" and
   "4th time since August" right away.
2. **Fix verification** (small): read `fixes.log` against the ledger to get "fix 3 held / didn't hold". This
   uses data doctor already writes.
3. **Change ledger and attribution** (medium): the apt/snap/boot/unit/`/etc` parsers, `since=` on the
   journal-derived checks, ranking, `doctor why N`, and the one-line hint in the report and on issue cards.
4. **Forecasts** (small): disk, inodes and SMART deltas from the ledger series. This replaces the static
   "90% full" warning with a time-to-full where the trend is significant.
5. **Calibration** (ongoing): log outcomes and refit the C2 ratios.

**One decision for you:** forecasts and onset windows get much better with denser samples than the user's
own check-up habit provides. The option that best fits the do-less rule is a tiny **systemd user timer**
(`doctor sample`, every 6 h, ~20 ms, no root) that records only the metrics line and fingerprints. It would
be installed by `install.sh` and could be turned off. The alternative is to rely only on check-ups and the
evidence clock (§4.3). That works, but forecasts need about 8 check-ups before they appear.

## 8. Sources

- Y.-M. Wang, C. Verbowski et al. *STRIDER: A Black-box, State-based Approach to Change and Configuration
  Management and Support.* LISA '03. <https://www.usenix.org/conference/lisa-03/strider-black-box-state-based-approach-change-and-configuration-management-and>
- H. J. Wang, J. C. Platt, Y. Chen, R. Zhang, Y.-M. Wang. *Automatic Misconfiguration Troubleshooting with
  PeerPressure.* OSDI '04. <https://www.usenix.org/conference/osdi-04/automatic-misconfiguration-troubleshooting-peerpressure>
- A. Whitaker, R. S. Cox, S. D. Gribble. *Configuration Debugging as Search: Finding the Needle in the
  Haystack* (Chronus). OSDI '04. <https://www.usenix.org/conference/osdi-04/configuration-debugging-search-finding-needle-haystack>
- S. Kandula et al. *Detailed Diagnosis in Enterprise Networks* (NetMedic). SIGCOMM '09.
  <https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/sigcomm09-395.pdf>
- J. Zhang, T. Xu, Y. Zhou et al. *EnCore: Exploiting System Environment and Correlation Information for
  Misconfiguration Detection.* ASPLOS '14. <https://www.research.ibm.com/publications/encore-exploiting-system-environment-and-correlation-information-for-misconfiguration-detection>
- E. Pinheiro, W.-D. Weber, L. A. Barroso. *Failure Trends in a Large Disk Drive Population.* FAST '07.
  <https://usenix.org/conference/fast-07/failure-trends-large-disk-drive-population>
- Backblaze. *Hard Drive SMART Stats.* <https://www.backblaze.com/blog/hard-drive-smart-stats/>
- S. Garg, A. van Moorsel, K. Vaidyanathan, K. Trivedi. *A Methodology for Detection and Estimation of
  Software Aging.* 1998. <https://repository.lib.ncsu.edu/items/de618a39-f31d-4412-821c-46e069bd3819/full>
- R. Matias, L. de Sena, A. Andrzejak, K. Trivedi. *Software Aging Detection Based on Differential Analysis.*
  WoSAR 2016 (caveats on RSS as a leak signal; Mann-Kendall false positives).
  <https://aip.ifi.uni-heidelberg.de/fileadmin/papers/2016/Software_Aging_Detection_Based_on_Differential_Analysis_WoSAR_2016.pdf>

*Not verified at full-text level:* the PeerPressure 12/20 figure and the EnCore 1.6–3.5× figure come from the
paper abstracts. The NetMedic description comes from the abstract and author summaries.
