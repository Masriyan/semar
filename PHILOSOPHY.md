# The Philosophy of SEMAR

> *"Sing ngerti kabeh, nanging ora ngancam"* — Knows everything, but never threatens.

This document explains **why the project is named SEMAR**, the cultural and
spiritual story behind the name, and how that story is encoded directly into the
software's design decisions. It is longer and more reflective than the rest of
the documentation on purpose: the name is not decoration, it is the spec.

---

## 1. Who is Semar?

In the **wayang kulit** (shadow-puppet) and **wayang golek** traditions of Java
and the wider Indonesian archipelago, **Semar** is the foremost of the
*Punakawan* — a quartet of clown-servants (Semar and his sons Gareng, Petruk,
and Bagong) who accompany the heroic knights of the *Mahabharata* and
*Ramayana* epics as they are performed in the local idiom.

To the casual eye, Semar is comic relief: a short, round-bodied figure with a
flat nose, a single topknot of hair, a perpetual half-smile, and a tear in one
eye — laughing and weeping at once. He speaks plainly, jokes with kings, and
serves the noble *Pandawa* brothers as a humble retainer.

But every Javanese audience knows the secret: **Semar is a god.**

He is **Sang Hyang Ismaya**, an elder deity who, in the *Punakawan* mythology,
voluntarily took on the lowliest, most unremarkable human form in order to walk
among mortals and guide them. He is, in many tellings, simultaneously
*male and female, servant and master, mortal and divine, the oldest and the
humblest*. He holds more power than the kings he serves, yet he never seizes a
throne, never gives an order, never threatens. He advises. He protects. He
watches.

That paradox — **maximum power exercised with maximum restraint** — is the
heart of why this tool bears his name.

---

## 2. Why name a security tool after him?

A security audit tool sits in an extraordinarily privileged position. To do its
job, it must:

- **See everything** — read every configuration file, every system prompt,
  every secret, every tool definition, every MCP manifest.
- **Understand everything** — know what an attacker could do with each of those
  things.
- **Touch nothing** — never alter the system it is inspecting, never become a
  new risk itself, never overstep.

There is a real temptation, in tooling, to *act*: to auto-fix, to rewrite
configs, to "remediate" on your behalf. That power is precisely what makes a
tool dangerous. A scanner that can modify your files is a scanner that can break
your production agent, leak your secrets to a new place, or be subverted into an
attack vector.

Semar is the perfect patron for the opposite approach. He is the guardian who
**knows everything but never threatens**. So SEMAR, the software, is built to be
the same.

---

## 3. From legend to design decisions

Each trait of the wayang Semar maps to a concrete, enforced property of the
software. These are not aspirations — they are how the code is written.

### 3.1 "Sees everything" → Total, deep inspection

SEMAR does not skim. It walks the entire target tree, parses JSON/YAML/TOML/.env,
extracts MCP server blocks and tool definitions, locates system prompts and
instruction files, and (opt-in) reads environment variables. It correlates
across all of them. *Knowing everything* is the first half of the tagline, and
it is taken literally.

### 3.2 "Never threatens" → Read-only by design

SEMAR **never writes to the target.** There is no `--fix`, no auto-rewrite, no
"apply remediation" that touches your files. It opens files for reading only.
The worst thing SEMAR can do to your system is tell you the truth about it.

When SEMAR produces a remediation, it produces *instructions and examples* for a
human to apply — never an edit. This is the single most important design
constraint in the project, and it comes straight from the legend.

### 3.3 "Advises kings, never rules them" → Findings, not mandates

Every finding carries severity, evidence, framework mappings, and a concrete
remediation — and then **stops.** The decision to act is always the operator's.
SEMAR informs the king; it does not take the throne. Exit codes exist so *your*
CI policy can enforce gates, but the policy is yours, not SEMAR's.

### 3.4 "Humble servant, secretly powerful" → Small CLI, deep expertise

SEMAR ships as a single static binary with no runtime dependencies. It is
unassuming. Yet inside it carries the combined knowledge of OWASP LLM Top 10,
MITRE ATLAS, NIST AI RMF, CWE, secret-detection heuristics, entropy analysis,
and prompt-injection scoring. Humble form, divine knowledge.

### 3.5 "Protects from unseen danger" → The new attack surface

The Pandawa could not always see the threats Semar guarded them against. AI
agent operators, likewise, rarely see the prompt-injection surface in a tool
description, the secret in a system prompt, or the SSRF path in an allowlist.
SEMAR's whole purpose is to make the invisible visible.

### 3.6 "Laughing and weeping at once" → Honest reporting

Semar holds joy and sorrow together. SEMAR reports the good and the bad without
flattery: a clean scan is stated plainly, and a critical finding is stated
plainly. No false comfort, no manufactured alarm. Determinism guarantees the
report is the same truth every time.

---

## 4. The name as a backronym

Beyond the legend, **SEMAR** is also a precise description of the software in
Bahasa Indonesia:

> **S**istem **E**valuasi **M**ulti-**A**gen untuk **R**isk, konfigurasi &
> ke**A**manan a**I**

In English: *"A Multi-Agent Evaluation System for Risk, Configuration, and AI
Security."* The acronym does real work — it states the scope (multi-agent),
the method (evaluation), and the three pillars (risk, configuration, security).

---

## 5. The three pillars

The backronym names three pillars; SEMAR's modules map onto them:

| Pillar | Meaning | Modules |
|--------|---------|---------|
| **Risk** | What could an attacker achieve? | `prompt-injection`, `iam`, scoring & compliance mapping |
| **Konfigurasi** (Configuration) | Are the agent's settings safe? | `config`, `network`, `sandbox` |
| **keAmanan** (Security) | Are credentials and the supply chain protected? | `secrets`, `supply-chain` |

---

## 6. Design tenets (the short version)

If you remember nothing else, remember these — they are the operating contract:

1. **Read-only, always.** SEMAR never modifies a target. (Ora ngancam.)
2. **See everything.** Deep, correlated inspection of the whole agent surface. (Ngerti kabeh.)
3. **Deterministic.** Same input ⇒ same output and ordering.
4. **Redact at the source.** Secrets are masked the instant they are found.
5. **Advise, don't enforce.** Findings + remediation; the operator decides.
6. **Map to standards.** Every finding speaks OWASP / ATLAS / NIST / CWE.
7. **Humble footprint.** One static binary, no surprises.

---

## 7. A closing note

Naming a piece of security software after a wayang god is, admittedly, a little
romantic. But software inherits the values of the metaphors we build it around.
By choosing Semar — the guardian who watches over everything and threatens
nothing — we committed ourselves to a tool that is powerful precisely *because*
it is restrained.

*Like the wayang character, SEMAR sees everything, but never disrupts.*

— **[github.com/masriyan/semar](https://github.com/masriyan/semar)**
