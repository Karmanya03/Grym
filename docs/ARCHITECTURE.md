# GRYM Architecture

This document is the deep dive. If the README is the movie trailer, this is the director's commentary, the storyboards, and the safety manual all in one. We will walk through the high-level system, the workspace layout, the Scope Guard lifecycle, the scanner pipeline, the browser extension, the AI agent boundary, and the rules that keep the whole thing from turning into a liability.

---

## Table of contents

1. [Guiding principles](#guiding-principles)
2. [High-level system architecture](#high-level-system-architecture)
3. [Workspace crate dependency map](#workspace-crate-dependency-map)
4. [The Scope Guard lifecycle](#the-scope-guard-lifecycle)
5. [Scanner pipeline](#scanner-pipeline)
6. [Browser extension data flow](#browser-extension-data-flow)
7. [CVE intelligence, exploit generation, and prediction](#cve-intelligence-exploit-generation-and-prediction)
8. [AI agent boundary](#ai-agent-boundary)
9. [Core data model](#core-data-model)
10. [Module boundaries and extension rules](#module-boundaries-and-extension-rules)
11. [Implementation status](#implementation-status)

---

## Guiding principles

GRYM is built around five non-negotiable ideas. Break any of them and the architecture has failed.

1. **Fail-closed by default.** If there is any doubt about whether a request is allowed, it is denied. Doubt includes malformed scope, missing attestation, audit-write failure, and expired windows.
2. **Scope is code, not documentation.** The policy is parsed from a typed file and enforced by `grym_core::ScopedClient`. Operators cannot accidentally disable it with a CLI flag.
3. **Attestation is an action, not a setting.** Active techniques require a typed, in-memory authorization phrase. It cannot be committed to a config file.
4. **Defense in depth.** Rate limits, circuit breakers, redirect re-authorization, and evidence redaction are mandatory, not optional.
5. **Clean module boundaries.** Module crates depend on `grym-core`. They do not talk to the network directly, they do not use `unsafe`, and they do not hardcode taxonomies.

Think of `grym-core` as the nightclub bouncer and the module crates as the party guests. Everyone gets ID-checked at the door, everyone is on the list, and nobody is allowed to sneak in through the kitchen.

---

## High-level system architecture

```mermaid
flowchart TB
    subgraph user["User-facing surfaces"]
        CLI["grym CLI"]
        TUI["grym-tui"]
        POPUP["Extension popup"]
        DASH["Extension dashboard"]
    end

    subgraph api["API layer"]
        SERVE["grym serve<br/>Axum HTTP server"]
    end

    subgraph core["GRYM core"]
        SCOPE["Scope Guard<br/>policy + attestation"]
        RATE["Rate limiter"]
        CB["Circuit breaker"]
        AUDIT["Audit logger"]
        REDACT["Redaction engine"]
        CLIENT["ScopedClient"]
    end

    subgraph modules["Scanner modules"]
        WEB["grym-web-scanner"]
        CVE["grym-cve-intel"]
        RECON["grym-recon-*"]
        BIN["grym-binary-analysis"]
        MOB["grym-mobile-analysis"]
        AGENT["grym-ai-agent"]
    end

    subgraph data["Data and reporting"]
        STORE["grym-storage"]
        REPORT["grym-report"]
        DASHBOARD["grym-dashboard"]
    end

    CLI --> CLIENT
    TUI --> CLIENT
    POPUP --> SERVE
    DASH --> SERVE
    SERVE --> SCOPE
    SCOPE --> RATE --> CB --> CLIENT
    CLIENT --> AUDIT
    CLIENT --> REDACT
    CLIENT --> WEB
    CLIENT --> CVE
    CLIENT --> RECON
    CLIENT --> BIN
    CLIENT --> MOB
    CLIENT --> AGENT
    WEB --> STORE
    CVE --> STORE
    AGENT --> STORE
    STORE --> REPORT
    STORE --> DASHBOARD
```

The diagram shows the separation of concerns: interfaces never touch the network directly, the core owns authorization and transport, modules own detection logic, the AI agent owns reasoning, and storage/reporting crates own persistence and presentation.

---

## Workspace crate dependency map

```mermaid
graph TD
    CLI["grym-cli"] --> CORE["grym-core"]
    CLI --> WEB["grym-web-scanner"]
    CLI --> CVE["grym-cve-intel"]
    CLI --> RP["grym-recon-passive"]
    CLI --> RA["grym-recon-active"]
    CLI --> STORE["grym-storage"]
    CLI --> REPORT["grym-report"]
    CLI --> AGENT["grym-ai-agent"]

    TUI["grym-tui"] --> CORE
    TUI --> STORE

    WEB --> CORE
    WEB --> TEMPLATE["grym-template-engine"]

    CVE --> CORE
    RP --> CORE
    RA --> CORE
    BIN["grym-binary-analysis"] --> CORE
    MOB["grym-mobile-analysis"] --> CORE
    FUZZ["grym-fuzz-harness"] --> CORE
    OOB["grym-oob-server"] --> CORE
    STEALTH["grym-stealth"] --> CORE
    PLUGIN["grym-plugin-runtime"] --> CORE
    DASHBOARD["grym-dashboard"] --> CORE
    DASHBOARD --> STORE
    AGENT --> CORE
    AGENT --> CVE
    AGENT --> WEB
    AGENT --> BIN

    STORE --> CORE
    REPORT --> CORE
    REPORT --> STORE

    XTASK["xtask"] --> CORE
```

A few things to notice:

- Every module crate eventually depends on `grym-core`. No module crate depends on another module crate.
- `grym-cli` and `grym-tui` are thin shells. They orchestrate; they do not implement detection.
- `grym-template-engine` is a pure data crate. It knows how to match signatures, not how to fetch them.
- `grym-ai-agent` depends on several module crates but only through their public, safe interfaces. It never talks to the network directly.
- `xtask` is the build-automation crate and only touches stable public interfaces.

---

## The Scope Guard lifecycle

The Scope Guard is the load-bearing safety component. The following diagram shows every decision point an outbound request must survive before it is allowed to leave the process.

```mermaid
flowchart TD
    START(["Request submitted"]) --> PARSE["Parse target URL"]
    PARSE --> VALID["URL is valid and has a scheme/host?"]
    VALID -->|No| DENY["Deny + audit"]
    VALID -->|Yes| WINDOW["Inside engagement window?"]
    WINDOW -->|No| DENY
    WINDOW -->|Yes| DENY_RULE["Matches any deny rule?"]
    DENY_RULE -->|Yes| DENY
    DENY_RULE -->|No| ALLOW["Matches an allow rule?"]
    ALLOW -->|No| DENY
    ALLOW -->|Yes| TIER["Technique tier allowed<br/>for this scope?"]
    TIER -->|No| DENY
    TIER -->|Yes| ATTEST["Active technique requires attestation?<br/>Is attestation present and valid?"]
    ATTEST -->|No| DENY
    ATTEST -->|Yes| RATE["Rate limiter allows?"]
    RATE -->|No| DENY
    RATE -->|Yes| CB["Circuit breaker closed?"]
    CB -->|No| DENY
    CB -->|Yes| SEND["Send request via underlying client"]
    SEND --> RESP["Receive response"]
    RESP --> REDIR["Is it a redirect?"]
    REDIR -->|Yes| PARSE
    REDIR -->|No| AUDIT["Write audit record"]
    AUDIT -->|Write fails| DENY
    AUDIT -->|Success| REDACT["Redact secrets from evidence"]
    REDACT --> RETURN["Return response to caller"]
    DENY --> AUDIT
    RETURN --> DONE(["Done"])
    DENY --> DONE
```

Key details:

- **Deny-first.** Deny rules are evaluated before allow rules. A target on the deny list is rejected even if it also matches an allow rule.
- **Engagement window.** Scopes have a start and end time. Outside that window, every request is denied.
- **Technique tiers.** Passive fingerprinting, standard detection, active validation, and exploitation are separate tiers. Higher tiers require higher authorization.
- **Typed attestation.** For active techniques, the operator must supply the exact in-memory phrase `I CONFIRM AUTHORIZATION FOR <ENGAGEMENT_ID>`. It cannot be in a file or environment variable.
- **Redirect re-authorization.** Redirects are disabled in the underlying HTTP client. When a redirect is returned, the target URL is parsed and run through the entire lifecycle again.
- **Audit-write failure is denial.** If the audit record cannot be written, the action fails closed.
- **Redaction.** Secrets in URL query parameters and response bodies are redacted before the response is returned to the caller or stored.

---

## Scanner pipeline

```mermaid
flowchart LR
    INPUT(["Target URL + selected modules"]) --> ROUTER["Module router"]
    ROUTER --> MOD1["SQLi module"]
    ROUTER --> MOD2["XSS module"]
    ROUTER --> MOD3["SSTI module"]
    ROUTER --> MODn["... other modules"]

    MOD1 --> CLIENT1["ScopedClient request"]
    MOD2 --> CLIENT2["ScopedClient request"]
    MOD3 --> CLIENT3["ScopedClient request"]
    MODn --> CLIENTn["ScopedClient request"]

    CLIENT1 --> RESP1["Response + signature match"]
    CLIENT2 --> RESP2["Response + signature match"]
    CLIENT3 --> RESP3["Response + signature match"]
    CLIENTn --> RESPn["Response + signature match"]

    RESP1 --> FINDING["Finding objects"]
    RESP2 --> FINDING
    RESP3 --> FINDING
    RESPn --> FINDING

    FINDING --> CHAIN["Chain builder"]
    CHAIN --> STORE[("Finding store")]
    STORE --> REPORT["Report generator"]
    STORE --> DASH["Dashboard / TUI"]
```

The scanner is deliberately modular:

- Each module is independent. A failure in one module does not stop the others.
- Every module uses `ScopedClient` for every request. There is no back-channel.
- Modules return `Vec<Finding>`. A finding is a plain data struct with severity, confidence, evidence, and remediation.
- The chain builder consumes findings and proposes multi-step attack chains mapped to MITRE ATT&CK techniques.
- Findings are stored, then rendered by report and dashboard crates.

---

## Browser extension data flow

```mermaid
sequenceDiagram
    actor U as User
    participant P as Extension popup
    participant D as Extension dashboard
    participant C as Content script
    participant S as Service worker
    participant API as grym serve
    participant CORE as Scope Guard + modules

    U->>P: Enter target, click Scan
    P->>S: Post scan request
    S->>API: POST /scan
    API->>CORE: Run selected modules
    CORE-->>API: Findings JSON
    API-->>S: Findings JSON
    S-->>D: Render findings
    D-->>U: Display results

    U->>D: Switch to CVE DB tab
    D->>S: Request CVE list
    S->>API: GET /cve-db
    API->>CORE: Query CVE database
    CORE-->>API: CVE entries
    API-->>S: CVE entries
    S-->>D: Render table

    U->>C: Browse target page
    C->>C: Detect technologies, secrets, forms
    C->>S: Page metadata
    S->>API: POST /cve-lookup
    API->>CORE: Correlate fingerprint
    CORE-->>API: Matching CVEs
    API-->>S: Matching CVEs
    S-->>D: Highlight matches
```

The extension never performs active exploitation itself. It is a polished remote control for the local `grym serve` process. Because the server enables CORS, the dashboard can call it directly from a `chrome-extension://` origin, but all network traffic still goes through the Scope Guard.

---

## CVE intelligence, exploit generation, and prediction

```mermaid
flowchart TB
    subgraph input["Input"]
        FINGER["Component fingerprint"]
        VERSION["Version string"]
        BODY["Response body"]
    end

    subgraph cve["CVE intelligence"]
        DB[("CVE database<br/>525+ entries")]
        LOOKUP["Correlation engine"]
    end

    subgraph exploit["Exploit generation"]
        GEN["PoC generator"]
        FORMATS["Output formats:<br/>Python, Go, Rust, curl, Bash,<br/>PowerShell, Nuclei, Metasploit,<br/>Node.js, Java, PHP, HTTPie,<br/>Burp Intruder, Ruby, Perl,<br/>Lua, C#"]
    end

    subgraph predict["Zero-day prediction"]
        HIST["Component history"]
        CWE["CWE pattern database"]
        SCORE["Risk scorer"]
    end

    FINGER --> LOOKUP
    VERSION --> LOOKUP
    LOOKUP --> DB
    DB --> KNOWN["Known CVEs"]
    KNOWN --> GEN
    GEN --> FORMATS

    FINGER --> HIST
    VERSION --> HIST
    BODY --> CWE
    HIST --> SCORE
    CWE --> SCORE
    SCORE --> RISK["Zero-day risk score"]
```

The intelligence subsystem is split into three responsibilities:

- **CVE lookup.** Given a technology fingerprint and version, return matching CVEs with signatures, CVSS, and remediation.
- **Exploit generation.** Given a CVE, emit a safe, local PoC in the requested format. This is source code, not a remote payload. It is up to the operator to use it only inside the authorized scope.
- **Zero-day prediction.** Mine historical patterns and CWE correlations to estimate how likely a component/version is to have an unpatched vulnerability class. This is research-grade inference, not magic.

---

## AI agent boundary

`grym-ai-agent` adds autonomous reasoning on top of the same safe boundaries.

```mermaid
flowchart LR
    subgraph input["Agent input"]
        QUERY["User query / target description"]
        SESSION["Session store"]
    end

    subgraph agent["grym-ai-agent"]
        REASON["Reasoning loop"]
        TOOLS["Tool registry"]
        HUNT["CVE hunter"]
    end

    subgraph core["Core enforcement"]
        SCOPE["Scope Guard"]
        CLIENT["ScopedClient"]
    end

    QUERY --> REASON
    SESSION --> REASON
    REASON --> TOOLS
    REASON --> HUNT
    TOOLS --> SCOPE
    HUNT --> SCOPE
    SCOPE --> CLIENT
```

Key points:

- The agent never holds a raw HTTP client. When it needs network data, it calls a tool that routes through `ScopedClient`.
- The tool registry is explicit. Adding a new capability means adding a typed tool, not giving the model an open socket.
- Sessions are bounded and evicted by age/count. The agent cannot accumulate infinite state.
- The CVE hunter generates hypotheses and PoC templates, but the actual execution is delegated to the scanner modules under the same scope rules.

---

## Core data model

```mermaid
classDiagram
    class Finding {
        +String id
        +String url
        +String title
        +String severity
        +String confidence
        +String module
        +String description
        +String evidence
        +String remediation
        +Vec~String~ tags
    }

    class Scope {
        +String engagement_id
        +DateTimeUtc start
        +DateTimeUtc end
        +Vec~Rule~ allow
        +Vec~Rule~ deny
        +TechniqueTier max_tier
        +bool authorization_attested
        +RateLimit rate_limit
        +CircuitBreakerConfig cb_config
    }

    class ScopedClient {
        +Scope scope
        +AuditLog audit
        +RateLimiter limiter
        +CircuitBreaker breaker
        +Redactor redactor
        +get(module, url, tier)
        +post(module, url, body, tier)
    }

    class CveEntry {
        +String cve_id
        +String name
        +String affected_component
        +Vec~String~ affected_versions
        +f32 cvss_score
        +Vec~String~ detection_signatures
        +Vec~String~ payload_examples
        +String remediation
    }

    class Exploit {
        +Option~String~ cve_id
        +String format
        +String code
        +String usage
        +Vec~String~ dependencies
        +String risk_level
    }

    Finding --> ScopedClient : produced by
    ScopedClient --> Scope : enforces
    CveEntry --> Finding : correlated to
    Exploit --> CveEntry : generated from
```

The data model is intentionally boring. Findings are plain structs so they can be serialized, stored, and reported without pulling in scanner logic. The `ScopedClient` owns the dangerous state and is the only thing allowed to talk to the network.

---

## Module boundaries and extension rules

If you add a crate or a module, follow these rules. They are not suggestions.

1. **Module crates depend on `grym-core`.** They do not depend on other module crates. If two modules need shared logic, put it in `grym-core` or create a utility crate that does not touch the network.
2. **No raw network clients.** Do not import `reqwest`, `hyper`, `ureq`, `std::net::TcpStream`, or browser networking APIs inside module crates. Route everything through `ScopedClient`.
3. **`unsafe` is forbidden.** The workspace lint denies `unsafe_code`. If you think you need it, open an issue first and prepare a very strong argument.
4. **No `unwrap`, `expect`, `panic`, `todo`, or `unimplemented`.** Use proper error types and propagate them.
5. **Detection is non-destructive by default.** A module that actively mutates state belongs behind the explicit technique-tier and attestation APIs.
6. **Taxonomies live in mapping packs.** Do not hardcode category strings in scanner logic. If a new vulnerability class is added, it is added to the mapping pack and the scanner consumes it.
7. **Evidence is redacted before storage.** If your module captures a response, run it through the redactor before returning it.
8. **Tests are mandatory.** Every scope decision path and every detection heuristic needs deterministic tests. A regression that expands scope is a release blocker.

---

## Implementation status

### Implemented now

- Phase 0 scope schema, typed attestation gate, deny-first policy evaluation, structured audit trail, bounded scoped HTTP, rate limits, and circuit breaker.
- `grym-cli` with `scope validate`, `scope show`, and `serve`.
- `grym-web-scanner` with 20+ detection modules, fuzzer, chain builder, 525+ entry CVE DB, exploit generator, and payload generator.
- `grym-cve-intel` with zero-day prediction engine and response-body analysis.
- `grym-tui` with dashboard, scanner, findings, logs, and config tabs; full mouse support and a scrollable help overlay.
- Cross-browser Manifest V3 extension in `browser-ext/` with GRYM logo icons.
- `grym-ai-agent` with session management, tool registry, and autonomous CVE hunting.
- Versioned mapping packs, safe signature-template parsing, and fixture definitions.
- Cross-platform CI configuration, editor setup, dependency-policy configuration, and mapping validation.

### Planned behind the established interfaces

- Actual DNS/CT collection, port scanning, and crawling.
- OOB server listener with correlation IDs.
- Live CVE feed adapters and automated enrichment.
- Binary and mobile parser backends.
- Durable `redb` storage, PDF/SARIF reporting, and WASM plugin host.
- Scheduled dashboard jobs and long-running campaign orchestration.

---

**In short:** interfaces ask, the core decides, modules detect, the agent reasons, storage remembers, and the Scope Guard keeps everyone honest. Build accordingly.
