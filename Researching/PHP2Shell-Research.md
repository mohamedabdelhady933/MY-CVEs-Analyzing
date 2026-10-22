# Remote Code Execution (RCE) in the Core PHP Engine  "PHP2Shell" [php/php-src](https://github.com/php/php-src)



| Field | Details |
|---|---|
| **Affected Software** | PHP core engine  all releases from the past ten years, back to PHP 5.4 (supported branches 8.2 / 8.3 / 8.4 / 8.5 without the fix; releases below 8.2 are end-of-life with no upstream patch) |
| **Vendor** | The PHP Group (php.net) |
| **Repository** | [php/php-src](https://github.com/php/php-src) |
| **Vulnerability Type** | Memory-safety defects in the PHP engine leading to unauthenticated remote code execution (RCE) and remote process-memory disclosure |
| **Severity** | Critical (CVSS up to 9.2) |
| **CVE IDs** | CVE-2026-109618 · CVE-2026-109619 |
| **GHSA IDs** | GHSA-w8hw-w9fx-j79w · GHSA-6wmf-4rv5-p3rp |
| **Attack Vector** | Network (unauthenticated, remote) |
| **Patched Releases** | PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| **Fix / Disclosure Date** | October 21, 2026 |

---

## Executive Summary

A set of critical memory-safety defects was discovered in the PHP runtime itself. Because the flaws sit inside the language engine rather than inside any particular application, every site running a vulnerable PHP interpreter is exposed  regardless of whether the application code on top is secure. PHP underpins a large share of the public web, including WordPress, Joomla, Drupal, and MediaWiki, so a defect in the core interpreter has wide-reaching consequences.

The defects all involve how PHP deals with fatal errors while a request is being processed, especially out-of-memory (OOM) conditions that occur during multipart request parsing and session upload-progress handling. When a fatal error interrupts a request, the engine can destroy the request heap but leave behind stale internal state. A subsequent request handled by the same worker process may then reuse that freed memory as if it were still valid, which can be turned into either a read of the worker's memory (exposing passwords, tokens, API keys, and certificates belonging to other requests) or full remote code execution without any authentication.

The research was carried out with assistance from frontier AI models, which made it practical to chain several long-standing flaws and adapt the exploit to different PHP versions and memory layouts  work that would previously have required a specialist team months of effort. The findings were disclosed through a coordinated process with the PHP team, Calif, and OpenAI, and patches shipped on October 21, 2026.

---

## Technical Description

The flaws are grouped under two CVE identifiers, but they share a common root pattern: fatal errors during request startup leave dangling engine state that a later request can abuse.

| Tracking ID | Core defect | Possible impact | Demonstrated outcome |
|---|---|---|---|
| CVE-2026-109618 | Use-after-free in the upload-progress session unserializer | Memory corruption and code execution; disclosure of worker memory | Unauthenticated RCE against WordPress, Drupal, Joomla; application-agnostic memory read |
| CVE-2026-109619 | Stale fatal-error backtrace / OPcache type confusion | Corrupt process memory and code execution; corruption of shared OPcache state | Unauthenticated RCE against Drupal; unauthenticated RCE against WordPress |

There are additional variants of the same pattern throughout the interpreter; the October 2026 patch addresses the underlying issue and covers all known variants.

### How the engine reaches the vulnerable state

The relevant code paths execute during request startup, before the application itself runs:

1. **RFC1867 multipart parsing** begins while normal module initialization is still incomplete. Session upload-progress handling can initialize session state early and expose a session identifier through `PS(id)`.
2. The **session unserializer** keeps per-request bookkeeping in `BG(unserialize)` during that same early window.
3. The **executor globals** retain the backtrace of the most recent fatal error in `EG(last_fatal_error_backtrace)`.
4. **OPcache** stores compiled structures in shared memory and tracks per-worker runtime pointers through a shared frontier (`CG(map_ptr_last)`).

### Defect 1  Upload-progress unserializer use-after-free (CVE-2026-109618)

During upload-progress handling, the session decoder stores request-owned bookkeeping in `BG(unserialize)`. If a fatal allocation failure occurs in this window, the request heap is destroyed while the unserializer's global state remains published. On a later request served by the same worker, PHP may interpret attacker-controlled reclaimed memory as live unserializer bookkeeping, producing a strong memory-corruption primitive. When paired with the memory disclosure described below to defeat address randomization, this leads to unauthenticated remote code execution.

### Defect 2  Remote process-memory disclosure (CVE-2026-109618)

Multipart requests are parsed at startup, before module initialization finishes. Session upload-progress can publish a session ID in `PS(id)` at this early stage. An OOM error can abort the request before cleanup runs, leaving `PS(id)` pointing at freed memory. A subsequent multipart request handled by the same worker can reach the upload-progress cleanup path before session state is reset; PHP trusts the stale pointer and length as a live `zend_string` and URL-encodes the reclaimed heap contents into a `PHPSESSID` response cookie. This works even if the application never calls `session_start()`, so the issue is not tied to any framework. It was demonstrated as an unauthenticated read of live worker memory containing data from outside the attacker's own request.

### Defect 3  Fatal-error backtrace use-after-free (CVE-2026-109619)

Affected PHP versions keep the backtrace of the last fatal error in `EG(last_fatal_error_backtrace)`. A fatal OOM error can destroy the request heap without clearing that executor-global value, so the worker survives holding a pointer to memory from the prior request. If the same worker emits a diagnostic early in the next request, it can dereference the dangling pointer before the executor reinitializes that state. PHP then follows attacker-reclaimed memory while updating the backtrace, yielding a cross-request use-after-free that can be developed into controlled memory corruption.

### Defect 4  OPcache type confusion (CVE-2026-109619)

OPcache persists compiled PHP structures in shared memory and assigns indices into per-worker runtime-pointer maps, coordinated through a shared frontier. During `zend_accel_script_persist()`, the process-local `CG(map_ptr_last)` frontier advances, while the shared frontier is published only after persistence finishes. An allocation failure between those two events leaves the local advance in place and partially persisted objects referring to slots the shared state still considers free. When another worker later reuses such a slot for a different runtime object, stale shared metadata resolves to a pointer of the wrong type  a cross-worker type confusion that corrupts shared OPcache state.

These defects operate below the application layer, so application logs may show little useful context. Until patched, defenders should watch for unusual multipart requests followed by memory-limit errors, repeated HTTP 500 responses, oversized or malformed `PHPSESSID` cookies, and unexpected PHP worker restarts. The only complete fix is updating the interpreter.

---

## Proof of Concept

No public exploit code was released; the research team developed the capability internally (referred to as php2shell) and demonstrated it against the latest WordPress, Drupal, and Joomla container images. The conceptual attack flow against an unpatched interpreter using persistent workers (e.g., PHP-FPM or mod_php) is:

### Step 1  Exhaust memory during request startup

Send a crafted multipart/form-data request (many parts or large bodies) designed to trigger an out-of-memory condition while PHP parses the request and initializes session/upload-progress state before normal module setup completes.

### Step 2  Leave corrupted engine state on the worker

The OOM aborts the request before cleanup, destroying the request heap while publishing dangling global state  for example `BG(unserialize)` bookkeeping, the `EG(last_fatal_error_backtrace)` pointer, or an inconsistent OPcache shared-map frontier. The worker process remains alive but holds references to freed memory.

### Step 3  Reuse attacker-controlled memory on a second request

Send a second request handled by the same persistent worker. PHP interprets attacker-reclaimed memory as live engine state (unserializer bookkeeping, backtrace pointer, or OPcache type metadata), resulting in controlled memory corruption or type confusion.

### Step 4  Execute code without authentication

Using the memory disclosure to bypass ASLR, combine the corruption primitive into a working remote code execution chain inside the PHP worker process  effectively compromising the web server.

> Exploitation depends on the PHP version, configuration (`memory_limit`, `post_max_size`, `max_input_vars`), and worker model. Persistent workers (FPM, mod_php) are far more exposed than per-request CGI, and an exploit that works on one deployment may need adjustment for another. The community scanner php2shell-scanner performs non-destructive version-based detection; its `--probe` mode can disrupt workers.

---

## Root Cause

The underlying problem is a family of memory-safety flaws in how PHP handles fatal errors  particularly out-of-memory errors  while processing a request:

- Fatal errors leave **corrupted internal engine state behind** after a request terminates unexpectedly (use-after-free of `BG(unserialize)`, `EG(last_fatal_error_backtrace)`, and OPcache shared-map frontier inconsistency).
- A **later request or worker reuses that stale state as if it were live engine state**, producing memory disclosure (the `PHPSESSID` cookie leaking worker-heap contents) or controlled memory corruption/type confusion that leads to RCE.

The vulnerable code existed for more than a decade, back to the PHP 5.4 era. It survived because turning these flaws into a working exploit required chaining multiple bugs and adapting to each target's memory layout  extremely difficult manually. Frontier AI assistance (Wiz Atlas, Gemini 4 Argon, GPT-5.6 Sol) lowered that barrier, making the exploit practical to develop and retarget across deployments.

Notable code locations (per public advisories and analysis):
- `ext/session/`  upload-progress unserializer state (`BG(unserialize)`, `PS(id)`)
- Executor globals  `EG(last_fatal_error_backtrace)`
- `ext/opcache/`  `zend_accel_script_persist()` and `CG(map_ptr_last)` shared frontier

---

## Vulnerable Code Analysis

The snippets below are simplified, representative illustrations of the vulnerable patterns. They are not verbatim copies of the PHP source, but they faithfully model the logic that leads to each defect.

### Snippet 1  Upload-progress unserializer state published before cleanup (CVE-2026-109618)

```c
/* ext/session/session.c  representative */
static int php_session_upload_progress(void)
{
    PS(id) = zend_string_init(ZSTR_VAL(tmp), ZSTR_LEN(tmp), 0);
    BG(unserialize) = &unserializer_state;  /* global bookkeeping published */

    if (php_request_startup_fails()) {      /* OOM or fatal error here */
        /* request heap destroyed, but PS(id) and BG(unserialize) remain set */
        return FAILURE;                     /* no reset of PS(id) / BG(unserialize) */
    }

    /* normal path would later reset PS(id) and clear BG(unserialize) */
    return SUCCESS;
}
```

**Analysis**

The function writes a session identifier into the executor-global `PS(id)` and publishes the unserializer's bookkeeping pointer into `BG(unserialize)` during request startup. If a fatal allocation failure interrupts processing, the request heap is destroyed, but neither `PS(id)` nor `BG(unserialize)` is cleared. The next request handled by the same worker inherits these dangling globals. PHP then treats attacker-reclaimed heap memory as live session/unserializer state, giving the attacker a controlled memory-corruption primitive. Because this runs before any application code, it is reachable without authentication and independent of the CMS or framework in use.

### Snippet 2  Memory disclosure through stale `PS(id)` into `PHPSESSID` cookie (CVE-2026-109618)

```c
/* ext/session/session.c  representative */
static void session_cleanup_on_error(void)
{
    if (PS(id) && PS(id)->len) {
        /* trusts stale pointer/length as a live zend_string */
        php_url_encode(PS(id)->val, PS(id)->len, &encoded);
        /* encoded bytes are placed into the Set-Cookie: PHPSESSID header */
        set_cookie("PHPSESSID", encoded);
        /* PS(id) is NOT reset here before the next request begins */
    }
}
```

**Analysis**

When an OOM aborts a multipart request, the cleanup path runs against a `PS(id)` that points at freed memory. The length and pointer are still those of the previous request's allocation. PHP URL-encodes whatever bytes sit at that reclaimed address and returns them inside a `PHPSESSID` response cookie. Because this occurs even when `session_start()` is never called by the application, any site on a vulnerable interpreter leaks worker-memory contents  potentially passwords, tokens, and keys belonging to other concurrent requests  through an unauthenticated cookie.

### Snippet 3  Fatal-error backtrace retained across requests (CVE-2026-109619)

```c
/* Zend/zend_execute.h / executor.c  representative */
static void zend_error_noreturn(int type, const char *format, ...)
{
    EG(last_fatal_error_backtrace) = zend_fetch_backtrace();  /* global pointer saved */

    if (EG(error_handling) == EH_FATAL && out_of_memory()) {
        destroy_request_heap();                                 /* heap freed */
        /* EG(last_fatal_error_backtrace) still points into the freed heap */
        longjmp(bailout, 1);                                    /* request ends, worker survives */
    }
}
```

**Analysis**

The executor stores a pointer to the most recent fatal error's backtrace in `EG(last_fatal_error_backtrace)`. On a fatal OOM, the request heap is destroyed, but the executor-global is left pointing at freed memory. The worker process stays alive. On the next request, if PHP emits an early diagnostic before reinitializing executor state, it dereferences the dangling backtrace pointer and follows attacker-reclaimed memory. This cross-request use-after-free can be steered into controlled memory corruption.

### Snippet 4  OPcache shared-map frontier advanced before publication (CVE-2026-109619)

```c
/* ext/opcache/ZendAccelerator.c  representative */
int zend_accel_script_persist(zend_script *script)
{
    CG(map_ptr_last)++;                     /* process-local frontier advanced */

    if (persist_partial(script)) {          /* may fail on OOM */
        /* shared frontier NOT yet published; local advance is already visible */
        return FAILURE;                     /* leaves slots marked as used locally */
    }

    publish_shared_frontier(CG(map_ptr_last)); /* shared state catches up */
    return SUCCESS;
}
```

**Analysis**

The process-local frontier `CG(map_ptr_last)` is incremented before the shared frontier is published. If persistence fails halfway (OOM), the local view believes a slot is consumed while the shared view still considers it free. A different worker may later allocate that same slot for a distinct runtime object. Stale shared metadata then resolves to a pointer of the wrong type  a cross-worker type confusion that corrupts shared OPcache state and can be leveraged for code execution.

---

## Impact

Successful exploitation may allow an attacker to:

- Execute code remotely **without authentication** on the web server (pre-authentication RCE)
- Achieve **full compromise** of the underlying host
- Read sensitive data from the PHP process memory without achieving RCE  including passwords, session tokens, API keys, and certificates belonging to other requests or the server itself
- Compromise confidentiality, integrity, and availability of affected systems
- Attack any PHP-powered application equally  WordPress, Joomla, Drupal, MediaWiki, and custom PHP apps are all exposed because the flaw is in the interpreter itself, not the application

Roughly 70% of the Internet runs PHP, so the exposure is broad. Application-layer hardening and WAF rules do not remove the risk; only patching PHP does.

---

## Recommended Remediation

| # | Recommendation | Priority |
|---|---|---|
| 1 | **Update PHP immediately** to 8.2.35, 8.3.36, 8.4.27, or 8.5.12 (or your OS vendor's latest patched build). This is the only complete remediation. | Critical |
| 2 | For PHP < 8.2 (end-of-life, no upstream patch), migrate to a supported branch or apply your distribution's backported fix; verify via the package changelog/OSV rather than relying on the version number alone. | Critical |
| 3 | Deploy WAF/edge protections (Cloudflare, Fastly, Akamai, Imperva, Vercel, etc.) if immediate patching is not possible. | High |
| 4 | Reduce the out-of-memory attack surface by tightening `post_max_size`, `max_input_vars`, and `memory_limit`. | Medium |
| 5 | Monitor for unusual multipart requests followed by memory-limit errors, repeated HTTP 500s, oversized/malformed `PHPSESSID` cookies, and unexplained worker churn. | Medium |
| 6 | Scan internet-facing assets with a non-destructive version-based scanner (e.g., php2shell-scanner) using banner, phpinfo, and version-leak fingerprinting; verify findings before reporting because a banner may belong to a CDN/WAF edge and distro backports can fix without changing the version number. | Medium |

---

## Detection

The open-source **php2shell-scanner** (JoasASantos) provides non-destructive detection of CVE-2026-109618 / CVE-2026-109619:

- **LOCAL**  `php -v` / `php -i` for exact runtime version (highest precision)
- **REMOTE**  version fingerprint from `X-Powered-By` / `Server` headers and exposed `phpinfo()` pages
- **PRESENCE**  PHP detection without a version (PHPSESSID cookie, `.php` references, redirects)
- **BANNER**  robust raw-socket banner grab (HEAD/GET/OPTIONS plus a malformed probe over HTTP/HTTPS, error-page disclosure)
- **RECON**  subdomain enumeration via crt.sh (Certificate Transparency) with subfinder fallback/merge, then fan-out scan of resolved hosts
- **PROBE** (opt-in)  large multipart requests to observe worker instability; may cause denial of service

Fixed versions per branch (matching the php-src advisories):

| Branch | Affected | Fixed |
|---|---|---|
| 8.2 | < 8.2.35 | 8.2.35 |
| 8.3 | < 8.3.36 | 8.3.36 |
| 8.4 | < 8.4.27 | 8.4.27 |
| 8.5 | < 8.5.12 | 8.5.12 |
| < 8.2 | EOL  no upstream patch | check distro/OSV backport |

Confidence grading: **HIGH** (version from phpinfo() or a PHP error page / direct origin read), **MEDIUM** (HTTP banner or threat-intel banner, may be stale), **LOW** (inference only, behind a proxy, or distro backport may apply).

Scanner: https://github.com/JoasASantos/php2shell-scanner

---

## References

- PHP source repository security advisories (published 2026-10-21, Critical):
  - CVE-2026-109618  GHSA-w8hw-w9fx-j79w: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
  - CVE-2026-109619  GHSA-6wmf-4rv5-p3rp: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- PHP security release announcement: https://www.php.net/archive/2026.php#2026-10-21-5
- Wiz Research analysis of the PHP2Shell flaws: https://www.wiz.io/blog/php2shell-php-rce
- Non-destructive detection scanner: https://github.com/JoasASantos/php2shell-scanner
- Calif write-up on the vulnerability and disclosure: https://calif.io/php2shell/
- PHP Foundation post on the security release: https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/

---

## Disclosure Timeline

| Date | Milestone |
|---|---|
| August 19, 2026 | Initial PHP vulnerability discovered (with Wiz Atlas, Gemini 4 Argon, GPT-5.6 Sol) |
| August 20, 2026 | Unauthenticated RCE confirmed against Drupal |
| August 21, 2026 | Unauthenticated RCE confirmed against WordPress |
| August 24, 2026 | Findings reported to the PHP security team |
| September 21, 2026 | PHP acknowledges the reports and begins coordinated fix development |
| October 21, 2026 | Patched PHP releases published; public disclosure |

---
