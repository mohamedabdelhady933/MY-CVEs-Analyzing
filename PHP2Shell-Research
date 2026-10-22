# Remote Code Execution (RCE) Vulnerability in Core PHP — "PHP2Shell" [php/php-src](https://github.com/php/php-src)



| Field | Details |
|---|---|
| **Affected Software** | PHP core engine — every PHP version released in the last decade, back to PHP 5.4 (supported branches 8.2 / 8.3 / 8.4 / 8.5 unpatched; < 8.2 is EOL with no upstream patch) |
| **Vendor** | The PHP Group (php.net) |
| **Repository** | [php/php-src](https://github.com/php/php-src) |
| **Vulnerability Type** | Memory-safety bugs in the core PHP engine → unauthenticated Remote Code Execution (RCE) + remote process-memory disclosure |
| **Severity** | Critical (CVSS up to 9.2) |
| **CVE IDs** | CVE-2026-109618 · CVE-2026-109619 |
| **GHSA IDs** | GHSA-w8hw-w9fx-j79w · GHSA-6wmf-4rv5-p3rp |
| **Attack Vector** | Network (unauthenticated remote) |
| **Fixed Versions** | PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| **Patch Date** | October 21, 2026 |
| **Public Disclosure** | October 21, 2026 |

---

## Executive Summary

Wiz Research uncovered multiple critical vulnerabilities in core PHP, a popular general-purpose scripting language that powers roughly 70% of all websites in the world (WordPress, Joomla, Drupal, Wikipedia's MediaWiki, and countless others). Successful exploitation could allow attackers to take control of affected servers, steal sensitive data, and deface the websites running on them.

These vulnerabilities live **in PHP itself, independent of the application running on top of it**, putting every affected website at immediate risk even when its own application code is secure. Every PHP version released in the last decade is affected by at least one of these issues, going back to PHP 5.4. Attackers can exploit them remotely, without authentication.

The flaws are memory-safety issues rooted in how PHP handles fatal errors while processing requests — particularly out-of-memory (OOM) errors during multipart/request startup and Session upload-progress handling. A fatal error can interrupt request processing, destroy the request heap, and leave corrupted internal PHP state behind. A later request handled by the same worker reuses that stale state, leading to memory disclosure or memory corruption that can be developed into unauthenticated remote code execution.

On October 21, 2026, PHP released the patch fixing multiple memory-safety vulnerabilities in the core engine. Wiz Research combined the exploitable bugs into a single exploit capability dubbed **php2shell** and demonstrated unauthenticated pre-authentication RCE on WordPress, Drupal, and Joomla (latest container images), plus application-agnostic remote memory disclosure of PHP worker memory (which may contain passwords, authentication tokens, API keys, and certificates belonging to other requests or the server itself).

The discovery was made with frontier AI assistance (Wiz Atlas, Gemini 4 Argon, GPT-5.6 Sol) — AI made it practical to chain multiple long-standing flaws and adapt the exploit to different PHP versions, configurations, and memory layouts, turning a decade-old flaw into a working exploit. The work was coordinated with the PHP team, Calif, and OpenAI prior to public disclosure.

---

## Technical Description

The vulnerabilities all stem from key architecture decisions made over a decade ago in the PHP engine. They are grouped under two CVEs:

| Tracking ID | Bug | What an attacker can achieve | What was demonstrated |
|---|---|---|---|
| **CVE-2026-109618** | Upload-progress unserializer use-after-free | Corrupt process memory and execute code; unauthenticated disclosure of PHP worker memory | Pre-auth RCE on WordPress, Drupal, Joomla; application-agnostic remote memory disclosure |
| **CVE-2026-109619** | Fatal-error backtrace use-after-free / OPcache type confusion | Corrupt process memory and execute code; corrupt shared PHP state and execute code | Pre-auth RCE on Drupal; pre-auth RCE on WordPress |

While only four instances are detailed below, there are other tracked (and likely untracked) variants of this same pattern in the PHP codebase. The PHP patch fixes the issue at its core and eliminates all variants in the patched release.

### Entry Point

The vulnerable code is in PHP's core engine request-processing path, **not** in any application-layer endpoint. Exploitation does not require WordPress, Drupal, Joomla, or any specific CMS — even a simple "Hello World" application running on an affected PHP version is vulnerable.

The relevant request-processing surfaces:

1. **RFC1867 multipart request parsing** during request startup, *before* normal module initialization completes. Session upload-progress handling can initialize Session state at this early stage and publish a session ID in `PS(id)`.
2. **Session module unserializer** (`BG(unserialize)`), which stores request-owned bookkeeping during upload-progress handling in the same pre-initialization window.
3. **Executor globals** — `EG(last_fatal_error_backtrace)`, which retains the backtrace of the most recent fatal error.
4. **OPcache** — compiled PHP structures persisted in shared memory with per-worker runtime-pointer maps (`CG(map_ptr_last)` frontier).

### Bug 1: Upload-progress unserializer use-after-free (CVE-2026-109618)

PHP's Session module can decode session data during upload-progress handling in the pre-initialization window. The decoder stores request-owned bookkeeping in `BG(unserialize)`. A fatal allocation failure (OOM) can interrupt this path, destroy the request heap, and leave the unserializer's global state published.

On a later request handled by the same worker, PHP can consume attacker-reclaimed memory as live unserializer bookkeeping. The stale state becomes a powerful memory-corruption primitive. Combined with the memory disclosure (below) to remove address uncertainty, this yields unauthenticated remote code execution on WordPress, Drupal, and Joomla.

### Bug 2: Remote process-memory disclosure (CVE-2026-109618)

PHP parses RFC1867 multipart requests during request startup, before normal module initialization completes. Session upload-progress handling can initialize Session state at this early stage and publish a session ID in `PS(id)`. An out-of-memory error can abort the request before cleanup completes. PHP then destroys the request heap and may leave `PS(id)` pointing to the freed allocation.

A later multipart request handled by the same worker can reach the upload-progress cleanup path before normal Session initialization resets that pointer. PHP trusts the stale pointer and length as a live `zend_string` and URL-encodes the reclaimed heap contents into a `PHPSESSID` response cookie. The attack works even when the application never calls `session_start()`, making the issue application-agnostic. Wiz demonstrated unauthenticated disclosure of an attacker-sized region of live worker memory containing data from outside the attacker's request.

### Bug 3: Fatal-error backtrace use-after-free (CVE-2026-109619)

In affected versions, PHP retains the backtrace of the most recent fatal error in `EG(last_fatal_error_backtrace)`. A fatal out-of-memory error can destroy the request heap without undefining that executor-global value. The worker survives with a global that still points to memory from the previous request.

If the same worker emits a diagnostic early in the next request, it can access the pointer before the executor reinitializes that state. PHP then destroys or updates the dangling backtrace and follows attacker-reclaimed memory. The resulting cross-request use-after-free can be developed into controlled memory corruption. Wiz demonstrated unauthenticated remote code execution against Drupal using this primitive.

### Bug 4: OPcache type confusion (CVE-2026-109619)

OPcache persists compiled PHP structures in shared memory and assigns indices into per-worker runtime-pointer maps. Workers coordinate those indices through a shared frontier. During `zend_accel_script_persist()`, PHP advances the process-local `CG(map_ptr_last)` frontier, publishing the corresponding shared frontier only after persistence completes. An allocation failure between those two events leaves the process-local advance in place and partially persisted objects referring to slots that the shared state still considers available.

When another worker later reuses one of those slots for a different runtime object, stale shared metadata resolves to a pointer of the wrong type. The mismatch creates a cross-worker type confusion and corrupts shared OPcache state. Wiz used this primitive to build an unauthenticated RCE chain against WordPress.

These issues execute below the application layer, so application logs may contain little context. Until systems are patched, defenders should pay particular attention to unusual multipart requests followed by memory-limit errors or repeated HTTP 500 responses, unexpectedly large or malformed `PHPSESSID` response cookies, and unexplained PHP worker churn. Applying the PHP security update remains the only complete remediation.

---

## Proof of Concept

No public exploit code was released (responsible disclosure). Wiz Research developed the **php2shell** exploit capability internally and demonstrated it against WordPress, Drupal, and Joomla latest container images. Below is the conceptual attack flow an attacker would follow against a target running an unpatched PHP version with persistent workers (e.g., PHP-FPM or mod_php):

### Step 1 — Trigger an OOM fatal error during request startup

Send a crafted multipart/form-data request (large number of parts / large bodies) designed to exhaust `memory_limit` while PHP parses the request during startup and initializes Session/upload-progress state before normal module initialization completes.

### Step 2 — Leave corrupted/stale engine state on the worker

The OOM aborts the request before cleanup completes, destroying the request heap while leaving published global state dangling:
- `BG(unserialize)` bookkeeping (CVE-2026-109618), or
- `EG(last_fatal_error_backtrace)` pointer (CVE-2026-109619), or
- OPcache shared-map frontier inconsistency (CVE-2026-109619).

The worker survives with globals that still point to freed memory from the previous request.

### Step 3 — Reuse attacker-controlled memory on a second request

Send a second request handled by the same persistent worker. PHP consumes attacker-reclaimed memory as live internal engine state (unserializer bookkeeping, backtrace pointer, or OPcache type metadata), producing controlled memory corruption / type confusion.

### Step 4 — Achieve unauthenticated remote code execution

With memory disclosure to defeat ASLR (via the `PHPSESSID` cookie leak), combine the corruption primitive into a working RCE chain executing arbitrary code in the PHP worker process context — effectively full compromise of the web server.

> **Note:** Exploitation depends on the target's PHP version, configuration (`memory_limit`, `post_max_size`, `max_input_vars`), SAPI/worker model (persistent workers such as FPM/mod_php are far more exposed than per-request CGI), and memory layout. An exploit that works against one deployment may require adjustment for another. The JoasASantos `php2shell-scanner` provides a non-destructive version-based detection strategy (with an opt-in `--probe` mode that may cause DoS — authorized use only).

---

## Root Cause

The core issue is a set of memory-safety flaws in how PHP handles fatal errors (especially out-of-memory errors) while processing requests:

- Bugs leave a **corrupted internal PHP state behind** after a request ends unexpectedly (use-after-free of `BG(unserialize)`, `EG(last_fatal_error_backtrace)`, and OPcache shared-map frontier inconsistency).
- A **later request or worker reuses that stale state** as live engine state, leading to memory disclosure (`PHPSESSID` cookie leaking worker heap contents) or controlled memory corruption / type confusion → RCE.

The vulnerable code had been present for **more than a decade** (since the PHP 5.4 era). It remained unaddressed because vulnerability discovery and exploitation were incredibly complex — chaining multiple bugs and adapting to each target's memory layout required world-class reverse-engineering effort. Frontier AI models (Gemini 4 Argon, GPT-5.6 Sol via Wiz Atlas) substantially reduced that barrier, making the exploit practical to develop and adapt across targets in hours rather than months.

Root locations (indicative, based on public advisories and analysis):
- `ext/session/` — upload-progress unserializer state (`BG(unserialize)`, `PS(id)`)
- `Zend/zend_execute.h` / executor globals — `EG(last_fatal_error_backtrace)`
- `ext/opcache/ZendAccelerator.c` / `zend_accel_script_persist()` — `CG(map_ptr_last)` shared frontier

---

## Impact

Successful exploitation of these vulnerabilities may allow an attacker to:

- Execute arbitrary code remotely **without authentication** on the web server (pre-auth RCE)
- Achieve **full compromise** of the underlying host
- Read sensitive data from the PHP process's memory without achieving RCE — including passwords, authentication tokens, API keys, and certificates belonging to other requests or the server itself (Heartbleed-style memory disclosure)
- Compromise confidentiality, integrity, and availability of affected systems
- Attack any PHP-powered application regardless of the application's own security — WordPress, Joomla, Drupal, MediaWiki, and custom PHP apps are all equally exposed because the flaw is in the engine itself

With roughly 70% of the Internet running PHP, the exposure is massive. The vulnerabilities are application-agnostic: WAFs and application-layer hardening do not remove the risk; only patching PHP does.

---

## Recommended Remediation

| # | Recommendation | Priority |
|---|---|---|
| 1 | **Update PHP immediately** to the patched releases: 8.2.35, 8.3.36, 8.4.27, or 8.5.12 (or the latest patched build from your OS vendor). This is the only complete remediation. | Critical |
| 2 | For PHP < 8.2 (EOL, no upstream patch), upgrade to a supported branch or apply your distribution's backported security patch; verify via the package changelog/OSV, not just the version number. | Critical |
| 3 | Deploy WAF/edge rules (Cloudflare, Fastly, Akamai, Imperva, Vercel, etc.) offering out-of-the-box PHP2Shell protection if patching cannot be applied immediately. | High |
| 4 | Restrict multipart request size (`post_max_size`, `max_input_vars`, `memory_limit`) to shrink the OOM attack surface for CVE-2026-109618. | Medium |
| 5 | Monitor for unusual multipart requests followed by memory-limit errors, repeated HTTP 500s, large/malformed `PHPSESSID` cookies, and unexplained PHP worker churn. | Medium |
| 6 | Scan internet-facing assets for vulnerable PHP versions using a non-destructive version-based scanner (e.g., JoasASantos `php2shell-scanner`) with banner/phpinfo/version-leak fingerprinting; verify findings before reporting (banner may belong to a CDN/WAF edge, distro backports may fix without a version bump). | Medium |

---

## Detection

The community scanner **php2shell-scanner** (JoasASantos) provides non-destructive detection of CVE-2026-109618 / CVE-2026-109619:

- **LOCAL** — `php -v` / `php -i` for exact runtime version (max precision)
- **REMOTE** — version fingerprint via `X-Powered-By` / `Server` headers and exposed `phpinfo()` files
- **PRESENCE** — PHP detection without version (PHPSESSID cookie, `.php` references, redirects)
- **BANNER** — robust raw-socket banner grab (HEAD/GET/OPTIONS + malformed probe over HTTP/HTTPS, error-page disclosure)
- **RECON** — subdomain enumeration via crt.sh (Certificate Transparency) with subfinder fallback/merge, then fan-out scan
- **PROBE** (opt-in) — large multipart requests to observe worker instability; may cause DoS — authorized use only

Fixed-version table (matches php-src advisories exactly):

| Branch | Affected | Fixed |
|---|---|---|
| 8.2 | < 8.2.35 | 8.2.35 |
| 8.3 | < 8.3.36 | 8.3.36 |
| 8.4 | < 8.4.27 | 8.4.27 |
| 8.5 | < 8.5.12 | 8.5.12 |
| < 8.2 | EOL — no upstream patch | check distro/OSV backport |

Confidence grades: HIGH (phpinfo() or PHP error page / origin), MEDIUM (HTTP banner or threat-intel banner), LOW (inference only, behind proxy, or distro backport may apply).

Scanner: https://github.com/JoasASantos/php2shell-scanner

---

## Vulnerable Code Reference

- PHP security advisories (published 2026-10-21, Critical, by bukka):
  - CVE-2026-109618 — GHSA-w8hw-w9fx-j79w: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
  - CVE-2026-109619 — GHSA-6wmf-4rv5-p3rp: https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- PHP release announcement: https://www.php.net/archive/2026.php#2026-10-21-5
- Wiz Research blog — "PHP2Shell: AI uncovers critical RCE vulnerabilities affecting 70% of the Internet": https://www.wiz.io/blog/php2shell-php-rce
- Non-destructive scanner: https://github.com/JoasASantos/php2shell-scanner
- Calif writeup: https://calif.io/php2shell/
- PHP Foundation post: https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/

---

## Responsible Disclosure Timeline

| Date | Event |
|---|---|
| August 19, 2026 | Wiz Research discovers the first PHP vulnerability (with Wiz Atlas, Gemini 4 Argon, GPT-5.6 Sol) |
| August 20, 2026 | Unauthenticated RCE confirmed against Drupal |
| August 21, 2026 | Unauthenticated RCE confirmed against WordPress |
| August 24, 2026 | Wiz Research reports the vulnerabilities to the PHP security team |
| September 21, 2026 | PHP acknowledges the reports and begins developing a coordinated fix |
| October 21, 2026 | Patched PHP releases become available; public disclosure |

---

**Authorization note:** This report is for authorized security assessment and defensive remediation purposes only. Testing against assets you do not own or have explicit permission to test is prohibited. The `--probe` mode of the scanner may cause denial of service and must only be used with explicit authorization.
