# PHP2Shell: Critical PHP Runtime Vulnerabilities Leading to Remote Code Execution

> **Report updated:** October 22, 2026  
> **Affected component:** PHP core runtime  
> **CVE IDs:** CVE-2026-109618 and CVE-2026-109619  
> **Severity:** Critical CVSS 9.2  
> **Primary remediation:** Upgrade to a fixed PHP release or install a verified vendor backport.

## 1. Vulnerability Summary

Two critical memory-safety vulnerabilities were disclosed in the PHP runtime on October 21, 2026. Tracked as **CVE-2026-109618** and **CVE-2026-109619**, the issues can allow unauthenticated remote code execution (RCE) and, in demonstrated scenarios, disclosure of process memory.

The vulnerabilities affect PHP itself rather than a specific CMS or application. Consequently, updating WordPress, Drupal, Joomla, MediaWiki, or application code alone does not remediate the underlying PHP runtime flaws. Practical exploitability depends on the PHP version, SAPI, worker lifecycle, configuration, and request-processing path.

The PHP project identifies Apache `mod_php` as the highest-risk deployment model because a demonstrated exploit can trigger the vulnerable path before application code runs. The PHP project's advisory also lists other web-serving SAPIs, including PHP-FPM, `php-cgi`, FrankenPHP, and LiteSpeed, as potentially at risk.

**Fixed upstream releases:**

| PHP branch | Fixed release |
|---|---:|
| PHP 8.5.x | 8.5.12 |
| PHP 8.4.x | 8.4.27 |
| PHP 8.3.x | 8.3.36 |
| PHP 8.2.x | 8.2.35 |
| PHP 8.1 and earlier | End of upstream support; check distribution/vendor backports or upgrade |

The PHP project states that updating is the only complete remediation. Temporary configuration and edge protections can reduce exposure to specific paths but do not make an unpatched installation fully safe.

## 2. CVE Overview

| CVE | Core issue described by the PHP project | Demonstrated impact and scope |
|---|---|---|
| **CVE-2026-109618** | Out-of-memory (OOM) handling can interrupt request processing while internal request data is only partially initialized. Cleanup may subsequently treat invalid or uninitialized data as valid. | The published research demonstrates unauthenticated RCE against specific WordPress, Drupal, and Joomla container images using `mod_php`, as well as application-agnostic process-memory disclosure. The PHP advisory distinguishes this from the early-startup path that does not persist in the same way under FPM. |
| **CVE-2026-109619** | Request-owned internal state can remain referenced after the backing memory has been freed. A later request handled by the same worker may use that stale state before normal initialization resets it. | Published research describes confirmed RCE paths involving fatal-error backtrace state and the session upload-progress lifecycle. The advisory describes conditions under which the session-lifecycle path can affect both `mod_php` and PHP-FPM. |

These are related but distinct vulnerabilities. Do not assume that every exploit primitive, memory-disclosure result, or worker-model behavior applies identically to both CVEs.

## 3. Technical Description

### 3.1 CVE-2026-109618 Out-of-memory handling and invalid request state

PHP enforces its configured `memory_limit`. In the vulnerable code path, an out-of-memory condition can interrupt execution while request-related internal data is only partially initialized. Subsequent cleanup may treat that state as valid, creating a memory-safety failure.

The PHP project describes a fix that changes how OOM conditions are handled in the affected path: a soft OOM is deferred to a VM safe point, while a more severe OOM uses an immediate process exit at a higher threshold. This is intended to avoid continuing through cleanup with invalid internal state.

Wiz Research reported:
- Pre-authentication RCE against WordPress, Drupal, and Joomla container images in its research environment.
- An application-agnostic process-memory disclosure result.

The demonstrated RCE was tied to a specific execution path and worker model. It should not be interpreted as proof that every PHP deployment is exploitable through an identical request sequence.

### 3.2 CVE-2026-109619 Stale state across request boundaries

The second vulnerability concerns request-owned state that can remain referenced after its memory has been released. If a persistent worker processes a later request before the stale state is safely reset, code may consume a dangling reference.

The official advisory describes confirmed consumer paths involving:
- Fatal-error backtrace state, including `EG(last_fatal_error_backtrace)`.
- Session upload-progress lifecycle state.

The same-worker condition matters: the later request must reach a worker that retains the relevant stale state. Worker recycling or multiple workers can affect repeatability, but they are not substitutes for patching.

For PHP-FPM, the exact triggering sequence differs from the demonstrated `mod_php` startup-failure path. The PHP advisory describes a validated session-lifecycle path under FPM subject to its documented conditions. Avoid generalizing this into a claim that all FPM deployments are equally exploitable or that every request can trigger the issue.

### 3.3 What is confirmed versus inferred

The public advisories and primary research support the existence and impact of the two vulnerabilities. Detailed internal exploit chains should only be stated as confirmed when they are directly supported by the advisories, patch/commit, or primary research.

In particular, avoid presenting invented or schematic C functions as if they were excerpts from `php-src`. If a source-level explanation is included, cite the exact file and commit or clearly label the diagram as conceptual.

### 3.4 Illustrative code examples (conceptual pseudocode)

The following snippets are simplified teaching examples to illustrate the classes of memory-safety errors discussed above. **They are not excerpts from PHP source code, do not reproduce the vulnerabilities, and should not be treated as proof of the exact implementation-level root cause.** The actual behavior must be established from the PHP advisories and the relevant source changes.

#### Example A Unsafe cleanup after partial initialization

```c
/* Conceptual pseudocode not actual PHP source */

struct request_state {
    char *session_id;
    int initialized;
};

int initialize_request(struct request_state *req) {
    req->initialized = 0;
    req->session_id = allocate_session_buffer();

    if (req->session_id == NULL) {
        /* Cleanup must tolerate partially initialized state. */
        cleanup_request(req);
        return -1;
    }

    req->initialized = 1;
    return 0;
}
```

**Security lesson:** Error-handling paths must not assume initialization completed. Cleanup routines should safely handle every partial-initialization state and release only resources that were successfully acquired.

#### Example B A dangling pointer retained across requests

```c
/* Conceptual pseudocode not actual PHP source */

static char *worker_state;

void handle_request(void) {
    char *request_data = allocate_request_data();
    if (request_data == NULL) {
        return;
    }

    worker_state = request_data;
    process_request(request_data);

    free(request_data);

    /* Defect in this example: worker_state is now dangling. */
    /* A later request could use the stale reference. */
}
```

**Security lesson:** A long-lived worker must not retain references to request-owned memory after the request ends. Clearing one pointer does not invalidate other aliases; ownership and lifetime must be managed consistently.

A simplified defensive pattern is:

```c
/* Conceptual pseudocode not actual PHP source */

void handle_request(void) {
    char *request_data = allocate_request_data();
    if (request_data == NULL) {
        worker_state = NULL;
        return;
    }

    worker_state = request_data;
    process_request(request_data);

    worker_state = NULL;   /* Clear the persistent reference first. */
    free(request_data);
    request_data = NULL;
}
```

This is only an illustrative pattern. Real implementations must account for all aliases, error exits, callbacks, and ownership rules; setting a pointer to `NULL` alone is not a complete memory-safety strategy.

#### Example C Safe handling of request initialization and cleanup

```c
/* Conceptual lifecycle pattern not actual PHP source */

int handle_request(void) {
    struct request_state req = {0};

    if (initialize_request(&req) != 0) {
        cleanup_request(&req);  /* Must be safe after partial init. */
        return -1;
    }

    process_request(&req);
    cleanup_request(&req);
    return 0;
}
```

**Security lesson:** Initialization and cleanup should follow a clear ownership model. Cleanup must be safe whether initialization succeeds fully, fails partway through, or exits through an error path.

These examples illustrate general secure-C programming principles relevant to the report. They are not a reproduction of either CVE and do not demonstrate exploitability.

## 4. Exploitation Conditions and Scope

Exploitability depends on factors that can differ between deployments:

- **PHP release and patch status:** The runtime must be vulnerable and not protected by an applicable vendor backport.
- **SAPI and worker model:** The PHP project considers `mod_php` the highest-risk configuration. Other web-serving SAPIs are also listed as potentially at risk, but the triggering conditions differ.
- **Request path:** Multipart parsing, upload-progress handling, fatal-error paths, and relevant initialization/cleanup behavior affect reachability.
- **Worker lifecycle:** Some stale-state paths require a subsequent request to reach the same worker process.
- **Configuration and application behavior:** Memory limits, request limits, relevant PHP settings, and attacker-reachable fatal-error paths can affect specific exploit chains.

Do not claim that PHP-CGI or any other SAPI is categorically immune solely because it may not reuse a worker across requests. A conclusion about a particular SAPI requires evidence about the specific vulnerable path and lifecycle.

## 5. Impact

Depending on the vulnerability and deployment conditions, successful exploitation may result in:

- **Unauthenticated remote code execution** with the privileges of the PHP worker.
- **Process-memory disclosure**, potentially exposing data held in process memory from other requests.
- **Confidentiality, integrity, and availability impacts**, including follow-on compromise if the PHP worker has excessive permissions or access to sensitive resources.

Examples of potentially exposed data—such as credentials, session tokens, API keys, or other application data—should be described as potential impact unless the cited research confirms that specific data was recovered.

RCE in a PHP worker does not automatically establish root-level access or full compromise of the host. The ultimate impact depends on the worker's privileges, isolation controls, accessible secrets, and surrounding infrastructure.

## 6. Remediation

### 6.1 Primary remediation: update PHP

Upgrade to a fixed upstream release:

- PHP 8.5.12
- PHP 8.4.27
- PHP 8.3.36
- PHP 8.2.35

If PHP is managed by a Linux distribution, hosting provider, appliance vendor, or long-term-support vendor, verify whether a patched package or backport is available. Do not rely solely on the upstream version string to establish patch status.

For PHP 8.1 and earlier, contact the distribution/vendor about backports or migrate to a supported, patched release. The PHP project does not provide ordinary upstream security releases for these end-of-life branches.

### 6.2 Temporary measures when immediate patching is impossible

The PHP project documents the following measures as **partial mitigations only**. They do not replace updating.

| CVE / path | Temporary measure | Important limitations |
|---|---|---|
| CVE-2026-109618 controllable OOM path | The PHP advisory identifies an administratively enforced `memory_limit=-1` as a mitigation for the demonstrated controllable-memory-limit path. | This removes PHP's per-request memory limit and is not a complete fix: underlying allocation failures can still reach vulnerable code. Assess resource-exhaustion risk, enforce the setting centrally, and ensure application or directory-level configuration cannot restore a finite limit. |
| CVE-2026-109618 request parsing | Apply conservative request-size and multipart limits at PHP and, where appropriate, the web server or proxy. Keep `upload_max_filesize` below `post_max_size`. | These controls reduce exposure but do not address every path. Limits should account for decoded request size, input field count, multipart part/header count, and nesting depth, including requests without a usable `Content-Length`. |
| CVE-2026-109619 session lifecycle | Set `session.upload_progress.enabled=0` if upload-progress tracking is not required. Apply it in a configuration that takes effect before request parsing and restart all relevant workers. | This blocks the documented session paths, not every possible variant. Do not rely on `ini_set()` or FPM `.user.ini` for an early-startup mitigation. |
| CVE-2026-109619 fatal backtrace path | On PHP 8.5, set `fatal_error_backtraces=0` and restart all relevant workers. | This addresses the confirmed fatal-backtrace path only; it is not a complete fix for CVE-2026-109619. |
| Both | Consider temporary isolation of exposed applications, WAF/edge rules, and monitoring while patching. | WAF rules and request filtering are defense in depth. They are not a substitute for a fixed runtime. |

Use container or cgroup memory controls as an availability boundary where appropriate. Follow the PHP advisory's warning not to substitute `RLIMIT_AS` or `RLIMIT_DATA` for the documented mitigation, because those limits can themselves trigger vulnerable allocation failures.

### 6.3 Deployment validation checklist

- [ ] Inventory all PHP runtimes, including containers, hosting panels, appliances, and bundled third-party products.
- [ ] Verify the actual installed package and vendor patch status.
- [ ] Update/rebuild container images and redeploy affected workloads.
- [ ] Restart all relevant PHP workers and services after patching or changing mitigations.
- [ ] Confirm the application is running the expected patched runtime, not an older runtime behind a proxy or on a separate pool.
- [ ] Keep WAF and request-size controls enabled as defense in depth.
- [ ] Review logs and endpoint telemetry for suspicious activity before and after remediation.

## 7. Detection and Monitoring

A version-fingerprinting scanner can help identify candidate PHP deployments, but remote detection does not reliably prove whether the origin runtime is vulnerable.

| Detection method | What it can establish | Limitation |
|---|---|---|
| Local package/runtime inspection | Runtime version and package details on the inspected system | Confirm vendor patch/backport status as well as the displayed version. |
| `phpinfo()` or PHP error page | May disclose runtime details | May be unavailable, exposed unintentionally, or reflect a different runtime from the origin serving the target request. |
| `X-Powered-By` / `Server` headers | A possible version clue | Headers may be missing, stale, rewritten, or generated by a CDN/WAF rather than the origin. |
| PHP presence indicators such as `.php` references or `PHPSESSID` | May indicate PHP use | Does not establish a vulnerable version or exploitability. |
| Active multipart probe | May reveal instability in an authorized test environment | Can cause denial of service or worker disruption; do not describe it as non-destructive. Use only with explicit authorization and a controlled test plan. |

The report's referenced scanner is available at: [JoasASantos/php2shell-scanner](https://github.com/JoasASantos/php2shell-scanner). Independently verify its current behavior, documentation, and safety characteristics before using it in production.

### Monitoring recommendations

Monitor for:
- Unexpected PHP worker crashes, restarts, or abnormal child-process creation.
- Unusual multipart request patterns and repeated server errors.
- Suspicious commands, files, accounts, or outbound connections associated with PHP/web-server processes.
- Relevant web, application, authentication, and endpoint-security events.

These indicators are not proof of exploitation on their own. Correlate them with host and application telemetry and investigate unexplained activity.

## 8. Proof-of-Concept Status

Wiz Research reported using an internal tool referred to as `php2shell` to demonstrate RCE against specific WordPress, Drupal, and Joomla container images. Public reporting after disclosure also noted public PoC repositories.

The existence of a public repository does not establish that its code works, is reliable, or applies to a particular deployment. This report does not reproduce exploit code and does not claim independent validation of third-party PoCs. Test only in an authorized, isolated environment.

## 9. Disclosure Timeline

The PHP security release and public advisories were published on **October 21, 2026**. The upstream fixed releases are listed in Section 1.

Any more granular dates for initial discovery, application-specific exploit demonstrations, or private disclosure should be included only when directly supported by a primary-source disclosure timeline.

## 10. References

1. **PHP official security release announcement:** [Security advisory: Critical remote code execution vulnerabilities, update now](https://www.php.net/archive/2026.php)
2. **PHP advisory CVE-2026-109618:** [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
3. **PHP advisory CVE-2026-109619:** [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
4. **Wiz Research:** [PHP2Shell: AI uncovers critical RCE vulnerabilities affecting 70% of the Internet](https://www.wiz.io/blog/php2shell-php-rce)
5. **Google Cloud / Google DeepMind:** [Responding to core PHP vulnerabilities CVE-2026-109618 and CVE-2026-109619](https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619)
6. **CERT-EU:** [Critical Vulnerabilities in PHP](https://cow-prod-www-v3.azurewebsites.net/publications/security-advisories/2026-018/)
7. **Canadian Centre for Cyber Security:** [AL26-026 Critical vulnerabilities impacting PHP](https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619)
8. **ENISA and EU partners:** [Joint statement on critical PHP vulnerabilities](https://www.enisa.europa.eu/news/joint-statement-on-critical-php-vulnerabilities)
9. **Detection scanner:** [JoasASantos/php2shell-scanner](https://github.com/JoasASantos/php2shell-scanner)

---

**Authorization note:** This report is intended for authorized security assessment and defensive remediation. Do not test systems without ownership or explicit permission. Active multipart probes may disrupt service and should only be used under an approved test plan.
