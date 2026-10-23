# PHP2Shell: Analysis of Two Critical PHP Runtime Vulnerabilities

<img width="1924" height="799" alt="2026-10-23_09-36" src="https://github.com/user-attachments/assets/41d0586d-2700-4d12-9cf5-9163139cc9e8" />

> **Report updated:** October 22, 2026  
> **Affected component:** PHP core runtime  
> **CVE IDs:** CVE-2026-109618 and CVE-2026-109619  
> **Severity:** Critical CVSS 9.2  
> **Primary remediation:** Upgrade to a fixed PHP release or install a verified vendor backport.

## 1. Overview

The PHP project disclosed two critical memory-safety flaws: **CVE-2026-109618** and **CVE-2026-109619**. Under the right conditions, both can lead to unauthenticated remote code execution (RCE); the research also demonstrated disclosure of process memory.

These are PHP runtime bugs, not flaws limited to a particular CMS. Updating WordPress, Drupal, Joomla, or application code will not fix an affected PHP installation. Whether a deployment can be exploited depends on its PHP build, SAPI, configuration, request path, and worker lifecycle.

Apache `mod_php` is considered the highest-risk setup because the demonstrated path can be reached before application code runs. The PHP advisory also lists PHP-FPM, `php-cgi`, FrankenPHP, and LiteSpeed as potentially affected, although the conditions are not identical across SAPIs.

**Fixed upstream releases:**

| PHP branch | Fixed release |
|---|---:|
| PHP 8.5.x | 8.5.12 |
| PHP 8.4.x | 8.4.27 |
| PHP 8.3.x | 8.3.36 |
| PHP 8.2.x | 8.2.35 |
| PHP 8.1 and earlier | End of upstream support; check distribution/vendor backports or upgrade |

Updating to a fixed PHP release is the only complete fix. Configuration changes and WAF rules can reduce exposure to particular paths, but they should be treated as temporary safeguardsnot replacements for patching.

## 2. The Two CVEs

| CVE | Core issue described by the PHP project | Demonstrated impact and scope |
|---|---|---|
| **CVE-2026-109618** | Out-of-memory (OOM) handling can interrupt request processing while internal request data is only partially initialized. Cleanup may subsequently treat invalid or uninitialized data as valid. | The published research demonstrates unauthenticated RCE against specific WordPress, Drupal, and Joomla container images using `mod_php`, as well as application-agnostic process-memory disclosure. The PHP advisory distinguishes this from the early-startup path that does not persist in the same way under FPM. |
| **CVE-2026-109619** | Request-owned internal state can remain referenced after the backing memory has been freed. A later request handled by the same worker may use that stale state before normal initialization resets it. | Published research describes confirmed RCE paths involving fatal-error backtrace state and the session upload-progress lifecycle. The advisory describes conditions under which the session-lifecycle path can affect both `mod_php` and PHP-FPM. |

The two CVEs share a broader memory-safety theme, but they involve different paths. Results demonstrated for one issue should not automatically be attributed to the other.

## 3. Technical Description

### 3.1 CVE-2026-109618 Out-of-memory handling and invalid request state

The first flaw is triggered by an out-of-memory (OOM) condition during request processing. If PHP is interrupted while internal request data is only partly initialized, later cleanup may handle that data as though initialization had finished.

The fix changes how PHP handles OOM in the affected path. A recoverable OOM is deferred to a VM safe point; a more severe one causes the process to exit at a higher threshold. The aim is to avoid continuing through cleanup with invalid request state.

Wiz Research demonstrated unauthenticated RCE against WordPress, Drupal, and Joomla container images, and reported a process-memory disclosure that was not tied to a specific application. These results show the seriousness of the issue, but they do not mean every PHP deployment can be exploited in the same way.

### 3.2 CVE-2026-109619 Stale state across request boundaries

The second flaw involves a pointer to request-owned memory that remains in worker state after the memory has been freed. If the same worker handles another request before that state is reset, PHP may use the stale pointer.

The official advisory describes confirmed consumer paths involving:
- Fatal-error backtrace state, including `EG(last_fatal_error_backtrace)`.
- Session upload-progress lifecycle state.

This path depends on a later request reaching a worker that still holds the stale state. Worker recycling can affect whether the issue reproduces, but it is not a fix.

PHP-FPM does not behave exactly like `mod_php` when request startup fails. The advisory nevertheless describes a session-lifecycle path that was validated under specific FPM conditions. This does not mean every FPM deployment is equally exposed or that an arbitrary request will trigger the flaw.

### 3.3 What is confirmed versus inferred

The descriptions in this report are based on the PHP advisories and published research. Where those sources do not confirm a low-level detail, it should not be presented as established fact. The code examples below are simplified illustrations, not excerpts from `php-src`.

### 3.4 Code examples

The snippets below show the general programming mistakes involved: cleaning up an object that was only partly initialized, and keeping a pointer after its memory has been freed. They are **illustrative C examples, not PHP source code or working reproductions of either CVE**.

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

**Why it matters:** An error path can run before every field has been set. Cleanup needs to handle that state safely and release only resources that were actually allocated.

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

**Why it matters:** A persistent worker must not keep using memory that belonged to a completed request. Clearing one pointer is not enough if other references still point to the same allocation.

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

This is a simplified example. Real code must account for every reference and every error path; setting one pointer to `NULL` does not make all other references safe.

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

**Why it matters:** Cleanup should work whether initialization succeeds, fails halfway through, or exits through an error path. These examples explain the general memory-management problem; they do not reproduce either CVE or establish exploitability.

## 4. Exploitation Conditions and Scope

Whether a particular server is exploitable depends on its setup, including:

- **PHP release and patch status:** The runtime must be vulnerable and not protected by an applicable vendor backport.
- **SAPI and worker model:** The PHP project considers `mod_php` the highest-risk configuration. Other web-serving SAPIs are also listed as potentially at risk, but the triggering conditions differ.
- **Request path:** Multipart parsing, upload-progress handling, fatal-error paths, and relevant initialization/cleanup behavior affect reachability.
- **Worker lifecycle:** Some stale-state paths require a subsequent request to reach the same worker process.
- **Configuration and application behavior:** Memory limits, request limits, relevant PHP settings, and attacker-reachable fatal-error paths can affect specific exploit chains.

A SAPI should not be called immune simply because its worker model differs. Check the specific request path and lifecycle before drawing conclusions about a deployment.

## 5. Potential Impact

If an attacker can exploit the issue, the impact may include:

- **Unauthenticated remote code execution** with the privileges of the PHP worker.
- **Process-memory disclosure**, potentially exposing data held in process memory from other requests.
- **Confidentiality, integrity, and availability impacts**, including follow-on compromise if the PHP worker has excessive permissions or access to sensitive resources.

Examples of potentially exposed datasuch as credentials, session tokens, API keys, or other application datashould be described as potential impact unless the cited research confirms that specific data was recovered.

Code execution runs with the privileges available to the PHP worker. It does not automatically mean root access; the wider impact depends on the worker account, isolation, accessible secrets, and surrounding infrastructure.

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

The PHP project lists the following as **temporary mitigations**. They reduce specific risks but do not fix the underlying bugs.

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

A scanner can help find servers that may be running PHP versions of interest, but a remote fingerprint alone cannot confirm that the origin is vulnerable.

| Detection method | What it can establish | Limitation |
|---|---|---|
| Local package/runtime inspection | Runtime version and package details on the inspected system | Confirm vendor patch/backport status as well as the displayed version. |
| `phpinfo()` or PHP error page | May disclose runtime details | May be unavailable, exposed unintentionally, or reflect a different runtime from the origin serving the target request. |
| `X-Powered-By` / `Server` headers | A possible version clue | Headers may be missing, stale, rewritten, or generated by a CDN/WAF rather than the origin. |
| PHP presence indicators such as `.php` references or `PHPSESSID` | May indicate PHP use | Does not establish a vulnerable version or exploitability. |
| Active multipart probe | May reveal instability in an authorized test environment | Can cause denial of service or worker disruption; do not describe it as non-destructive. Use only with explicit authorization and a controlled test plan. |

The referenced scanner is [JoasASantos/php2shell-scanner](https://github.com/JoasASantos/php2shell-scanner). Review its code and documentation before running it against production systems.

### Monitoring recommendations

Monitor for:
- Unexpected PHP worker crashes, restarts, or abnormal child-process creation.
- Unusual multipart request patterns and repeated server errors.
- Suspicious commands, files, accounts, or outbound connections associated with PHP/web-server processes.
- Relevant web, application, authentication, and endpoint-security events.

None of these signs proves exploitation on its own. Compare them with application and host logs, then investigate activity that cannot be explained.

## 8. PoC Status

Wiz Research reported using an internal tool referred to as `php2shell` to demonstrate RCE against specific WordPress, Drupal, and Joomla container images. Public reporting after disclosure also noted public PoC repositories.

A public PoC repository is not proof that the exploit works against a given server. I have not independently validated third-party PoCs for this report, and no exploit code is reproduced here. Any testing should take place in an isolated environment with explicit authorization.

## 9. Disclosure Timeline

The PHP security release and public advisories were published on **October 21, 2026**. The upstream fixed releases are listed in Section 1.

This report records the public release date only. Earlier discovery and disclosure dates should be added only if they can be confirmed from a primary source.

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
