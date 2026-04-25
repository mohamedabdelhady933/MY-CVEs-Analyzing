# Remote Code Execution via Improper validation on the script_url in [intel/neural-compressor](https://github.com/intel/neural-compressor)



## Description

The `/task/submit/` endpoint is basically creating a task given by the user through user controllable input which is "script_url". The responsible for this function is route is `./frontend/fastapi/main_server.py` script.<br>

```
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


The application check if the task is valid using the `is_valid_task()` function then execute this task. The `is_valid_task()` is imported from the utilities that defined here `./neural_solution/frontend/utility.py.
<br>
Here is the `is_valid_task()` code
<br>
```
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

<br>
It just check on the format of every single parameter coming from the user request. Additionally here is 2 functions that support the task generation as well. First function is `prepare_task()` and here is the code.
<br>

```
  def prepare_task(self, task: Task):
        """Prepare workspace and download run_task.py for task.

        Args:
            task (Task): task
        """
        self.task_path = build_workspace(path=get_task_workspace(self.config.workspace), task_id=task.task_id)
        logger.info(f"****TASK PATH: {self.task_path}")
        if is_remote_url(task.script_url):
            task_url = task.script_url.replace("github.com", "raw.githubusercontent.com").replace("blob", "")
            try:
                subprocess.check_call(["wget", "-P", self.task_path, task_url])
            except subprocess.CalledProcessError as e:
                logger.info("Failed: {}".format(e.cmd))
        else:
            # Assuming the file is uploaded in directory examples
            example_path = os.path.abspath(os.path.join(self.upload_path, task.script_url))
            # only one python file
            script_path = glob.glob(os.path.join(example_path, "*.py"))[0]
            # script_path = glob.glob(os.path.join(example_path, f'*{extension}'))[0]
            self.script_name = script_path.split("/")[-1]
            shutil.copy(script_path, os.path.abspath(self.task_path))
            task.arguments = task.arguments.replace("=dataset", "=" + os.path.join(example_path, "dataset")).replace(
                "=model", "=" + os.path.join(example_path, "model")
            )
        if not task.optimized:
            # Generate quantization code with Neural Coder API
            neural_coder_cmd = ["python -m neural_coder --enable --approach"]
            # for users to define approach: "static", "static_ipex", "dynamic", "auto"
            approach = task.approach
            neural_coder_cmd.append(approach)
            if is_remote_url(task.script_url):
                self.script_name = task.script_url.split("/")[-1]
            neural_coder_cmd.append(self.script_name)
            neural_coder_cmd = " ".join(neural_coder_cmd)
            full_cmd = """cd {}\n{}""".format(self.task_path, neural_coder_cmd)
            p = subprocess.Popen(full_cmd, shell=True)  # nosec
            logger.info("[Neural Coder] Generating optimized code start.")
            p.wait()
            logger.info("[Neural Coder] Generating optimized code end.")
```
<br>
The application get the check `script_url` ,by optimizing it. The optimization process will relay on 
<br>
1- Creates a per-task workspace directory <br>
2- If it's remote url then the application change the github.com to raw.raw.githubusercontent.com to get the raw data of the file. <br>
3- Fetches a Python script (either remote or local) <br>
4-Normalize the script if the request parameter "optimized": "True", if it's not, it will not go into this function.<br>

The second function is `_parse_cmd`


```
   def _parse_cmd(self, task: Task, resource):
        # mpirun -np 3 -mca btl_tcp_if_include 192.168.20.0/24 -x OMP_NUM_THREADS=80
        # --host mlt-skx091,mlt-skx050,mlt-skx053 bash run_distributed_tuning.sh
        self.prepare_task(task)
        conda_env = self.prepare_env(task)
        host_str = ",".join([item.split(" ")[1] for item in resource])
        logger.info(f"[TaskScheduler] host resource: {host_str}")

        # Activate environment
        conda_bash_cmd = f"source {CONDA_SOURCE_PATH}"
        conda_env_cmd = f"conda activate {conda_env}"
        mpi_cmd = [
            "mpirun",
            "-np",
            "{}".format(task.workers),
            "-host",
            "{}".format(host_str),
            "-map-by",
            "socket:pe={}".format(self.num_threads_per_process),
            "-mca",
            "btl_tcp_if_include",
            "192.168.20.0/24",  # TODO replace it according to the node
            "-x",
            "OMP_NUM_THREADS={}".format(self.num_threads_per_process),
            "--report-bindings",
        ]
        mpi_cmd = " ".join(mpi_cmd)

        # Initial Task command
        task_cmd = ["python"]
        task_cmd.append(self.script_name)
        task_cmd.append(self.sanitize_arguments(task.arguments))
        task_cmd = " ".join(task_cmd)

        # use optimized code by Neural Coder
        if not task.optimized:
            task_cmd = task_cmd.replace(".py", "_optimized.py")

        # build a bash script to run task.
        bash_script_name = "distributed_run.sh" if task.workers > 1 else "run.sh"
        bash_script = """{}\n{}\ncd {}\n{}""".format(conda_bash_cmd, conda_env_cmd, self.task_path, task_cmd)
        bash_script_path = os.path.join(self.task_path, bash_script_name)
        with open(bash_script_path, "w", encoding="utf-8") as f:
            f.write(bash_script)
        full_cmd = """cd {}\n{} bash {}""".format(self.task_path, mpi_cmd, bash_script_name)

```
<br>
It does checking on the command line, by the following 
<br>
1- prepare the task environment <br>
2- Conda activation commands <br>
3- MPI command construction <br>
4- Sanitize the arguments before execution <br>
5- Python task command creation<br>

And here is the sanitize_arguments function `./neural_solution/backend/scheduler.py`

```
   def sanitize_arguments(self, arguments: str):
        """Replace space encoding with space."""
        return arguments.replace("\xa0", " ")

```

## Proof of Concept

1- Since no restriction on source or hostname of the script URL you can use any other website with the python script code such as `https://justfortexting.free.beeceptor.com/exploit`<br>
<br>
2- The exploit file code is:
<br>

```
import os
os.system("touch /tmp/hacked_rce")
```
<br>
3- if you use `https://justfortesting.free.beeceptor.com/exploit.py` that ends with .py extension, the application will optimize it to `exploit_optimized.py` as mentioned in file `./neural_solution/backend/scheduler.py`.
<br>
4- However if you use the file without extension it will be downloaded and executed successfully because the code will not sanitize it because the script isn't with .py extension or from github.com website.
<br>
Note:

you can do the same with `github.com` website as well but the file should be without extension.


## Impact

Bypass the filtering flows to execute system commands


## Vulnerable code
This function should validate on the fetched URL properly
`https://github.com/intel/neural-compressor/blob/5f3f388c2d44de2ef0d8c923989a7892758684a8/neural_solution/backend/scheduler.py#L129`
