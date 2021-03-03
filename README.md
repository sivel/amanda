# amanda

A simple web application, to mimic the V2 API endpoints for Ansible Galaxy Collections, with no database, just a directory with artifact

## Usage

### Go

1. `go install github.com/sivel/amanda@latest` (You can use the `GOBIN` env variable to install to a custom location)
1. Create a directory to hold the artifacts, which by default is named `artifacts` and lives adjacent to the `amanda` binary
1. Drop `ansible-galaxy collection build/download` artifacts in the `artifacts` directory
1. Run the app:

    ```
    ./amanda -artifacts=/path/to/artifacts
    ```
1. Install collections:

    ```
    ansible-galaxy collection install -s http://hostname:5000/api namespace.collection
    ```

### Python

1. Download `amanda.py` and `requirements.txt`
1. `pip install -r requirements.txt`
1. Create a directory to hold the artifacts, which by default is named `artifacts` and lives adjacent to the `amanda.py` file
1. Drop `ansible-galaxy collection build/download` artifacts in the `artifacts` directory
1. Run the app:

    ```
    python3 amanda.py --artifacts=/path/to/artifacts
    ```
1. Install collections:

    ```
    ansible-galaxy collection install -s http://hostname:5000/api namespace.collection
    ```
