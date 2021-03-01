# amanda

A simple web application, to mimic the V2 API endpoints for Ansible Galaxy Collections, with no database, just a directory with artifact

## Usage

1. Download (and potentially build) either `amanda.py` or `amanda.go`
1. Create a directory adjacent to the `amanda.py`/`amanda` file named `artifacts`
1. Drop `ansible-galaxy collection build/download` artifacts in the `artifacts` directory
1. Run the app:

    ```
    python3 amanda.py
    ```

    or

    ```
    ./amanda
    ```
1. Install collections:

    ```
    ansible-galaxy collection install -s http://hostname:5000/api namespace.collection
    ```

## Notes

If you are running the python version, for "production", I'd recommend using `gunicorn` (`gunicorn amanda:app`)
