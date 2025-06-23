# amanda

A simple web application, to mimic the v3 API endpoints for Ansible Galaxy Collections, with no database, just a directory with artifacts

## Usage

1. `go install github.com/sivel/amanda@latest` (You can use the `GOBIN` env variable to install to a custom location). Binary artifacts can also be found for a variety of OSes and architectures at https://github.com/sivel/amanda/actions/workflows/build.yml
1. Create a directory to hold the artifacts, which by default is named `artifacts` and lives in the current working directory
1. Drop `ansible-galaxy collection build/download` artifacts in the `artifacts` directory
1. Run the app:

    ```
    ./amanda -artifacts=/path/to/artifacts
    ```
1. Install collections:

    ```
    ansible-galaxy collection install -s http://hostname:5000/api namespace.collection
    ```

## Signatures

Alongside the `.tar.gz` artifact for a collection, create a file with the same base name and a `.asc` extension.

A quick example on creating and verifying the signature:

```
cd collections/ansible_collections/namespace/name
ansible-galaxy collection build
tar -Oxzf namespace-name-1.0.0.tar.gz MANIFEST.json | gpg --output namespace-name-1.0.0.asc --detach-sign --armor --local-user email@example.org -
tar -Oxzf namespace-name-1.0.0.tar.gz MANIFEST.json | gpg --verify namespace-name-1.0.0.asc -
```
