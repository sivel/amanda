# amanda

A simple web application, to mimic the v3 API endpoints for Ansible Galaxy Collections, with no database, just a directory with artifacts

## Usage

### Binary

1. `go install github.com/sivel/amanda@latest` (You can use the `GOBIN` env variable to install to a custom location). Binary artifacts can also be found for a variety of OSes and architectures at https://sivel.github.io/amanda/
1. Create a directory to hold the artifacts, which by default is named `artifacts` and lives in the current working directory
1. Drop `ansible-galaxy collection build/download` artifacts in the `artifacts` directory
1. Run the app:

    ```console
    ./amanda -artifacts=/path/to/artifacts
    ```
1. Install collections:

    ```console
    ansible-galaxy collection install -s http://hostname:5000/api namespace.collection
    ```

### Docker

```console
docker run --rm -d -p 5000:5000 -v /path/to/artifacts:/artifacts ghcr.io/sivel/amanda:latest
```

### HTML UI

`amanda` now includes a basic HTML UI, disabled by default, that can be enabled using the `-ui` flag, accessible by default at `http://hostname:5000/`

```console
./amanda -ui
```

### Publish

If you want to be able to use `ansible-galaxy collection publish` you can enable the functionality in `amanda` with `-publish`.

```console
./amanda -publish
```

This application does not and will not handle any form of authentication or role based access controls; If you enable publishing it is highly recommended to use a reverse proxy that has authentication functionality that you can place in front of `amanda` to prevent unauthorized uploads.

Publishing does not support the ability to upload a signature.

## Reverse Proxy

When running `amanda` behind a reverse proxy with a path prefix (e.g., `http://example.com/amanda/` instead of `http://example.com/`), configure your reverse proxy to send the `X-Forwarded-Prefix` header so that URLs in API responses are correct.

Example Caddyfile:

```caddyfile
:8080 {
    handle_path /amanda/* {
        reverse_proxy localhost:5000 {
            header_up X-Forwarded-Prefix /amanda
        }
    }
}
```

## Signatures

Alongside the `.tar.gz` artifact for a collection, create a file with the same base name and a `.asc` extension.

A quick example on creating and verifying the signature:

```console
cd collections/ansible_collections/namespace/name
ansible-galaxy collection build
tar -Oxzf namespace-name-1.0.0.tar.gz MANIFEST.json | gpg \
    --output  namespace-name-1.0.0.asc --detach-sign --armor \
    --local-user email@example.org -
tar -Oxzf namespace-name-1.0.0.tar.gz MANIFEST.json | gpg \
    --verify namespace-name-1.0.0.asc -
```
