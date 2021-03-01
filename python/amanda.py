#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) 2020 Matt Martz <matt@sivel.net>
# GNU General Public License v3.0+
#     (see https://www.gnu.org/licenses/gpl-3.0.txt)

import json
import os
import tarfile
from collections import defaultdict
from functools import partial
from hashlib import sha256

from flask import Flask, g, request, send_from_directory, url_for


ARTIFACT_BASE = os.getenv('SIMPLE_GALAXY_ARTIFACT_BASE', 'artifacts')


app = Flask(__name__)

def get_sha(fobj):
    digest = sha256()
    # Localize variable access to minimize overhead.
    digest_update = digest.update
    buffer_size = (64 * 1024) // digest.block_size * digest.block_size
    for b_block in iter(partial(fobj.read, buffer_size), b''):
        digest_update(b_block)
    return digest.hexdigest()


def discover_collections(namespace=None, name=None, version=None):
    try:
        g.discovery_cache
    except AttributeError:
        g.discovery_cache = defaultdict(dict)

    for path in os.listdir(ARTIFACT_BASE):
        filename = os.path.basename(path)
        path = os.path.join(os.path.abspath(ARTIFACT_BASE), filename)
        stat = os.stat(path)

        info = g.discovery_cache[filename].get(stat.st_mtime)

        if not info:
            info = {
                'filename': filename,
                'path': path,
            }

            with open(path, 'rb') as f:
                try:
                    t = tarfile.open(mode='r:gz', fileobj=f)
                    with t.extractfile('MANIFEST.json') as m_f:
                        info['manifest'] = manifest = json.load(m_f)
                except Exception:
                    continue

                ci = manifest['collection_info']

                f.seek(0)
                info['sha'] = get_sha(f)

                g.discovery_cache[filename][stat.st_mtime] = info

        match = (
            not all((namespace, name)) or
            (ci['namespace'] == namespace and ci['name'] == name)
        )

        if match and (not version or ci['version'] == version):
            yield info


@app.route('/api/v2/collections/download/<filename>')
def download(filename):
    return send_from_directory(
        ARTIFACT_BASE,
        filename,
        mimetype='application/gzip',
    )


@app.route('/api/')
@app.route('/api')
def api():
    return (
        json.dumps(
            {
                'available_versions': {
                    'v1': 'v1/',
                    'v2': 'v2/'
                },
                'current_version': 'v1',
                'description': 'GALAXY REST API',
            },
            sort_keys=True,
            indent=4
        ),
        200,
        {'Content-Type': 'application/json'}
    )


@app.route('/api/v2/collections/<namespace>/<collection>/')
@app.route('/api/v2/collections/<namespace>/<collection>')
def collection(namespace, collection):
    discovered = list(discover_collections(namespace, collection))
    latest = sorted(
        discovered,
        key=lambda i: i['manifest']['collection_info']['version'],
    )[-1]
    version = latest['manifest']['collection_info']['version']
    return (
        json.dumps(
            {
                "href": request.url,
                "id": 0,
                "latest_version": {
                    'href': url_for(
                        'version',
                        namespace=namespace,
                        collection=collection,
                        version=version,
                        _external=True
                    ),
                    "version": version
                },
                "name": collection,
                "namespace": {
                    "name": namespace
                },
                "versions_url": url_for(
                    'versions',
                    namespace=namespace,
                    collection=collection,
                    _external=True
                )
            },
            sort_keys=True,
            indent=4
        ),
        200,
        {'Content-Type': 'application/json'}
    )


@app.route('/api/v2/collections/<namespace>/<collection>/versions/')
@app.route('/api/v2/collections/<namespace>/<collection>/versions')
def versions(namespace, collection):
    versions = []
    discovered = list(discover_collections(namespace, collection))
    for info in discovered:
        version = info['manifest']['collection_info']['version']
        versions.append(
            {
                'href': url_for(
                    'version',
                    namespace=namespace,
                    collection=collection,
                    version=version,
                    _external=True
                ),
                'version': version
            }
        )

    return (
        json.dumps(
            {
                'count': len(discovered),
                'next': None,
                'previous': None,
                'results': versions,
            },
            sort_keys=True,
            indent=4
        ),
        200,
        {'Content-Type': 'application/json'}
    )


@app.route('/api/v2/collections/<namespace>/<collection>/versions/<version>/')
@app.route('/api/v2/collections/<namespace>/<collection>/versions/<version>')
def version(namespace, collection, version):
    info = next(discover_collections(namespace, collection, version))

    return (
        json.dumps(
            {
                'artifact': {
                    'filename': info['filename'],
                    'sha256': info['sha'],
                    'size': 0
                },
                'collection': {
                    'name': collection
                },
                'namespace': {
                    'name': namespace,
                },
                'download_url': url_for(
                    'download',
                    filename=info['filename'],
                    _external=True,
                ),
                'hidden': False,
                'href': request.url,
                'id': 0,
                'metadata': info['manifest']['collection_info'],
                'version': version
            },
            sort_keys=True,
            indent=4
        ),
        200,
        {'Content-Type': 'application/json'}
    )


if __name__ == '__main__':
    app.run('0.0.0.0', 5000, debug=True, threaded=True)