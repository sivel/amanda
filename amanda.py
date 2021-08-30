#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) 2020 Matt Martz <matt@sivel.net>
# GNU General Public License v3.0+
#     (see https://www.gnu.org/licenses/gpl-3.0.txt)

import argparse
import datetime
import json
import os
import tarfile
from collections import defaultdict
from functools import partial
from hashlib import sha256

from flask import Flask, abort, g, request, send_from_directory, url_for

import semver


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

    artifacts = app.config['ARTIFACTS']

    for path in os.listdir(artifacts):
        filename = os.path.basename(path)
        path = os.path.join(os.path.abspath(artifacts), filename)
        if not os.path.isfile(path):
            continue

        stat = os.stat(path)

        info = g.discovery_cache[filename].get(stat.st_mtime)

        if not info:
            info = {
                'filename': filename,
                'path': path,
                'created': datetime.datetime.fromtimestamp(
                    stat.st_mtime
                ).isoformat(),
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
        else:
            ci = info['manifest']['collection_info']

        match = (
            not all((namespace, name)) or
            (ci['namespace'] == namespace and ci['name'] == name)
        )

        if match and (not version or ci['version'] == version):
            yield info


@app.route('/api/v2/collections/download/<filename>')
def download(filename):
    return send_from_directory(
        app.config['ARTIFACTS'],
        filename,
        mimetype='application/gzip',
    )


@app.route('/api')
@app.route('/api/')
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


@app.route('/api/v2/collections')
@app.route('/api/v2/collections/')
def collections():
    discovered = discover_collections()

    seen = set()
    out = {
        'results': []
    }

    for collection in discovered:
        namespace = collection['manifest']['collection_info']['namespace']
        name = collection['manifest']['collection_info']['name']
        seen_key = f'{namespace}.{name}'

        if seen_key in seen:
            continue
        else:
            seen.add(seen_key)

        versions = list(discover_collections(namespace, name))
        prod_versions = []
        for version in versions:
            v = semver.VersionInfo.parse(
                version['manifest']['collection_info']['version']
            )
            if not v.prerelease:
                prod_versions.append(version)
        prod_versions.sort(
            key=lambda i: semver.VersionInfo.parse(
                i['manifest']['collection_info']['version']
            ),
        )

        latest = versions[-1]
        oldest = versions[0]

        result = {
            "name": name,
            "namespace": {
                "name": namespace
            },
            "versions_url": url_for(
                'versions',
                namespace=namespace,
                collection=name,
                _external=True
            ),
            "created": oldest['created'],
            "modified": latest['created'],
        }

        if prod_versions:
            prod_latest = prod_versions[-1]
            latest_version = prod_latest['manifest']['collection_info']['version']
            result["latest_version"] = {
                'href': url_for(
                    'version',
                    namespace=namespace,
                    collection=name,
                    version=latest_version,
                    _external=True
                ),
                "version": latest_version
            }

        out['results'].append(result)

    return (
        json.dumps(
            out,
            sort_keys=True,
            indent=4
        ),
        200,
        {'Content-Type': 'application/json'}
    )

@app.route('/api/v2/collections/<namespace>/<collection>')
@app.route('/api/v2/collections/<namespace>/<collection>/')
def collection(namespace, collection):
    discovered = list(discover_collections(namespace, collection))

    if not discovered:
        abort(404)

    prod_collections = []
    for c in discovered:
        v = semver.VersionInfo.parse(
            c['manifest']['collection_info']['version']
        )
        if not v.prerelease:
            prod_collections.append(c)
    prod_collections.sort(
        key=lambda i: semver.VersionInfo.parse(
            i['manifest']['collection_info']['version']
        ),
    )

    collections = sorted(
        discovered,
        key=lambda i: semver.VersionInfo.parse(
            i['manifest']['collection_info']['version']
        ),
    )
    latest = collections[-1]
    oldest = collections[0]

    out = {
        "name": collection,
        "namespace": {
            "name": namespace
        },
        "versions_url": url_for(
            'versions',
            namespace=namespace,
            collection=collection,
            _external=True
        ),
        "created": oldest['created'],
        "modified": latest['created'],
    }

    if prod_collections:
        prod_latest = prod_collections[-1]
        version = prod_latest['manifest']['collection_info']['version']
        out["latest_version"] = {
            'href': url_for(
                'version',
                namespace=namespace,
                collection=collection,
                version=version,
                _external=True
            ),
            "version": version
        }

    return (
        json.dumps(
            out,
            sort_keys=True,
            indent=4
        ),
        200,
        {'Content-Type': 'application/json'}
    )


@app.route('/api/v2/collections/<namespace>/<collection>/versions')
@app.route('/api/v2/collections/<namespace>/<collection>/versions/')
def versions(namespace, collection):
    versions = []
    discovered = list(discover_collections(namespace, collection))

    if not discovered:
        abort(404)

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


@app.route('/api/v2/collections/<namespace>/<collection>/versions/<version>')
@app.route('/api/v2/collections/<namespace>/<collection>/versions/<version>/')
def version(namespace, collection, version):
    try:
        info = next(discover_collections(namespace, collection, version))
    except StopIteration:
        abort(404)

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
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts', default='artifacts',
                        help='Location of the artifacts dir')
    parser.add_argument('--port', default='5000', type=int,
                        help='Port')
    args = parser.parse_args()
    app.config['ARTIFACTS'] = args.artifacts
    app.run('0.0.0.0', args.port, threaded=True)
