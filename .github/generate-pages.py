#!/usr/bin/env python3

import hashlib
from pathlib import Path
from string import Template
from datetime import datetime, timezone
import os


def get_file_size(filepath):
    size = filepath.stat().st_size
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}TB"


def get_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def generate_binary_html(binary_files):
    binary_html = ""
    for filepath in binary_files:
        size = get_file_size(filepath)
        sha256 = get_sha256(filepath)

        binary_html += f'''        <div class="download-item">
            <a href="{filepath.name}">{filepath.name}</a>
            <span class="file-size">({size})</span>
            <br><div class="sha256">SHA256: {sha256}</div>
        </div>
'''
    return binary_html


def main():
    commit_sha = os.environ.get('GITHUB_SHA', 'unknown')
    repository = os.environ.get('GITHUB_REPOSITORY', 'unknown/unknown')
    build_date = datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    binary_files = sorted(Path('.').glob('amanda_*'))

    binaries_html = generate_binary_html(binary_files)

    template_content = Path('../.github/pages-template.html').read_text()

    template = Template(template_content)
    result = template.substitute(
        COMMIT_SHA=commit_sha,
        BUILD_DATE=build_date,
        REPOSITORY=repository,
        BINARIES=binaries_html
    )

    Path('index.html').write_text(result)

    print(f"Generated index.html with {len(binary_files)} binaries")


if __name__ == '__main__':
    main()
