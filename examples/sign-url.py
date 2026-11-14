#!/usr/bin/env python3
"""Create CloudFront canned-policy or Google Media CDN signed URLs."""

# Copyright (C) Hanada

import argparse
import base64
import json
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa


def sign_url(provider, url, key_name, private_key, expires):
    parts = urlsplit(url)
    if (not url.isascii() or re.search(r'[\x00-\x20\x7f"\\#]', url)
            or re.search(r'%(?![0-9a-fA-F]{2})', url)
            or parts.scheme not in ('http', 'https') or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.port is not None or parts.netloc != parts.hostname
            or not parts.path.startswith('/') or parts.fragment
            or url.endswith(('?', '&')) or expires <= 0):
        raise ValueError('use an absolute, percent-encoded HTTP(S) URL without a port or fragment')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', key_name):
        raise ValueError('invalid key name')
    reserved = {'expires', 'signature', 'key-pair-id', 'hash-algorithm', 'policy'}
    if provider == 'media-cdn':
        reserved = {'expires', 'keyname', 'signature', 'urlprefix', 'headername', 'headervalue', 'ipranges'}
    if any(name.lower() in reserved for name, _ in parse_qsl(parts.query, keep_blank_values=True)):
        raise ValueError('URL already contains signing parameters')
    separator = '&' if parts.query else '?'

    if provider == 'cloudfront':
        if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size != 2048:
            raise ValueError('the CloudFront example requires an RSA 2048-bit private key')
        policy = {'Statement': [{'Resource': url, 'Condition': {'DateLessThan': {'AWS:EpochTime': expires}}}]}
        message = json.dumps(policy, separators=(',', ':')).encode('ascii')
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        encoded = base64.b64encode(signature).decode().translate(str.maketrans('+=/', '-_~'))
        return f'{url}{separator}Expires={expires}&Signature={encoded}&Key-Pair-Id={key_name}&Hash-Algorithm=SHA256'

    if provider != 'media-cdn' or not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError('the Media CDN example requires an Ed25519 private key')
    message = f'{url}{separator}Expires={expires}&KeyName={key_name}'
    encoded = base64.urlsafe_b64encode(private_key.sign(message.encode('ascii'))).decode()
    return f'{message}&Signature={encoded}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('provider', choices=['cloudfront', 'media-cdn'])
    parser.add_argument('url')
    parser.add_argument('--key-name', default='example-key')
    parser.add_argument('--private-key', required=True, type=Path)
    parser.add_argument('--expires', required=True, type=int, help='expiration in Unix seconds (GMT)')
    args = parser.parse_args()
    try:
        key = serialization.load_pem_private_key(args.private_key.read_bytes(), password=None)
        result = sign_url(args.provider, args.url, args.key_name, key, args.expires)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    print(result)


if __name__ == '__main__':
    main()
