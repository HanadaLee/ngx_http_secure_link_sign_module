#!/usr/bin/env python3
"""Generate signed URL interoperability cases for the example configurations."""

import base64
import datetime
import importlib.util
import json
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.x509.oid import NameOID


def main(root):
    repo = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('sign_url', repo/'examples/sign-url.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    keys = {'cloudfront': rsa.generate_private_key(65537, 2048),
            'media-cdn': ed25519.Ed25519PrivateKey.generate()}
    expires = int(time.time()) + 3600
    servers, cases = [], []

    # A certificate for the HTTPS transport tests, independent of URL signing.
    tls_key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(days=1))
            .not_valid_after(now+datetime.timedelta(days=1)).sign(tls_key, hashes.SHA256()))
    (root/'tls.key').write_bytes(tls_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (root/'tls.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def add(label, url, status=200, method='GET', host=None):
        p = urlsplit(url)
        cases.append(dict(name=label, uri=p.path+('?' + p.query if p.query else ''),
                          host=host or p.hostname, ssl=p.scheme=='https',
                          status=status, method=method))

    for provider, key in keys.items():
        host = provider + '.example.com'
        pub = provider + '.pem'
        (root/pub).write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        filename = 'cloudfront.conf' if provider == 'cloudfront' else 'google-media-cdn.conf'
        text = (repo/'examples'/filename).read_text()
        text = text.replace('/etc/nginx/keys/'+('cloudfront.pem' if provider=='cloudfront' else 'media-cdn.pem'), pub)
        servers.append(f'''server {{
            listen 127.0.0.1:8080;
            listen 127.0.0.1:8443 ssl;
            server_name {host};
            ssl_certificate tls.pem;
            ssl_certificate_key tls.key;
            {text}
            location / {{ return 200 "accepted"; }}
        }}''')
        for scheme in ['http', 'https']:
            for path in ['/video.mp4', '/a%20b/%E4%B8%AD.mp4', '/video.mp4?quality=hd&x=%2F+%3F', '/a&b.mp4', '/a.mp4?x=1&x=2']:
                url = f'{scheme}://{host}{path}'
                signed = helper.sign_url(provider, url, 'example-key', key, expires)
                # Independent reference assembly, following the provider formats.
                if provider == 'cloudfront':
                    message = ('{"Statement":[{"Resource":"'+url+'","Condition":{"DateLessThan":{"AWS:EpochTime":'+str(expires)+'}}}]}').encode()
                    sig = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
                    token = base64.b64encode(sig).decode().replace('+','-').replace('=','_').replace('/','~')
                    reference = f'{url}{"&" if "?" in url else "?"}Expires={expires}&Signature={token}&Key-Pair-Id=example-key&Hash-Algorithm=SHA256'
                else:
                    message = f'{url}{"&" if "?" in url else "?"}Expires={expires}&KeyName=example-key'
                    raw = key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
                    sig = ed25519.Ed25519PrivateKey.from_private_bytes(raw).sign(message.encode())
                    reference = message+'&Signature='+base64.urlsafe_b64encode(sig).decode()
                assert reference == signed, provider + ' signer parity'
                add(provider+' '+scheme+' '+path, signed)
                add(provider+' HEAD '+path, signed, method='HEAD')
                add(provider+' POST '+path, signed, 403, 'POST')
                add(provider+' altered path '+path, signed.replace(path.split('?')[0], '/changed', 1), 403)
                add(provider+' expiry tamper '+path, signed.replace(str(expires),str(expires+1)), 403)
                add(provider+' extra parameter '+path, signed+'&extra=1', 403)
                add(provider+' wrong host '+path, signed, 403, host='wrong.example.com')
                if '?' not in path:
                    add(provider+' wrong delimiter '+path, signed.replace('?Expires=', '&Expires='), 403)
            unsigned = f'{scheme}://{host}/video.mp4'
            add(provider+' unsigned', unsigned, 403)
            add(provider+' expired', helper.sign_url(provider,unsigned,'example-key',key,expires-7200),403)
            signed=helper.sign_url(provider,unsigned,'example-key',key,expires)
            add(provider+' wrong key ID',signed.replace('example-key','unknown-key'),403)
            add(provider+' duplicate expiry',signed.replace('?Expires=',f'?Expires={expires}&Expires='),403)
            add(provider+' duplicate signature',signed+'&Signature=bad',403)
            add(provider+' wrong scheme',signed.replace(scheme+'://', ('https' if scheme=='http' else 'http')+'://'),403)
            token='Signature='
            pos=signed.index(token)+len(token)
            add(provider+' corrupted signature',signed[:pos]+('B' if signed[pos]=='A' else 'A')+signed[pos+1:],403)

    config='''%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
'''+ '\n'.join(servers)+'\n}\n'
    (root/'generated.conf').write_text(config)
    (root/'cases.json').write_text(json.dumps(cases))


if __name__=='__main__':
    main(Path(sys.argv[1]))
