#!/usr/bin/env python3
"""Generate independent signatures and nginx integration cases."""

import base64
import json
import os
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils


def main(root):
    keys = {
        'rsa': rsa.generate_private_key(65537, 2048),
        'other': rsa.generate_private_key(65537, 2048),
        'ec': ec.generate_private_key(ec.SECP256R1()),
        'ec384': ec.generate_private_key(ec.SECP384R1()),
        'ec521': ec.generate_private_key(ec.SECP521R1()),
        'ed': ed25519.Ed25519PrivateKey.generate(),
    }
    for name, key in keys.items():
        (root / (name + '.pem')).write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    (root / 'private.pem').write_bytes(keys['rsa'].private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (root / 'bad.pem').write_text('not a public key')

    cases, locations = [], []
    now = int(time.time())
    def case(name, path, sig, expected='1', headers=None):
        cases.append(dict(name=name, uri=path, token=sig, expected=expected,
                          headers=headers or {}))
    def location(path, directives='', response='$secure_link_sign'):
        locations.append(f'location = {path} {{ {directives} return 200 "{response}"; }}')
    def encode(raw):
        return base64.b64encode(raw).decode()
    def sign(key='rsa', digest=256, pss=False, message=b'payload'):
        k = keys[key]
        if key == 'ed':
            return k.sign(message)
        md = getattr(hashes, 'SHA' + str(digest))()
        if key.startswith('ec'):
            return k.sign(message, ec.ECDSA(md))
        pad = padding.PSS(mgf=padding.MGF1(md), salt_length=md.digest_size) if pss else padding.PKCS1v15()
        return k.sign(message, pad, md)

    for family, key, digests in [('rsa', 'rsa', [1, 256, 384, 512]),
                                  ('rsa-pss', 'rsa', [256, 384, 512]),
                                  ('ecdsa', 'ec', [256, 384, 512]),
                                  ('ed25519', 'ed', [None])]:
        for digest in digests:
            name = family if digest is None else f'{family}-sha{digest}'
            path = '/' + name
            location(path, f'secure_link_sign_algorithm {name}; secure_link_sign_public_key {key}.pem;')
            raw = sign(key, digest, family == 'rsa-pss')
            case(name, path, encode(raw))
            case(name + ' changed message', path, encode(raw), '', {'X-Message': 'tampered'})
            case(name + ' truncated signature', path, encode(raw[:-1]), '')
            case(name + ' appended signature', path, encode(raw + b'\0'), '')
            bad = bytearray(raw); bad[len(bad)//2] ^= 1
            case(name + ' tampered signature', path, encode(bad), '')

    for key, digest, width in [('ec', 256, 32), ('ec384', 384, 48), ('ec521', 512, 66)]:
        path = '/p1363-' + key
        location(path, f'secure_link_sign_algorithm ecdsa-sha{digest} format=ieee-p1363; secure_link_sign_public_key {key}.pem;')
        raw = sign(key, digest)
        r, s = utils.decode_dss_signature(raw)
        fixed = r.to_bytes(width, 'big') + s.to_bytes(width, 'big')
        case(key + ' fixed width', path, encode(fixed))
        case(key + ' DER in fixed width mode', path, encode(raw), '')
        case(key + ' short fixed width', path, encode(fixed[:-1]), '')

    raw = sign()
    b64 = encode(raw)
    url = base64.urlsafe_b64encode(raw).decode()
    location('/default')
    location('/hex', 'secure_link_sign_check_token $http_x_token digest=hex;')
    location('/url', 'secure_link_sign_check_token $http_x_token digest=base64url;')
    location('/bin', 'var $decoded hex_decode $http_x_token; secure_link_sign_check_token $decoded digest=bin;')
    for path, value in [('/default', b64), ('/default', b64.rstrip('=')),
                        ('/url', url), ('/url', url.rstrip('=')),
                        ('/hex', raw.hex()), ('/hex', raw.hex().upper()),
                        ('/bin', raw.hex())]:
        case('encoding ' + path + ' ' + str(len(value)), path, value)
    for label, value in [('missing', ''), ('oversized', 'A'*4096),
                         ('trailing junk', b64+'junk'), ('extra padding', b64+'='),
                         ('early padding', '='+b64[1:]), ('whitespace', b64[:4]+' '+b64[4:]),
                         ('wrong alphabet', url), ('pad bits', b64[:-3]+'B==')]:
        case(label, '/default', value, '')
    case('odd hex', '/hex', raw.hex()+'0', '')
    case('invalid hex', '/hex', 'zz'+raw.hex()[2:], '')
    case('short binary', '/bin', raw[:-1].hex(), '')
    case('oversized binary', '/bin', (raw*2).hex(), '')

    pem = (root/'rsa.pem').read_text().replace('\n', '\\n')
    location('/inline', f'secure_link_sign_public_key "data:{pem}";')
    location('/data', 'secure_link_sign_public_key data:$test_pem;')
    location('/file', 'secure_link_sign_public_key $test_file;')
    location('/key-switch', 'secure_link_sign_public_key $selected_key;')
    for path in ['/inline', '/data', '/file', '/key-switch']:
        case('public key source ' + path, path, b64)
    for key in ['other', 'bad', 'missing', 'private', 'ed']:
        case('key selection ' + key, '/key-switch?key='+key, b64, '')
    case('key selection changes valid signer', '/key-switch?key=other', encode(sign('other')))
    location('/disabled', 'secure_link_sign off;')
    case('disabled', '/disabled', b64, '')
    location('/reevaluate', '''secure_link_sign_message $payload;
        set $payload payload; set $first $secure_link_sign;
        set $payload changed; set $second $secure_link_sign;''', '$first|$second')
    case('message reevaluation', '/reevaluate', b64, '1|')
    location('/key-reevaluate', '''secure_link_sign_public_key $key_path;
        set $key_path rsa.pem; set $first $secure_link_sign;
        set $key_path other.pem; set $second $secure_link_sign;''', '$first|$second')
    case('key reevaluation', '/key-reevaluate', b64, '1|')
    location('/empty', 'secure_link_sign_message ""; secure_link_sign_algorithm ed25519; secure_link_sign_public_key ed.pem;')
    case('empty Ed25519 message', '/empty', encode(sign('ed', message=b'')))
    location('/pss-mismatch', 'secure_link_sign_algorithm rsa-pss-sha256;')
    case('PKCS1 rejected by PSS', '/pss-mismatch', b64, '')
    pss = keys['rsa'].sign(b'payload', padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0), hashes.SHA256())
    case('PSS wrong salt length', '/pss-mismatch', encode(pss), '')
    pss = keys['rsa'].sign(b'payload', padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=32), hashes.SHA256())
    case('PSS wrong MGF digest', '/pss-mismatch', encode(pss), '')

    location('/expiry', 'secure_link_sign_check_time $arg_ts range_end=0;')
    for ts, expected in [(now+3600,'1'), (now-60,''), (0,''), (-1,''), ('bad',''), ('92233720368547758070','')]:
        case('expiry '+str(ts), '/expiry?ts='+str(ts), b64, expected)
    location('/range', 'secure_link_sign_check_time $arg_ts range_start=$arg_start range_end=$arg_end;')
    for start,end,expected in [('-3600','3600','1'),('30','-30',''),('bad','30',''),('-30','bad',''),('','30',''),('-9223372036854775807','9223372036854775807','1')]:
        case('range '+start+':'+end, f'/range?ts={now}&start={start}&end={end}', b64, expected)
    location('/ms', 'secure_link_sign_check_time $arg_ts format=%ms range_end=0;')
    case('milliseconds', f'/ms?ts={now+3600}123', b64)
    case('bad milliseconds', f'/ms?ts={now+3600}bad', b64, '')
    location('/hex-time', 'secure_link_sign_check_time $arg_ts format=%x range_end=0;')
    case('hex time', f'/hex-time?ts={now+3600:x}', b64)
    location('/date', 'secure_link_sign_check_time $http_x_date format=%Y-%m-%dT%H:%M:%S timezone=gmt range_end=0;')
    date=time.strftime('%Y-%m-%dT%H:%M:%S',time.gmtime(now+3600))
    case('GMT date', '/date', b64, headers={'X-Date':date})

    expr = ''
    if os.environ.get('TEST_NGINX_EXPR') == '1':
        expr='expr alternate str_eq $arg_mode alternate;'
        location('/when', '''when alternate {
            secure_link_sign_public_key ed.pem;
            secure_link_sign_algorithm ed25519;
            secure_link_sign_message alternate;
            secure_link_sign_check_token $http_x_token digest=base64url;
            secure_link_sign_check_time $arg_ts range_end=0;
        }''')
        case('conditional fallback', '/when', b64)
        case('conditional key algorithm message token time', f'/when?mode=alternate&ts={now+3600}',
             base64.urlsafe_b64encode(sign('ed',message=b'alternate')).decode())
        case('conditional expiry', f'/when?mode=alternate&ts={now-60}',
             base64.urlsafe_b64encode(sign('ed',message=b'alternate')).decode(), '')
        location('/when-reevaluate', '''expr changed str_eq $mode changed;
            when changed { secure_link_sign off; }
            set $mode original; set $first $secure_link_sign;
            set $mode changed; set $second $secure_link_sign;''', '$first|$second')
        case('condition reevaluation', '/when-reevaluate', b64, '1|')

    config=f'''%%TEST_GLOBALS%%
daemon off;
events {{}}
http {{
    %%TEST_GLOBALS_HTTP%%
    map $http_x_message $test_message {{ "" payload; default $http_x_message; }}
    map $host $test_pem {{ default "{pem}"; }}
    map $host $test_file {{ default rsa.pem; }}
    map $arg_key $selected_key {{ default rsa.pem; other other.pem; bad bad.pem;
        missing missing.pem; private private.pem; ed ed.pem; }}
    secure_link_sign on;
    secure_link_sign_public_key rsa.pem;
    secure_link_sign_message $test_message;
    secure_link_sign_check_token $http_x_token;
    server {{
        listen 127.0.0.1:8080;
        {expr}
        {chr(10).join(locations)}
    }}
}}
'''
    (root/'generated.conf').write_text(config)
    (root/'cases.json').write_text(json.dumps(cases))


if __name__ == '__main__':
    main(Path(sys.argv[1]))
