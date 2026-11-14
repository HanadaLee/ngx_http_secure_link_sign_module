# ngx_http_secure_link_sign_module

Public-key signature verification for nginx HTTP requests. Supports RSA, RSA-PSS, ECDSA and Ed25519, with optional time validation and conditional configuration.

## Synopsis

```nginx
location /download/ {
    secure_link_sign on;
    secure_link_sign_algorithm rsa-sha256;
    secure_link_sign_public_key /etc/nginx/keys/public.pem;
    secure_link_sign_message "$uri:$arg_expires";
    secure_link_sign_check_token $arg_signature digest=base64url;
    secure_link_sign_check_time $arg_expires range_end=0;

    if ($secure_link_sign != 1) {
        return 403;
    }
}
```

## Installation

Requires the OpenSSL development library, version 1.1.1 or later. The module does not require the nginx HTTP SSL module or a core patch.

Static module:

```sh
./configure --add-module=/path/to/ngx_http_secure_link_sign_module
make
make install
```

Dynamic module:

```sh
./configure --with-compat --add-dynamic-module=/path/to/ngx_http_secure_link_sign_module
make modules
```

```nginx
load_module modules/ngx_http_secure_link_sign_module.so;
```

Add the module to the same nginx source and build configuration as the target installation.

## Conditional configuration

With [ngx_expr_module](https://github.com/HanadaLee/ngx_expr_module), all directives support `when`:

```nginx
expr alternate str_eq $arg_key alternate;

when alternate {
    secure_link_sign_public_key /etc/nginx/keys/alternate.pem;
}

secure_link_sign_public_key /etc/nginx/keys/default.pem;
```

## Directives

### secure_link_sign

| | |
|---|---|
| Syntax | `secure_link_sign on \| off;` |
| Default | `secure_link_sign off;` |
| Context | `http`, `server`, `location`, `when` |

Enables signature verification through the `$secure_link_sign` variable.

### secure_link_sign_algorithm

| | |
|---|---|
| Syntax | `secure_link_sign_algorithm algorithm [format=der\|ieee-p1363];` |
| Default | `secure_link_sign_algorithm rsa-sha256;` |
| Context | `http`, `server`, `location`, `when` |

Sets the signature algorithm.

| Algorithm | Signature scheme |
|---|---|
| `rsa-sha1`, `rsa-sha256`, `rsa-sha384`, `rsa-sha512` | RSA PKCS#1 v1.5 |
| `rsa-pss-sha256`, `rsa-pss-sha384`, `rsa-pss-sha512` | RSA-PSS, with the same MGF1 digest and a salt the size of the digest |
| `ecdsa-sha256`, `ecdsa-sha384`, `ecdsa-sha512` | ECDSA |
| `ed25519` | Ed25519 |

The `format` parameter applies to ECDSA only. The default is ASN.1 DER. `ieee-p1363` accepts fixed-width `R || S`, with each integer padded to the curve size. This is separate from the token's textual encoding.

### secure_link_sign_public_key

| | |
|---|---|
| Syntax | `secure_link_sign_public_key file \| data:value;` |
| Default | — |
| Context | `http`, `server`, `location`, `when` |

Sets a PEM public key in SubjectPublicKeyInfo format (`BEGIN PUBLIC KEY`). Paths and data values can contain variables. Relative paths are resolved against the nginx configuration prefix.

```nginx
secure_link_sign_public_key /etc/nginx/keys/public.pem;
```

```nginx
secure_link_sign_public_key "data:-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
```

```nginx
secure_link_sign_public_key data:$public_key;
```

```nginx
secure_link_sign_public_key $public_key_file;
```

Constant keys are parsed when loading the configuration. Variable keys are evaluated and parsed on each verification. Select keys from trusted configuration; a request-supplied key ID may select a trusted key, but a request-supplied public key must not establish trust.

### secure_link_sign_message

| | |
|---|---|
| Syntax | `secure_link_sign_message value;` |
| Default | — |
| Context | `http`, `server`, `location`, `when` |

Sets the original signed message. The value can contain variables and binary data. Do not supply a precomputed digest, including for Ed25519.

### secure_link_sign_check_token

| | |
|---|---|
| Syntax | `secure_link_sign_check_token value [digest=hex\|base64\|base64url\|bin];` |
| Default | — |
| Context | `http`, `server`, `location`, `when` |

Sets the signature to verify. The value can contain variables. `digest` specifies the token encoding and defaults to `base64`.

| Encoding | Input |
|---|---|
| `hex` | Hexadecimal, either case |
| `base64` | Standard Base64, padded or unpadded |
| `base64url` | URL-safe Base64, padded or unpadded |
| `bin` | Raw signature bytes |

Base64 inputs must have valid padding and zero unused bits. Whitespace and trailing data are rejected.

### secure_link_sign_check_time

| | |
|---|---|
| Syntax | `secure_link_sign_check_time value [range_start=value] [range_end=value] [format=format] [timezone=gmt[+\|-HHMM]];` |
| Default | — |
| Context | `http`, `server`, `location`, `when` |

Checks `range_start <= now - timestamp <= range_end`. Each bound is optional; without either bound, time validation is disabled. The timestamp and bounds can contain variables. Bounds are seconds and accept signed decimal or `0x` hexadecimal integers.

| Format | Timestamp |
|---|---|
| `%s` (default) | Unix seconds |
| `%ms` | Unix milliseconds, truncated to seconds |
| `%x` | Hexadecimal Unix seconds |
| Other | A [strptime()](https://pubs.opengroup.org/onlinepubs/9799919799/functions/strptime.html) format |

Calendar values use GMT by default. `timezone` affects calendar formats only.

```nginx
# An absolute expiration time
secure_link_sign_check_time $arg_expires range_end=0;

# An issue time valid for one hour
secure_link_sign_check_time $arg_issued range_start=0 range_end=3600;
```

The timestamp must be covered by the signature or derived from trusted configuration.

## Variables

`$secure_link_sign` is `1` when signature and configured time checks succeed, and empty otherwise. Verification is reevaluated when the variable is read. The module does not send a response automatically.

## Examples

The following examples validate GET and HEAD requests on a dedicated server. They preserve the original escaped path and application query parameters. Each example fixes the key identity and signature algorithm in trusted configuration. Replace `$scheme://$host` with a trusted public origin if TLS terminates before nginx.

### CloudFront signed URLs

[cloudfront.conf](examples/cloudfront.conf) verifies an RSA-SHA256 signed URL with a canned policy. It requires **[ngx_var_module](https://github.com/HanadaLee/ngx_var_module) with the `tr` operation** to convert CloudFront's Base64 alphabet:

```nginx
var $cf_signature_base64 tr $cf_signature "-_~" "+=/";
```

The signed message is the compact policy JSON containing the original URL and expiration. The example accepts the final parameters in this order: `Expires`, `Signature`, `Key-Pair-Id`, `Hash-Algorithm=SHA256`. Custom policies and signed cookies require their corresponding policy and constraint checks.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out cloudfront.key
openssl pkey -in cloudfront.key -pubout -out cloudfront.pem

python3 examples/sign-url.py cloudfront 'https://cdn.example.com/video.mp4?quality=hd' \
    --private-key cloudfront.key --key-name example-key --expires 1893456000
```

Reference: [CloudFront canned-policy signed URLs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-creating-signed-url-canned-policy.html).

### Google Media CDN signed URLs

[google-media-cdn.conf](examples/google-media-cdn.conf) verifies Ed25519 signatures. It does not require `ngx_var_module`.

The signed message is the complete URL through `Expires` and `KeyName`, excluding the final `Signature` parameter. The example covers full-URL signatures; prefix, cookie and optional policy fields require their corresponding checks.

```sh
openssl genpkey -algorithm ED25519 -out media-cdn.key
openssl pkey -in media-cdn.key -pubout -out media-cdn.pem

python3 examples/sign-url.py media-cdn 'https://media.example.com/video.mp4?quality=hd' \
    --private-key media-cdn.key --key-name example-key --expires 1893456000
```

`KeyName` identifies the Media CDN keyset. Configure the matching trusted public key locally. The Python helper accepts a PEM private key; Google examples using a raw 32-byte Ed25519 seed produce the same signatures for the same key and message.

Reference: [Generate Media CDN signatures](https://docs.cloud.google.com/media-cdn/docs/generate-signatures).

Both commands use [sign-url.py](examples/sign-url.py), which requires the Python `cryptography` package. `--expires` is a Unix timestamp in GMT. Query-parameter removal after verification is optional.

## Testing

Tests use nginx-tests and independently generated Python `cryptography` signatures.

```sh
TEST_NGINX_BINARY=/path/to/nginx \
    prove -I /path/to/nginx-tests/lib t
```

The test build includes `ngx_var_module`. Set `TEST_NGINX_EXPR=1` for conditional tests when `ngx_expr_module` is compiled in. CI covers static and dynamic builds, builds without `ngx_expr_module`, and AddressSanitizer/UndefinedBehaviorSanitizer.

## Changes

See [CHANGELOG.md](CHANGELOG.md).

## Contributing

Include an nginx regression test with behavior changes and follow nginx C style.

## Author

Hanada <im@hanada.info>

## License

[BSD 2-Clause License](LICENSE).
