#!/usr/bin/perl

# Tests for configuration errors.

###############################################################################

use warnings;
use strict;
use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my @cases = (
    ['secure_link_sign_algorithm sha256;', qr/invalid signature algorithm/, 'unknown algorithm'],
    ['secure_link_sign_algorithm ed25519 format=der;', qr/only with ECDSA/, 'format with Ed25519'],
    ['secure_link_sign_algorithm ecdsa-sha256 format=raw;', qr/invalid parameter/, 'unknown ECDSA format'],
    ['secure_link_sign_algorithm rsa-sha256; secure_link_sign_algorithm rsa-sha512;', qr/duplicate/, 'duplicate algorithm'],
    ['secure_link_sign_public_key missing.pem;', qr/could not open public key/, 'missing key'],
    ['secure_link_sign_public_key data:bad;', qr/could not parse PEM public key/, 'bad inline key'],
    ['secure_link_sign_public_key "";', qr/invalid public key/, 'empty key'],
    ['secure_link_sign_check_token value digest=base64suffix;', qr/invalid token format/, 'digest suffix'],
    ['secure_link_sign_check_token one; secure_link_sign_check_token two;', qr/duplicate/, 'duplicate token'],
    ['secure_link_sign_check_time 1 range_start=;', qr/invalid numeric value/, 'empty start'],
    ['secure_link_sign_check_time 1 range_end=bad;', qr/invalid numeric value/, 'invalid end'],
    ['secure_link_sign_check_time 1 range_end=999999999999999999999;', qr/invalid numeric value/, 'overflow'],
    ['secure_link_sign_check_time 1 range_end=0 range_end=1;', qr/duplicate range_end/, 'duplicate end'],
    ['secure_link_sign_check_time 1 format=%s format=%ms;', qr/duplicate format/, 'duplicate format'],
    ['secure_link_sign_check_time 1 timezone=gmt+2400;', qr/invalid timezone offset/, 'invalid timezone'],
);

my $t = Test::Nginx->new()->has(qw/http ngx_http_secure_link_sign_module/)
    ->plan(2 * scalar @cases);

for my $case (@cases) {
    my ($directive, $expected, $name) = @$case;
    $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http { $directive }
EOF
    my $output = $t->dump_config();
    isnt($?, 0, "$name is rejected");
    like($output, $expected, "$name diagnostic");
}

###############################################################################
