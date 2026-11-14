#!/usr/bin/perl

# Tests for CloudFront and Google Media CDN examples over HTTP and HTTPS.

###############################################################################

use warnings;
use strict;
use FindBin;
use JSON::PP qw/decode_json/;
use Test::More;
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite ngx_var_module
    ngx_http_secure_link_sign_module/)->has_daemon('openssl');
eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;

system('python3', "$FindBin::Bin/generate_examples.py", $t->testdir()) == 0
    or BAIL_OUT('could not generate example requests');
my $cases = decode_json($t->read_file('cases.json'));
$t->plan(scalar @$cases);
$t->write_file_expand('nginx.conf', $t->read_file('generated.conf'))->run();

for my $case (@$cases) {
    my $response = http("$case->{method} $case->{uri} HTTP/1.0\r\n"
        . "Host: $case->{host}\r\n\r\n", SSL => $case->{ssl});
    like($response, qr/^HTTP\/1\.[01] $case->{status} /, $case->{name});
}

###############################################################################
