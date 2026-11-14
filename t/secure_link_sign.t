#!/usr/bin/perl

# Tests for signature verification, key sources and conditional configuration.

###############################################################################

use warnings;
use strict;

use FindBin;
use JSON::PP qw/decode_json/;
use Test::More;
use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()
    ->has(qw/http rewrite ngx_var_module ngx_http_secure_link_sign_module/);

system('python3', "$FindBin::Bin/generate.py", $t->testdir()) == 0
    or BAIL_OUT('could not generate signature vectors');

my $cases = decode_json($t->read_file('cases.json'));
$t->plan(scalar @$cases);
$t->write_file_expand('nginx.conf', $t->read_file('generated.conf'))->run();

for my $case (@$cases) {
    my $headers = "X-Token: $case->{token}\r\n";
    for my $name (sort keys %{$case->{headers}}) {
        $headers .= "$name: $case->{headers}{$name}\r\n";
    }

    my $response = http("GET $case->{uri} HTTP/1.0\r\n"
        . "Host: localhost\r\n$headers\r\n");
    is(http_content($response), $case->{expected}, $case->{name});
}

###############################################################################
