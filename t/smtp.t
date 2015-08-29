#!/usr/bin/env perl

use warnings;
use strict;

use Test::More tests => 3;
use Test::Exception;
use Net::DNS::Resolver;

use_ok('Net::SMTP::Verify');
my $v = Net::SMTP::Verify->new(
  logging_callback => sub { diag(shift) },
);

isa_ok( $v, 'Net::SMTP::Verify');

lives_ok {
  my $r = $v->check(100000, 'bla@internetteam.de', 'ich@markusbenning.de', 'markus.benning@markusbenning.de', 'me@w3r3wolf.de');
} 'check mail address ich@markusbenning.de';
