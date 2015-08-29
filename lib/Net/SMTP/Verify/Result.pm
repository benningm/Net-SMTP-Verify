package Net::SMTP::Verify::Result;

use Moose;

# VERSION
# ABSTRACT: address verification result for a recipient

has 'address' => ( is => 'rw', isa => 'Str', required => 1 );
has 'host' => ( is => 'rw', isa => 'Maybe[Str]' );

has 'has_starttls' => ( is => 'rw', isa => 'Maybe[Bool]' );
has 'has_tlsa' => ( is => 'rw', isa => 'Maybe[Bool]' );

has 'smtp_message' => ( is => 'rw', isa => 'Maybe[Str]' );
has 'smtp_code' => ( is => 'rw', isa => 'Maybe[Int]' );

has 'error' => ( is => 'rw', isa => 'Maybe[Str]' );

1;

