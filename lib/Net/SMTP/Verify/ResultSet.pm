package Net::SMTP::Verify::ResultSet;

use Moose;

# VERSION
# ABSTRACT: resultset for Net::SMTP::Verify checks

use Net::SMTP::Verify::Result;

use Data::Dumper;
use JSON;

has 'results' => (
  is => 'ro', isa => 'HashRef[Net::SMTP::Verify::Result]', lazy => 1,
  default => sub { {} },
  traits => [ 'Hash' ],
  handles => {
    'recipient' => 'get',
    'recipients' => 'keys',
    'entries' => 'values',
    'count' => 'count',
  },
);

# install shortcuts
*rcpt = \&recipient;
*rcpts = \&recipients;

sub add_result {
  my ( $self, $result ) = @_;
  $self->results->{$result->address} = $result;
  return;
}

sub set {
  my ( $self, $rcpts, $field, @params ) = @_;
  if( ! ref $rcpts ) {
    $rcpts = [ $rcpts ];
  }

  foreach my $rcpt ( @$rcpts ) {
    my $result = $self->rcpt( $rcpt );
    if( ! defined $result ) {
      $result = Net::SMTP::Verify::Result->new(
        address => $rcpt,
      );
      $self->add_result( $result );
    }
    $result->$field( @params );
  }

  return;
}

sub dump {
  my $self = shift;
  print Dumper $self->entries;
  return;
}

sub dump_json {
  my $self = shift;
  foreach my $rcpt ( $self->entries ) {
    print to_json { %$rcpt }, {
      pretty => 1,
    };
  }
  return;
}

sub print_text {
  my $self = shift;

  foreach my $rcpt ( $self->entries ) {
    print $rcpt->{'address'}.":\n";
    foreach my $field ( keys %$rcpt ) {
      if( $field eq 'address') {
        next;
      }
      print "  $field: ".$rcpt->{$field}."\n";
    }
  }

  return;
}

1;
