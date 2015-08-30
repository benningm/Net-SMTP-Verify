package Net::SMTP::Verify::ResultSet;

use Moose;

# VERSION
# ABSTRACT: resultset for Net::SMTP::Verify checks

use Net::SMTP::Verify::Result;

use Data::Dumper;
use JSON;

=head1 DESCRIPTION

This class will hold a set of Net::SMTP::Verify::Result objects.

=head1 SYNOPSIS

  $rs = Net::SMTP::Verify::ResultSet->new;
  $rs->set( [
    'rcpt@domain.de',
    'rcpt2@domain.de',
  ], 'smtp_code', 200);
  $rs->print_text;

=head1 ATTRIBUTES

=head2 results

A HashRef holding the Net::SMTP::Verify::Result objects.

=head1 METHODS

=head2 recipient( $rcpt ), rcpt( $rcpt )

Get the result for address $rcpt.

=head2 recipients(), rcpts()

Get all recipient addresses in the resultset.

=head2 entries()

Returns a list of all Net::SMTP::Verify::Result objects.

=head2 count()

Returns the number of result objects.

=cut

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

=head2 add_result( $result )

Adds a single $result object to the resultset.

=cut

sub add_result {
  my ( $self, $result ) = @_;
  $self->results->{$result->address} = $result;
  return;
}

=head2 set( $rcpt, $field, $params )

If theres no result for $rcpt in the resultset it will create an result object
for the address.

Then it will call the accessor $field with @params.

If $rcpt is a array reference instead of a scalar it will do that for
every address listed in the array.

=cut

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

=head2 dump()

Output all results with Data::Dumper.

=cut

sub dump {
  my $self = shift;
  print Dumper $self->entries;
  return;
}

=head2 dump_json()

Output all results as JSON.

=cut

sub dump_json {
  my $self = shift;
  foreach my $rcpt ( $self->entries ) {
    print to_json { %$rcpt }, {
      pretty => 1,
    };
  }
  return;
}

=head2 print_text()

Output all results as text.

=cut

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

=head2 is_all_success()

Returns true if all object are success.

=cut

sub is_all_success {
  my $self = shift;
  
  foreach my $rcpt ( $self->entries ) {
    if( ! $rcpt->is_success ) {
      return 0;
    }
  }

  return 1;
}

=head2 successfull_rcpts(), success_rcpts()
=head2 error_rcpts()
=head2 temp_error_rcpts()
=head2 perm_error_rcpts()

Returns all successfull|error|temp_error|perm_error result objects.

=cut

sub successfull_rcpts {
  return grep { $_->is_success } shift->entries;
}
*success_rcpts = \&successfull_rcpts;
sub error_rcpts {
  return grep { $_->is_error } shift->entries;
}
sub temp_error_rcpts {
  return grep { $_->is_temp_error } shift->entries;
}
sub perm_error_rcpts {
  return grep { $_->is_perm_error } shift->entries;
}

1;
