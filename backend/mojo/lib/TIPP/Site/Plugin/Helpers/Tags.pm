package TIPP::Site::Plugin::Helpers::Tags;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

sub register
{
    my ( $me, $app ) = @_;
    $app->helper(
        'tags.ref2string',
        sub {
            my $c = shift;
            return "" unless ref( $_[0] );
            $c->tags->to_string( @{ $_[0] } );
        }
    );

    $app->helper(
        'tags.to_string',
        sub {
            my $c = shift;
            return $c->tags->normalize_string( join " ", @_ );
        }
    );

    $app->helper(
        'tags.normalize_string',
        sub {
            my $c = shift;
            my %tags = map { $_ => 1 } split /\s+/, $_[0];
            return join " ", sort keys %tags;
        }
    );
}


1;
