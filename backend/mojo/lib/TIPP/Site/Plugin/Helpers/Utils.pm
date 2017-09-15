package TIPP::Site::Plugin::Helpers::Utils;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;
use Mojo::Util 'decode', 'encode';

sub register
{
    my ( $me, $app ) = @_;

    $app->helper( 'u2p', sub { my $c = shift; decode( "utf-8", shift ) } );

    $app->helper(
        'jsparam',
        sub {
            my $c = shift;
            my $v = $c->param( $_[0] ) || "";
            $v = "" if $v eq "false";
            $v = "" if $v eq "undefined";
            $v;
        }
    );
    $app->helper(
        'gen_calculated_params',
        sub {
            my $me = shift;
            my $c  = shift;
            my $n  = $me->N( $c->{net} );
            $c->{net}          = "$n";
            $c->{first}        = $n->network->ip;
            $c->{last}         = $n->broadcast->ip;
            $c->{second}       = $n->first->ip;
            $c->{next_to_last} = $n->last->ip;
            $c->{sz}           = 2**( $n->bits - $n->masklen );
            $c->{bits}         = $n->masklen;
            $c->{f}            = $n->version;

            if ( $c->{net} =~ /^10\.|^172\.|^192\.168\.|^100\./ ) {
                if ( $c->{net} =~ /^10\./ ) {
                    $c->{private} = 1;
                } elsif ( $c->{net} =~ /^172\.(\d+)\./ && $1 >= 16 && $1 <= 31 ) {
                    $c->{private} = 1;
                } elsif ( $c->{net} =~ /^192\.168\./ ) {
                    $c->{private} = 1;
                } elsif ( $c->{net} =~ /^100\.(\d+)\./ && $1 >= 64 && $1 <= 127 ) {
                    $c->{private} = 1;
                }
            }
        }
    );
}


1;
