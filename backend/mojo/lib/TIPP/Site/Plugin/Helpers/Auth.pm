package TIPP::Site::Plugin::Helpers::Auth;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

sub register
{
    my ( $me, $app ) = @_;

    $app->helper(
        'current_user',
        sub {
            my $c = shift;
            my ($u) = split /:/, ( $c->req->url->to_abs->userinfo || 'testing:' );
            return $u;
        }
    );
}


1;
