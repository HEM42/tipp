package TIPP::Site::Controller::Api;
use Mojo::Base 'Mojolicious::Controller';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

use DBIx::Perlish;

# == PART OF THE OLD API ==

sub handle_config
{
    my $c = shift;
    my %caps;
    for ( keys %TIPP::Site::Controller::Api:: ) {
        $caps{$1} = 1 if /^handle_(\w+)$/;
    }

    $c->render(
        json => {
            extra_header => $c->config->{tipp}{extra_header},
            login        => $c->current_user,
            caps         => \%caps,
            linkify      => [ $c->config->{tipp}{linkify} ],
            permissions  => $c->perms->get,
        }
    );
}

sub handle_root
{
    my $c = shift;

    my $dbh = $c->dbh;
    my @c   = db_fetch {
        my $t : classes;
        sort $t->ord;
    };

    $c->render( json => \@c );
}

# == PART OF THE NEW API ==

sub ping
{
    my $c = shift;

    $c->render( json => { response => 'pong' } );
}

# == END OF HANDLERS ==


1;
