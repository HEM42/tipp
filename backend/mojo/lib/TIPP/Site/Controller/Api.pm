package TIPP::Site::Controller::Api;
use Mojo::Base 'Mojolicious::Controller';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

use DBIx::Perlish;
use Mojo::JSON qw/decode_json/;

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
            login        => $c->get_remote_user(),
            caps         => \%caps,
            linkify      => [ $c->config->{tipp}{linkify} ],
            permissions  => $c->get_permissions(),
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

sub get_permissions
{
    my $c    = shift;
    my $user = $c->get_remote_user();
    my $dbh  = $c->dbh;

    my $default_group_id = $c->config->{tipp}{default_group_id};
    my $gid              = db_fetch {
        my $u : users;

        $u->name eq $user;
        return $u->group_id;
    } || $default_group_id;

    my $json_permissions = db_fetch {
        my $g : groups;

        $g->id == $gid;
        return $g->permissions;
    } || "{}";

    return expand_permissions( eval { decode_json($json_permissions); } || {} );
}

sub expand_permissions
{
    my $p0 = shift;
    my $p1 = {};
    for my $perm (qw(superuser view_changelog view_usage_stats range net ip)) {
        $p1->{$perm} = $p0->{$perm} || 0;
    }
    $p1->{by_class} = {};
    for my $k ( keys %{ $p0->{by_class} || {} } ) {
        for my $perm (qw(range net ip)) {
            $p1->{by_class}{$k}{$perm} = $p0->{by_class}{$k}{$perm} || 0;
        }
    }
    return $p1;
}

sub get_remote_user
{
    my $c = shift;
    my ($u) = split /:/, ( $c->req->url->to_abs->userinfo || 'testing:' );
    return $u;
}


1;
