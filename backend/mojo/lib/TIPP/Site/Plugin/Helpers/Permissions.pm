package TIPP::Site::Plugin::Helpers::Permissions;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

use DBIx::Perlish;
use Mojo::JSON qw/decode_json/;

sub register
{
    my ( $me, $app ) = @_;

    $app->helper(
        'perms.get',
        sub {
            my $c    = shift;
            my $user = $c->current_user;
            my $dbh  = $c->pg->db->dbh;

            my $default_group_id = $c->config->{tipp}{default_group_id};
            my $gid              = db_fetch {
                my $u : users;

                $u->name eq $user;
                return $u->group_id;
            };
            $gid ||= $default_group_id;

            my $json_permissions = db_fetch {
                my $g : groups;

                $g->id == $gid;
                return $g->permissions;
            };
            $json_permissions ||= "{}";

            return $c->perms->expand( eval { decode_json($json_permissions); } || {} );
        }
    );

    $app->helper(
        'perms.expand',
        sub {
            my $c  = shift;
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
    );

    $app->helper(
        'perms.check',
        sub {
            my ( $c, $what, $class_id ) = @_;
            my $perms = $c->perms->get;
            return 1 if $perms->{superuser};
            if ($class_id) {
                return ( $perms->{by_class}{$class_id} && $perms->{by_class}{$class_id}{$what} ) || $perms->{$what};
            } elsif ( $what =~ /^(?:net|range|ip)$/ ) {
                for my $v ( values %{ $perms->{by_class} } ) {
                    return 1 if $v->{$what};
                }
            }
            return $perms->{$what};
        }
    );
}


1;
