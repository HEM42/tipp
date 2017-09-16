package TIPP::Site::Plugin::Helpers::Log;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;
use DBIx::Perlish;

sub register
{
    my ( $me, $app ) = @_;

    $app->helper(
        'log.change',
        sub {
            my ( $c, $what, $change, %p ) = @_;
            $what = "N" if $what eq "network";
            $what = "R" if $what eq "range";
            $what = "I" if $what eq "ip";
            $what = "G" if $what eq "group";
            $what = "U" if $what eq "user";
            $what = "?" unless length($what) == 1;
            my $when = $p{when} || time;
            my $dbh = $c->dbh;
            db_insert 'changelog',
              {
                change  => $change,
                who     => $c->current_user,
                what    => $what,
                created => $when,
              };
        }
    );
}


1;
