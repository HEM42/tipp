package TIPP::Site::Plugin::Helpers::Ip;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;
use DBIx::Perlish;

sub register
{
    my ( $me, $app ) = @_;

    $app->helper( 'N', sub { my $c = shift; TIPP::NetAddr::IP->new(@_) } );

    $app->helper(
        'ip.calculate_gaps',
        sub {
            my $c = shift;

            my ( $outer, @inner ) = @_;
            my $out = $c->N($outer);
            my $len = $out->masklen();
            my $of  = $out->network;
            my $ol  = $out->broadcast;
            my @in  = sort map { $c->N($_) } @inner;
            my @r;
            for my $in (@in) {
                last unless $of;    # XXX the whole outer range exhausted, no need to continue
                my $if = $c->N( $in->network->addr . "/$len" );
                my $il = $c->N( $in->broadcast->addr . "/$len" );
                if ( $if < $of ) {
                    next;           # XXX the current inner is below outer range, skipping
                } elsif ( $if == $of ) {
                    $of = $il + 1;
                    $of = undef if $of == $out->network;
                } else {
                    push @r, [ $of, $if - 1 ];
                    $of = $il + 1;
                    $of = undef if $of == $out->network;
                }
            }
            if ($of) {
                push @r, [ $of, $ol ];
            }
            my @n;
            for my $r (@r) {
                my ( $f, $l ) = @$r;
                my $len = $f->masklen;
                while ( $f <= $l ) {
                    while ( $f->network < $f || $f->broadcast > $c->N( $l->addr . "/" . $f->masklen ) ) {
                        $f = $c->N( $f->addr . "/" . ( $f->masklen + 1 ) );
                    }
                    push @n, $f;
                    $f = $c->N( $f->broadcast->addr . "/$len" );
                    last if $f->addr eq $l->addr;
                    $f++;
                }
            }
            @n;
        }
    );

    $app->helper(
        'ip.compact',
        sub {
            my $c = shift;
            return NetAddr::IP::Compact(@_);
        }
    );

    $app->helper(
        'ip.info',
        sub {
            my $c    = shift;
            my $ip   = shift;
            my $dbh  = $c->pg->db->dbh;
            my $info = db_fetch {
                my $i : ips;
                $i->ip == $ip;
                $i->invalidated == 0;
            };
            if ($info) {
                my $e = db_fetch {
                    my $e : ip_extras;
                    $e->id == $info->{id};
                };
                %$info = ( %$info, %$e ) if $e;
            } else {
                $info = {};
            }

            $info->{ip}          ||= $ip;
            $info->{id}          ||= 0;
            $info->{invalidated} ||= 0;
            for my $k (qw(descr location phone owner hostname comments)) {
                $info->{$k} ||= "";
                $info->{$k} = $c->u2p( $info->{$k} );
            }

            return $info;
        }
    );
}

package TIPP::NetAddr::IP;
use NetAddr::IP qw(:lower);
use base 'NetAddr::IP';
use overload '""' => sub { $_[0]->version == 4 ? $_[0]->cidr : $_[0]->short . "/" . $_[0]->masklen };

sub ip
{
    $_[0]->version == 4 ? $_[0]->addr : $_[0]->short;
}


1;
