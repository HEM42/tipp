package TIPP::Site::Plugin::Helpers::Search;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;
use DBIx::Perlish;
use Regexp::Common 'net';

sub register
{
    my ( $me, $app ) = @_;

    $app->helper(
        'search.networks',
        sub {
            my $c    = shift;
            my @s    = @_;
            my $only = $c->param("only") || "";
            return () if $only && $only ne "net";
            my @net_sql = ( 'n.invalidated = 0', 'n.class_id = c.id', 'cr.net >>= n.net' );
            my @net_bind;
            for my $t (@s) {
                my $term_sql;
                if ( $t =~ /^(\d+)\.$/ && $1 > 0 && $1 <= 255 ) {
                    $term_sql = "n.net <<= ?";
                    push @net_bind, "$1.0.0.0/8";
                } elsif ( $t =~ /^(\d+)\.(\d+)\.?$/ && $1 > 0 && $1 <= 255 && $2 <= 255 ) {
                    $term_sql = "(n.net <<= ? or n.net >>= ?)";
                    push @net_bind, "$1.$2.0.0/16", "$1.$2.0.0/16";
                } elsif ( $t =~ /^(\d+)\.(\d+)\.(\d+)\.?$/ && $1 > 0 && $1 <= 255 && $2 <= 255 && $3 <= 255 ) {
                    $term_sql = "(n.net <<= ? or n.net >>= ?)";
                    push @net_bind, "$1.$2.$3.0/24", "$1.$2.$3.0/24";
                } elsif ( $t =~ /^$RE{net}{IPv4}$/ ) {
                    $term_sql = "(n.net >>= ?)";
                    push @net_bind, $t;
                } elsif ( $t =~ /^$RE{net}{IPv4}\/(\d+)$/ && $1 <= 32 ) {
                    $term_sql = "(n.net <<= ? or n.net >>= ?)";
                    push @net_bind, $t, $t;
                } else {
                    my $nn = $c->N($t);
                    if ( $nn && $nn->version == 6 ) {
                        if ( $nn->masklen < 128 ) {
                            $term_sql = "(n.net <<= ? or n.net >>= ?)";
                            @net_bind, "$nn", "$nn";
                        } else {
                            $term_sql = "(n.net >>= ?)";
                            push @net_bind, "$nn";
                        }
                    }
                }
                if ($term_sql) {
                    push @net_sql,
                      "(($term_sql) or (n.descr ilike ?) or (n.id in (select net_id from network_tags where tag ilike ?)))";
                } else {
                    push @net_sql, "((n.descr ilike ?) or (n.id in (select net_id from network_tags where tag ilike ?)))";
                }
                push @net_bind, "%$t%", "%$t%";
            }
            my $dbh = $c->dbh;
            my @n   = @{
                $dbh->selectall_arrayref(
                    "select "
                      . "n.net, n.id, n.class_id, c.name as class_name, n.descr, n.created, n.created_by, "
                      . "cr.class_id as parent_class_id, (n.class_id <> cr.class_id) as wrong_class"
                      . " from networks n,classes c,classes_ranges cr where "
                      . join( " and ", @net_sql )
                      . " order by net",
                    { Slice => {} },
                    @net_bind
                  )
                  || []
            };
            if ( @n < 50 || $c->param("all") ) {
                my $id2tag = $c->tags->fetch_for_networks(@n);
                my @ids = map { $_->{id} } @n;
                my %used;
                if (@n) {
                    %used = db_fetch {
                        my $n : networks;
                        my $i : ips;
                        join $n < $i => db_fetch {
                            inet_contains( $n->net, $i->ip );
                            $i->invalidated == 0;
                        };
                        $n->id < -@ids;
                        return -k $n->id, count( $i->id );
                    };
                }
                my $tot_size = 0;
                my $tot_used = 0;
                my $tot_free = 0;
                for my $n (@n) {
                    $n->{created_by} ||= "";
                    $n->{descr} = $c->u2p( $n->{descr} );
                    $n->{tags}  = $c->tags->ref2string( $id2tag->{ $n->{id} } );
                    $c->gen_calculated_params($n);
                    $n->{used} = $used{ $n->{id} } || 0;
                    $n->{unused} = $n->{sz} - $n->{used};
                    if ( $n->{f} == 4 ) {
                        $tot_size += $n->{sz};
                        $tot_used += $n->{used};
                        $tot_free += $n->{unused};
                    }
                }
                return (
                    n       => \@n,
                    nn      => scalar(@n),
                    v4_used => $tot_used,
                    v4_free => $tot_free,
                    v4_size => $tot_size
                );
            } else {
                return (
                    nn          => scalar(@n),
                    net_message => "Too many networks found, try to limit the search, or {view all results anyway}."
                );
            }
        }
    );

    $app->helper(
        'search.ips',
        sub {
            my ( $c, $history, @s ) = @_;
            my $only = $c->param("only") || "";
            my @ip_sql;
            my $name;
            if ($history) {
                return () if $only && $only ne "ip-history";
                @ip_sql = ('i.invalidated <> 0');
                $name   = "hi";
            } else {
                return () if $only && $only ne "ip";
                @ip_sql = ('i.invalidated = 0');
                $name   = "i";
            }
            my @ip_bind;
            for my $t (@s) {
                my @term_sql;
                my $nn = $c->N($t);
                if ( $t =~ /^(\d+)\.$/ && $1 <= 255 ) {

                    # class A
                    push @term_sql, "i.ip <<= ?";
                    push @ip_bind,  "$1.0.0.0/8";
                } elsif ( $t =~ /^(\d+)\.(\d+)(\.?)$/ && $1 <= 255 && $2 <= 255 ) {

                    # class B
                    push @term_sql, "i.ip <<= ?";
                    push @ip_bind, "$1.$2.0.0/16", $t;

                    # last two octets of an IPv4
                    unless ($3) {
                        push @term_sql, "text(i.ip) like ?";
                        push @ip_bind,  "%$t/32";
                    }
                } elsif ( $t =~ /^(\d+)\.(\d+)\.(\d+)(\.?)$/ && $1 <= 255 && $2 <= 255 && $3 <= 255 ) {

                    # class C
                    push @term_sql, "i.ip <<= ?";
                    push @ip_bind,  "$1.$2.$3.0/24";

                    # last three octets of an IPv4
                    unless ($4) {
                        push @term_sql, "text(i.ip) like ?";
                        push @ip_bind,  "%$t/32";
                    }
                } elsif ( $nn && $nn->bits == $nn->masklen ) {

                    # host
                    push @term_sql, "i.ip = ?";
                    push @ip_bind,  $nn->ip;
                } elsif ($nn) {

                    # network
                    push @term_sql, "i.ip <<= ?";
                    push @ip_bind,  "$nn";
                }
                push @term_sql, map {"$_ ilike ?"} qw(i.descr e.location e.phone e.owner e.hostname e.comments);
                push @ip_bind, ("%$t%") x 6;
                push @ip_sql, "(" . join( " or ", @term_sql ) . ")";
            }
            my $dbh = $c->dbh;
            my @i   = @{
                $dbh->selectall_arrayref(
                    "select * from ips i left join ip_extras e on i.id = e.id where " . join( " and ", @ip_sql ) . " order by ip",
                    { Slice => {} }, @ip_bind )
                  || []
            };
            if ( @i <= 64 || $c->param("all") ) {
                for my $i (@i) {
                    for my $k (qw(descr location phone owner hostname comments created_by invalidated_by)) {
                        $i->{$k} ||= "";
                        $i->{$k} = $c->u2p( $i->{$k} );
                    }
                }
                return ( $name => \@i, "n$name" => scalar(@i) );
            } else {
                my @r = ( "n$name" => scalar(@i) );
                if ($history) {
                    push @r,
                      ip_history_message => "Too many historic IPs found, try to limit the search, or {view all results anyway}.";
                } else {
                    push @r, ip_message => "Too many IPs found, try to limit the search, or {view all results anyway}.";
                }
                return @r;
            }
        }
    );
}


1;
