package TIPP::Site::Plugin::Helpers::Export;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;
use DBIx::Perlish;
use Text::CSV_XS;

sub register
{
    my ( $me, $app ) = @_;
    $app->helper(
        'export.range',
        sub {
            my ( $c, $range_net, %p ) = @_;
            my $dbh  = $c->dbh;
            my $range_descr = db_fetch {
                my $cr : classes_ranges;
                $cr->net eq $range_net;
                return $cr->descr;
            };
            my @nets = db_fetch {
                my $n : networks;
                $n->invalidated == 0;
                inet_contains( $range_net, $n->net );
                sort $n->net;
                return $n->net;
            };
            if ( $p{with_free} ) {
                my @miss = $c->calculate_gaps( $range_net, @nets );
                @nets = sort { $c->N($a) cmp $c->N($b) } @nets, @miss;
            }
            return { error => "No networks defined in $range_net" } unless @nets;

            my @csv;
            my $first = 1;
            for my $net (@nets) {
                my $r = $c->export->net( $net, %p );
                if ( $r && ref($r) && ref($r) eq "HASH" && !$r->{error} ) {
                    my @c = @{ $r->{content} };
                    shift @c unless $first;
                    $first = 0;
                    push @csv, @c;
                } else {
                    return $r;
                }
            }
            my $filename = sprintf "%s_%s", $range_descr, $range_net;
            $filename =~ s/\//-/g;
            return {
                filename => "$filename.csv",
                content  => \@csv,
            };
        }
    );

    $app->helper(
        'export.net',
        sub {
            my ( $c, $net_net, %p ) = @_;

            my $dbh = $c->dbh;
            my $net = db_fetch {
                my $n : networks;
                my $c : classes;
                $n->net == $net_net;
                $n->class_id == $c->id;
                $n->invalidated == 0;
                return $n, class_name => $c->name;
            };
            if ( $p{with_free} && !$net ) {
                my $cn = db_fetch {
                    my $cr : classes_ranges;
                    my $cs : classes;
                    inet_contains( $cr->net, $net_net );
                    $cr->class_id == $cs->id;
                    return $cs->name;
                };
                $net = {
                    id         => 0,
                    net        => $net_net,
                    class_id   => 0,
                    descr      => "[free]",
                    class_name => $cn || "unknown",
                };
            }
            return { error => "No such network (maybe someone else changed it?)" }
              unless $net;
            $net->{nn}    = $c->N( $net->{net} );
            $net->{base}  = $net->{nn}->network->addr;
            $net->{mask}  = $net->{nn}->mask;
            $net->{bits}  = $net->{nn}->masklen;
            $net->{sbits} = "/" . $net->{nn}->masklen;
            my $ips;
            $ips = $c->get_addresses( $net->{net} ) unless $p{ignore_ip};
            my $format = $c->cookie("ipexport");
            $format = $format || "iH";

            my %header = (
                C => "Network class",
                D => "Network description",
                H => "Hostname/description",
                N => "Network",
                d => "Description",
                h => "Hostname",
                i => "IP Address",
                l => "Location",
                o => "Owner/responsible",
                p => "Phone",
                B => "Network base",
                M => "Network mask",
                S => "Network bits",
                3 => "Network /bits",
            );
            my %ip_map = (
                d => "descr",
                h => "hostname",
                i => "ip",
                l => "location",
                o => "owner",
                p => "phone",
            );
            my %net_map = (
                C => "class_name",
                D => "descr",
                N => "net",
                B => "base",
                M => "mask",
                S => "bits",
                3 => "sbits",
            );
            my @f = split //, $format;
            my $csv = Text::CSV_XS->new( { binary => 1 } ) or die "Cannot use CSV: " . Text::CSV->error_diag();
            my @csv;

            my @v;
            for my $f (@f) {
                if ( $net_map{$f} ) {
                    push @v, $header{$f};
                } elsif ( $ip_map{$f} && !$p{ignore_ip} ) {
                    push @v, $header{$f};
                } elsif ( $f eq "H" && !$p{ignore_ip} ) {
                    push @v, $header{$f};
                }
            }
            $csv->combine(@v);
            push @csv, $csv->string;

            if ( $p{ignore_ip} ) {
                @v = ();
                for my $f (@f) {
                    if ( $net_map{$f} ) {
                        push @v, $net->{ $net_map{$f} } || "";
                    }
                }
                $csv->combine(@v);
                push @csv, $csv->string;
            } else {
                for my $ip (@$ips) {
                    @v = ();
                    for my $f (@f) {
                        if ( $f eq "H" ) {
                            if ( $ip->{hostname} && $ip->{descr} ) {
                                push @v, "$ip->{hostname}: $ip->{descr}";
                            } elsif ( $ip->{hostname} ) {
                                push @v, $ip->{hostname};
                            } else {
                                push @v, $ip->{descr} || "";
                            }
                        } elsif ( $ip_map{$f} ) {
                            push @v, $ip->{ $ip_map{$f} } || "";
                        } elsif ( $net_map{$f} ) {
                            push @v, $net->{ $net_map{$f} } || "";
                        } else {
                            die "Internal error finding out what field $f means\n";
                        }
                    }
                    $csv->combine(@v);
                    push @csv, $csv->string;
                }
            }

            my $filename = $net->{net};
            $filename =~ s/\//-/g;
            return {
                filename => "$filename.csv",
                content  => \@csv,
            };
        }
    );
}


1;
