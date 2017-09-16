package TIPP::Site::Plugin::Helpers::Tags;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;
use DBIx::Perlish;

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

    $app->helper(
        'tags.fetch_string_for_id',
        sub {
            my $c    = shift;
            my $id   = shift;
            my $dbh  = $c->dbh;
            my @tags = db_fetch {
                my $t : network_tags;
                $t->net_id == $id;
                return $t->tag;
            };
            return $c->tags->normalize_string( join " ", map { $c->u2p($_) } @tags );
        }
    );

    $app->helper(
        'tags.insert_string',
        sub {
            my ( $c, $id, $tags ) = @_;
            $c->tags->insert( $id, tagstring2tags($tags) );
        }
    );

    $app->helper(
        'tags.insert',
        sub {
            my ( $c, $id, @tags ) = @_;
            my $dbh = $c->dbh;
            for my $tag (@tags) {
                db_insert 'network_tags',
                  {
                    net_id => $id,
                    tag    => $tag,
                  };
            }
        }
    );

    $app->helper(
        'tags.insert_string',
        sub {
            my ( $c, $id, $tags ) = @_;
            $c->tags->insert( $id, $c->tags->string2tags($tags) );
        }
    );

    $app->helper(
        'tags.string2tags',
        sub {
            my $c = shift;
            return split /\s+/, $c->tags->normalize_string( $_[0] );
        }
    );

    $app->helper(
        'tags.fetch_for_id',
        sub {
            my $c = shift;
            return split /\s+/, $c->fetch_string_for_id(@_);
        }
    );

    $app->helper(
        'tags.fetch_for_ids',
        sub {
            my $c   = shift;
            my @ids = @_;
            return {} unless @ids;
            my %id2tag;
            my $dbh  = $c->dbh;
            my @tags = db_fetch {
                my $t : network_tags;
                $t->net_id < -@ids;
                return $t->net_id, $t->tag;
            };
            for my $t (@tags) {
                push @{ $id2tag{ $t->{net_id} } }, $c->u2p( $t->{tag} );
            }
            return \%id2tag;
        }
    );
    $app->helper(
        'tags.fetch_string_for_network',
        sub {
            my $c = shift;
            return $c->fetch_string_for_id($_[0]->{id});
        }
    );

    $app->helper(
        'tags.fetch_for_network',
        sub {
            my $c = shift;
            return split /\s+/, $c->fetch_string_for_network(@_);
        }
    );

    $app->helper(
        'tags.fetch_for_networks',
        sub {
            my $c = shift;
	        $c->tags->fetch_for_ids(map { $_->{id} } @_);
        }
    );

    $app->helper(
        'tags.fetch_summary',
        sub {
            my $c = shift;
            my $dbh = $c->dbh;
            db_fetch {
                my $n : networks;
                my $t : network_tags;
                $n->id == $t->net_id;
                $n->invalidated == 0;
                sort $t->tag;
                return $t->tag, cnt => count( $t->net_id );
            };
        }
    );

    $app->helper(
        'tags.fetch_networks',
        sub {
            my $c = shift;
            my $tag = shift;
            my $dbh = $c->dbh;
            my @n   = db_fetch {
                my $n : networks;
                my $t : network_tags;
                my $c : classes;
                my $cr : classes_ranges;

                $n->id == $t->net_id;
                $n->invalidated == 0;
                $t->tag eq $tag;

                inet_contains( $cr->net, $n->net );
                $c->id == $n->class_id;
                sort $n->net;
                return (
                    $n->id, $n->net,
                    $n->class_id,
                    class_name => $c->name,
                    $n->descr, $n->created, $n->created_by,
                    parent_class_id => $cr->class_id,
                    parent_range_id => $cr->id,
                    wrong_class     => ( $n->class_id != $cr->class_id )
                );
            };
            my $id2tag = $c->tags->fetch_for_networks(@n);
            for my $n (@n) {
                $n->{created_by} ||= "";
                $n->{descr} = $c->u2p( $n->{descr} );
                $n->{tags}  = $c->tags->ref2string( $id2tag->{ $n->{id} } );
                $c->gen_calculated_params($n);
            }
            return \@n;
        }
    );
}

1;
