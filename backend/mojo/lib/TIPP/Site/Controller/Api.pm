package TIPP::Site::Controller::Api;
use Mojo::Base 'Mojolicious::Controller';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

use DBIx::Perlish;
use Net::DNS::Resolver;

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

sub handle_class
{
    my $c = shift;
    my $id = $c->param('id') || 0;

    my $dbh = $c->dbh;

#select cr.id,cr.net,cr.class_id,cr.descr,sum(2^(32-masklen(n.net))) from classes_ranges cr left join networks n on inet_contains(cr.net, n.net) and n.invalidated = 0 where cr.class_id = 1 group by cr.id,cr.net,cr.class_id,cr.descr;
    my @cc = db_fetch {
        my $cr : classes_ranges;
        my $n : networks;
        $cr->class_id == $id;
        join $cr < $n => db_fetch {
            inet_contains( $cr->net, $n->net );
            $n->invalidated == 0;
        };
        sort $cr->net;
        return $cr->id, $cr->net, $cr->class_id, $cr->descr,
          used => sum( 2**( 2**( family( $n->net ) + 1 ) - masklen( $n->net ) ) ),
          f    => family( $cr->net );
    };
    my $misclassified = db_fetch {
        my $cr : classes_ranges;
        my $n : networks;
        $cr->class_id != $id;
        $n->class_id == $id;
        $n->invalidated == 0;
        inet_contains( $cr->net, $n->net );
        return count( $n->id );
    };
    for my $cc (@cc) {
        $cc->{net} =~ /\/(\d+)/;
        $cc->{used} ||= 0;
        $cc->{addresses} = 2**( 2**( $cc->{f} + 1 ) - $1 ) - $cc->{used};
        $cc->{descr} = $c->u2p( $cc->{descr} || "" );
    }
    push @cc, { misclassified => $misclassified, class_id => $id } if $misclassified;

    $c->render( json => \@cc );
}

#sub handle_top_level_nets
#{
#	my $dbh = connect_db();
#	my @c = map { N($_) } db_fetch {
#		my $t : classes_ranges;
#		return $t->net;
#	};
#	my @r = map { "$_" } NetAddr::IP::Compact(@c);
#	return \@r;
#}
#
sub handle_net
{
    my $c = shift;
    my %p = @_;

    my $id = $c->param('id');

    my $free = $c->jsparam("free");
    $free = $p{free} if exists $p{free};
    my $limit = $c->jsparam("limit");
    $limit = $p{limit} if exists $p{limit};
    my $misclassified = $c->jsparam("misclassified");
    my $class_id      = $c->jsparam("class_id");

    my $dbh = $c->dbh;
    my @c;
    if ($misclassified) {
        @c = db_fetch {
            my $cr : classes_ranges;
            my $n : networks;
            my $c : classes;
            $cr->class_id != $class_id;
            $n->class_id == $class_id;
            $n->invalidated == 0;
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
                wrong_class     => ( $n->class_id != $cr->class_id ),
                tags_array      => tags_array( $n->id ),
            );
        };
    } else {
        @c = db_fetch {
            my $cr : classes_ranges;
            my $n : networks;
            my $c : classes;
            $cr->id == $id unless $limit;
            inet_contains( $limit, $n->net ) if $limit;
            inet_contains( $cr->net, $n->net );
            $n->invalidated == 0;
            $c->id == $n->class_id;
            sort $n->net;
            return (
                $n->id, $n->net,
                $n->class_id,
                class_name => $c->name,
                $n->descr, $n->created, $n->created_by,
                parent_class_id => $cr->class_id,
                parent_range_id => $cr->id,
                wrong_class     => ( $n->class_id != $cr->class_id ),
                tags_array      => tags_array( $n->id ),
            );
        };
        if ($free) {
            my @r = db_fetch {
                my $cr : classes_ranges;
                my $c : classes;
                $cr->id == $id unless $limit;
                inet_contains( $limit, $cr->net ) || inet_contains( $cr->net, $limit ) if $limit;
                $cr->class_id == $c->id;
                return $cr->net, $cr->class_id, $cr->descr, class_name => $c->name;
            };
            return { error => "Cannot find class_range" } unless @r;
            my @miss = calculate_gaps( $limit ? $limit : $r[0]->{net}, map { $_->{net} } @c );
            for (@c) { $_->{nn} = N( $_->{net} ) }
            for my $r (@r) {
                $r->{nn} = N( $r->{net} );
            }
            my @m;
            for my $c (@miss) {
                my $cid   = 0;
                my $cname = "?unknown?";
                for my $r (@r) {
                    if ( $r->{nn}->contains($c) ) {
                        $cid   = $r->{class_id};
                        $cname = $r->{class_name};
                        last;
                    }
                }
                push @m, { net => "$c", nn => $c, free => 1, id => 0, class_name => $cname, class_id => $cid };
            }
            @c = sort { $a->{nn} cmp $b->{nn} } ( @c, @m );
        }
    }
    my %c;
    for my $cc (@c) {
        $cc->{tags} = $c->tags->ref2string( $cc->{tags_array} );
        $c{ $cc->{net} } = $cc unless $c->{free};
    }
    for my $cc (@c) {
        my $this = $c->N( $cc->{net} );
        my $super = $c->N( $this->network->addr . "/" . ( $this->masklen - 1 ) );
        my $neighbour;
        if ( $super->network->addr eq $this->network->addr ) {
            $neighbour = $c->N( $super->broadcast->addr . "/" . $this->masklen )->network;
        } else {
            $neighbour = $c->N( $super->network->addr . "/" . $this->masklen );
        }
        my $merge_with = $c{$neighbour};
        if ( $merge_with && $merge_with->{class_id} == $cc->{class_id} ) {
            $cc->{merge_with} = "$neighbour";
        }
        delete $cc->{nn};
        delete $cc->{parent_range_id};
        delete $cc->{tags_array};
        $cc->{descr} = $c->u2p( $cc->{descr} || "" );
        $cc->{created_by} ||= "";
        $c->gen_calculated_params($cc);
    }

    $c->render( json => \@c );
}

#sub handle_new_network
#{
#	my $net = param("net") || "";
#	my $class_id = param("class_id") || 0;
#	my $descr = u2p(param("descr")||"");
#	my $limit = param("limit")||"";
#	my $tags = normalize_tagstring(u2p(param("tags")||""));
#	my $in_class_range = (param("in_class_range")||"") eq "true";
#
#	return { error => "Network must be specified" } unless $net;
#	return { error => "Network class must be specified" } unless $class_id;
#	return { error => "Permission \"net\" denied" } unless perm_check("net", $class_id);
#	return { error => "Network description must be specified" } unless $descr;
#	my $nn = N($net);
#	return { error => "Bad network specification" } unless $nn;
#	$nn = $nn->network;
#	$net = "$nn";
#
#	if ($limit) {
#		my $n_limit = N($limit);
#		return {error=>"Invalid network limit"} unless $n_limit;
#		$limit = "$n_limit";
#		return {error=>"Network is not within $limit"} unless $n_limit->contains($nn);
#	}
#
#	my $dbh = connect_db();
#	my $cid = db_fetch {
#		my $c : classes;
#		$c->id == $class_id;
#		return $c->id;
#	};
#	return { error => "Non-existing network class" } unless $cid;
#	my $crid = db_fetch {
#		my $cr : classes_ranges;
#		inet_contains($cr->net, $net);
#		return $cr->id;
#	};
#	return { error => "Network $net is outside of any known range" } unless $crid;
#	my $first = $nn->first->addr;
#	my $last  = $nn->last->addr;
#	my $over = db_fetch {
#		my $n : networks;
#		$n->invalidated == 0;
#		inet_contains($n->net, $net) or
#		inet_contains($net, $n->net) or
#		inet_contains($n->net, $first) or
#		inet_contains($n->net, $last);
#		return $n->net;
#	};
#	return { error => "Network $net overlaps with existing network $over" } if $over;
#
#	my $when = time;
#	db_insert 'networks', {
#		id			=> sql("nextval('networks_id_seq')"),
#		net			=> $net,
#		class_id	=> $class_id,
#		descr		=> $descr,
#		created		=> $when,
#		invalidated	=> 0,
#		created_by	=> remote_user(),
#	};
#
#	my $new_net = db_fetch {
#		my $cr : classes_ranges;
#		my $n : networks;
#		my $c : classes;
#		$n->net == $net;
#		$n->invalidated == 0;
#		inet_contains($cr->net, $n->net);
#		$c->id == $n->class_id;
#		sort $n->net;
#		return ($n->id, $n->net,
#			$n->class_id, class_name => $c->name,
#			$n->descr, $n->created, $n->created_by,
#			parent_class_id => $cr->class_id,
#			wrong_class => ($n->class_id != $cr->class_id));
#	};
#	unless ($new_net) {
#		$dbh->rollback;
#		return { error => "Cannot insert network" };
#	}
#	insert_tagstring($new_net->{id}, $tags);
#	log_change(network => "Allocated new network $net of class $new_net->{class_name}", when => $when);
#	if ($limit && !$in_class_range) {
#		my $ret = handle_net(free => 1, limit => $limit);
#		if ((ref($ret)||"") ne "ARRAY") {
#			$dbh->rollback;
#			return $ret;
#		} else {
#			$dbh->commit;
#			return {msg => "Network $net successfully inserted", n => $ret};
#		}
#	}
#	$dbh->commit;
#	$new_net->{descr} = u2p($new_net->{descr});
#	$new_net->{tags} = $tags;
#	$new_net->{msg} = "Network $net successfully inserted";
#	$new_net->{created_by} ||= "";
#	gen_calculated_params($new_net);
#	return $new_net;
#}
#
#sub handle_edit_net
#{
#	my $dbh = connect_db();
#	my $class_id = param("class_id");
#	my $descr    = u2p(param("descr"));
#	my $tags     = normalize_tagstring(u2p(param("tags")||""));
#	my $net = db_fetch { my $n : networks;  $n->id == $id;  $n->invalidated == 0; };
#	return { error => "No such network (maybe someone else changed it?)" }
#		unless $net;
#	return { error => "Permission \"net\" denied" } unless perm_check("net", $class_id);
#	return { error => "Permission \"net\" denied" } unless perm_check("net", $net->{class_id});
#	$net->{descr} = u2p($net->{descr});
#	$net->{tags} = fetch_tagstring_for_id($id);
#	my $msg;
#	if ($descr ne $net->{descr} || $net->{class_id} != $class_id || $net->{tags} ne $tags) {
#		my $when = time;
#		my $who = remote_user();
#		db_update {
#			my $n : networks;
#			$n->id == $id;
#
#			$n->invalidated = $when;
#			$n->invalidated_by = $who;
#		};
#		my $new_id = db_fetch { return `nextval('networks_id_seq')`; };
#		db_insert 'networks', {
#			id			=> $new_id,
#			net			=> $net->{net},
#			class_id	=> $class_id,
#			descr		=> $descr,
#			created		=> $when,
#			invalidated	=> 0,
#			created_by	=> $who,
#		};
#		insert_tagstring($new_id, $tags);
#		$msg = "Network $net->{net} updated successfully";
#		log_change(network => "Modified network $net->{net}", when => $when);
#	} else {
#		$msg = "Network $net->{net} was not updated because nothing has changed";
#	}
#	my $new_net = db_fetch {
#		my $cr : classes_ranges;
#		my $n : networks;
#		my $c : classes;
#		$n->net == $net->{net};
#		$n->invalidated == 0;
#		inet_contains($cr->net, $n->net);
#		$c->id == $n->class_id;
#		sort $n->net;
#		return ($n->id, $n->net,
#			$n->class_id, class_name => $c->name,
#			$n->descr, $n->created, $n->created_by,
#			parent_class_id => $cr->class_id,
#			wrong_class => ($n->class_id != $cr->class_id));
#	};
#	unless ($new_net) {
#		$dbh->rollback;
#		return { error => "Cannot update network information" };
#	}
#	$dbh->commit;
#	$new_net->{descr} = u2p($new_net->{descr});
#	$new_net->{msg} = $msg;
#	$new_net->{tags} = $tags;
#	$new_net->{created_by} ||= "";
#	gen_calculated_params($new_net);
#	return $new_net;
#}
#
#sub handle_merge_net
#{
#	my $dbh = connect_db();
#
#	my $merge_with = param("merge_with");
#	return { error => "merge_with parameter is required" }
#		unless $merge_with;
#
#	my $net0 = db_fetch { my $n : networks;  $n->id == $id;  $n->invalidated == 0; };
#	return { error => "No such network (maybe someone else changed it?)" }
#		unless $net0;
#
#	my $net1 = db_fetch { my $n : networks;  $n->net == $merge_with;  $n->invalidated == 0; };
#	return { error => "No neighbouring network (maybe someone else changed it?)" }
#		unless $net1;
#	return { error => "Permission \"net\" denied" } unless perm_check("net", $net0->{class_id});
#
#	my $n0 = N($net0->{net});
#	my $n1 = N($net1->{net});
#	my $super = N($n0->network->addr . "/" . ($n0->masklen - 1))->network;
#	if ($super->network->addr ne $n0->network->addr) {
#		($net0,$net1) = ($net1,$net0);
#		($n0,$n1)     = ($n1,$n0);
#	}
#
#	return { error => "$n0 and $n1 belong to different classes, cannot merge" }
#		unless $net0->{class_id} == $net1->{class_id};
#
#	$net0->{descr} = u2p($net0->{descr});
#	$net1->{descr} = u2p($net1->{descr});
#	$net0->{descr} =~ s/^\s*\[merge\]\s+//;
#	$net1->{descr} =~ s/^\s*\[merge\]\s+//;
#	my $descr;
#	if ($net0->{descr} eq $net1->{descr}) {
#		$descr = "[merge] $net0->{descr}";
#	} else {
#		$descr = "[merge] $net0->{descr} | $net1->{descr}";
#	}
#
#	my $tags = tags2tagstring(fetch_tags_for_network($net0),
#		fetch_tags_for_network($net1));
#
#	my $when = time;
#	my $who = remote_user();
#	db_insert 'networks', {
#		id			=> sql("nextval('networks_id_seq')"),
#		net			=> "$super",
#		class_id	=> $net0->{class_id},
#		descr		=> $descr,
#		created		=> $when,
#		invalidated	=> 0,
#		created_by	=> $who,
#	};
#
#	db_update {
#		my $n : networks;
#		$n->invalidated == 0;
#		$n->id == $net0->{id} || $n->id == $net1->{id};
#
#		$n->invalidated = $when;
#		$n->invalidated_by = $who;
#	};
#	my $nn = "$super";
#	log_change(network => "Removed network $n0 (it was merged with $n1 into $nn)", when => $when);
#	log_change(network => "Removed network $n1 (it was merged with $n0 into $nn)", when => $when);
#
#	my $new_net = db_fetch {
#		my $cr : classes_ranges;
#		my $n : networks;
#		my $c : classes;
#		$n->net == $nn;
#		$n->invalidated == 0;
#		inet_contains($cr->net, $n->net);
#		$c->id == $n->class_id;
#		sort $n->net;
#		return ($n->id, $n->net,
#			$n->class_id, class_name => $c->name,
#			$n->descr, $n->created, $n->created_by,
#			parent_class_id => $cr->class_id,
#			wrong_class => ($n->class_id != $cr->class_id));
#	};
#	unless ($new_net) {
#		$dbh->rollback;
#		return { error => "Cannot merge networks in the database" };
#	}
#
#	insert_tagstring($new_net->{id}, $tags);
#
#	log_change(network => "Added network $nn (via merge of $n0 and $n1)", when => $when);
#	$dbh->commit;
#	my $msg = "Networks $n0 and $n1 successfully merged into $nn";
#
#	$new_net->{descr} = u2p($new_net->{descr});
#	$new_net->{tags} = $tags;
#	$new_net->{msg} = $msg;
#	$new_net->{created_by} ||= "";
#	gen_calculated_params($new_net);
#	return $new_net;
#}
#
#sub handle_edit_class_range
#{
#	my $dbh = connect_db();
#	my $class_id = param("class_id");
#	my $descr    = u2p(param("descr"));
#	my $range = db_fetch { my $cr : classes_ranges;  $cr->id == $id; };
#	return { error => "No such class range (maybe someone else changed it?)" }
#		unless $range;
#	return { error => "Permission \"range\" denied" } unless perm_check("range", $range->{class_id});
#	return { error => "Permission \"range\" denied" } unless perm_check("range", $class_id);
#	$range->{descr} = u2p($range->{descr}||"");
#	my $msg;
#	if ($descr ne $range->{descr} || $range->{class_id} != $class_id) {
#		my $when = time;
#		my $who = remote_user();
#		db_update {
#			my $cr : classes_ranges;
#			$cr->id == $id;
#
#			$cr->descr = $descr;
#			$cr->class_id = $class_id;
#		};
#		$msg = "Class range $range->{net} updated successfully";
#		log_change(range => "Modified class-range $range->{net}", when => $when);
#	} else {
#		$msg = "Class range $range->{net} was not updated because nothing has changed";
#	}
#	my $new_range = db_fetch {
#		my $cr : classes_ranges;
#		my $n : networks;
#
#		$cr->id == $id;
#		join $cr < $n => db_fetch {
#			inet_contains($cr->net, $n->net);
#			$n->invalidated == 0;
#		};
#
#		return $cr->id,$cr->net,$cr->class_id,$cr->descr,used => sum(2**(32-masklen($n->net)));
#	};
#	unless ($new_range) {
#		$dbh->rollback;
#		return { error => "Cannot update class range information" };
#	}
#	$dbh->commit;
#	$new_range->{descr} = u2p($new_range->{descr}||"");
#	$new_range->{msg} = $msg;
#	$new_range->{net} =~ /\/(\d+)/;
#	$new_range->{used} ||= 0;
#	$new_range->{addresses} = 2**(32-$1) - $new_range->{used};
#	return $new_range;
#}
#
#sub handle_add_class_range
#{
#	my $dbh = connect_db();
#	my $class_id = param("class_id");
#	my $descr    = u2p(param("descr"));
#	return { error => "Permission \"range\" denied" } unless perm_check("range", $class_id);
#	my $net = param("range")||"";
#	my $nn = N($net);
#	return { error => "Bad class range specification" } unless $nn;
#	$net = "$nn";
#
#	my $cid = db_fetch {
#		my $c : classes;
#		$c->id == $class_id;
#		return $c->id;
#	};
#	return { error => "Non-existing network class" } unless $cid;
#
#	my $first = $nn->network->addr;
#	my $last  = $nn->broadcast->addr;
#	my $over = db_fetch {
#		my $cr : classes_ranges;
#		inet_contains($cr->net, $net) or
#		inet_contains($net, $cr->net) or
#		inet_contains($cr->net, $first) or
#		inet_contains($cr->net, $last);
#		return $cr->net;
#	};
#	return { error => "Class range $net overlaps with existing class range $over" } if $over;
#
#	my $when = time;
#	db_insert 'classes_ranges', {
#		id			=> sql("nextval('classes_ranges_id_seq')"),
#		net			=> $net,
#		class_id	=> $class_id,
#		descr		=> $descr,
#	};
#
#	my $msg = "Class range $net created successfully";
#	log_change(range => "Created class-range $net", when => $when);
#
#	my $new_range = db_fetch {
#		my $cr : classes_ranges;
#		my $n : networks;
#
#		$cr->net == $net;
#		join $cr < $n => db_fetch {
#			inet_contains($cr->net, $n->net);
#			$n->invalidated == 0;
#		};
#
#		return $cr->id,$cr->net,$cr->class_id,$cr->descr,
#			used => sum(2**(2**(family($n->net)+1)-masklen($n->net))),
#			f => family($cr->net);
#	};
#	unless ($new_range) {
#		$dbh->rollback;
#		return { error => "Cannot create new class range $net" };
#	}
#	$dbh->commit;
#	$new_range->{descr} = u2p($new_range->{descr}||"");
#	$new_range->{msg} = $msg;
#	$new_range->{net} =~ /\/(\d+)/;
#	$new_range->{used} ||= 0;
#	$new_range->{addresses} = 2**(2**($new_range->{f}+1)-$1) - $new_range->{used};
#	return $new_range;
#}
#
#sub handle_remove_class_range
#{
#	my $dbh = connect_db();
#
#	my $range = db_fetch {
#		my $cr : classes_ranges;
#		my $n : networks;
#
#		$cr->id == $id;
#		join $cr < $n => db_fetch {
#			inet_contains($cr->net, $n->net);
#			$n->invalidated == 0;
#		};
#
#		return $cr->id,$cr->net,$cr->class_id,$cr->descr,used => sum(2**(32-masklen($n->net)));
#	};
#
#	return { error => "Class range not found!" } unless $range;
#	return { error => "Permission \"range\" denied" } unless perm_check("range", $range->{class_id});
#	return { error => "Class range $range->{net} is not empty!" } if $range->{used};
#
#	my $when = time;
#	db_delete {
#		my $cr : classes_ranges;
#		$cr->id == $id;
#	};
#	log_change(range => "Removed class-range $range->{net}", when => $when);
#	$dbh->commit;
#	return { msg => "Class range $range->{net} removed successfully" };
#}
#
#sub handle_ip_net
#{
#	my $ip = param("ip") || return;
#	my $dbh = connect_db();
#	my $net = db_fetch {
#		my $cr : classes_ranges;
#		my $n : networks;
#		my $c : classes;
#		inet_contains($n->net, $ip);
#		$n->invalidated == 0;
#		inet_contains($cr->net, $n->net);
#		$c->id == $n->class_id;
#		sort $n->net;
#		return ($n->id, $n->net,
#			$n->class_id, class_name => $c->name,
#			$n->descr, $n->created, $n->created_by,
#			parent_class_id => $cr->class_id,
#			wrong_class => ($n->class_id != $cr->class_id));
#	};
#	$net->{descr} = u2p($net->{descr});
#	$net->{created_by} ||= "";
#	gen_calculated_params($net);
#	return $net;
#}
#
#sub handle_net_history
#{
#	my $dbh = connect_db();
#	my $nn = param("net") || "";
#	my $net = db_fetch { my $n : networks;  $n->net == $nn; return $n->net; };
#	return { error => "No network found, strange" } unless $net;
#	my @net = db_fetch {
#		my $cr : classes_ranges;
#		my $n : networks;
#		my $c : classes;
#		$n->net == $net;
#		inet_contains($cr->net, $n->net);
#		$c->id == $n->class_id;
#		sort $n->created;
#		return ($n->id, $n->net,
#			$n->class_id, class_name => $c->name,
#			$n->descr, $n->created, $n->invalidated, $n->invalidated_by,
#			parent_class_id => $cr->class_id, $n->created_by,
#			wrong_class => ($n->class_id != $cr->class_id));
#	};
#	my $id2tag = fetch_tags_for_networks(@net);
#	my $last;
#	my @hist;
#	for my $n (@net) {
#		$n->{tags} = tagref2tagstring($id2tag->{$n->{id}});
#		if ($last && $last->{invalidated} < $n->{created}) {
#			my %fake;
#			$fake{net}			= $net;
#			$fake{class_name}	= "unallocated";
#			$fake{descr}		= "";
#			$fake{tags}			= "";
#			$fake{id}			= 0;
#			$fake{created}		= $last->{invalidated};
#			$fake{invalidated}	= $n->{created};
#			$fake{created_by}	= $last->{invalidated_by};
#			push @hist, \%fake;
#		}
#		push @hist, $n;
#		$last = $n;
#	}
#	if (@hist && $hist[-1]->{invalidated} > 0) {
#		my %fake;
#		$fake{net}			= $net;
#		$fake{class_name}	= "unallocated";
#		$fake{descr}		= "";
#		$fake{tags}			= "";
#		$fake{id}			= 0;
#		$fake{created}		= $hist[-1]->{invalidated};
#		$fake{invalidated}	= 0;
#		$fake{created_by}	= $hist[-1]->{invalidated_by};
#		push @hist, \%fake;
#	}
#	for my $c (@hist) {
#		$c->{descr} = u2p($c->{descr});
#		$c->{created_by} ||= "";
#		delete $c->{invalidated_by};
#	}
#	@hist = reverse @hist;
#	return \@hist;
#}
#
sub handle_addresses
{
    my $c = shift;

    my $net = shift || $c->param("net") || return;
    my $dbh = $c->dbh;
    my @dip = db_fetch {
        my $ip : ips;
        my $ipe : ip_extras;
        join $ip < $ipe => db_fetch { $ip->id == $ipe->id };
        $ip->invalidated == 0;
        inet_contains( $net, $ip->ip );
    };
    my %ip;
    for my $ip (@dip) {
        for my $k (qw(descr location phone owner hostname comments created_by invalidated_by)) {
            $ip->{$k} ||= "";
            $ip->{$k} = $c->u2p( $ip->{$k} );
        }
        $ip{ $ip->{ip} } = $ip;
    }
    my @ip;
    my $n = $c->N($net);
    if ( $n->version == 4 ) {
        my $last_ip = "";
        for my $ipn ( $n->network, $n->hostenum, $n->broadcast ) {
            my $ip = $ipn->addr;
            next if $ip eq $last_ip;
            $last_ip = $ip;
            if ( $ip{$ip} ) {
                push @ip, $ip{$ip};
            } else {
                push @ip, { ip => $ip, descr => "" };
            }
        }
    } else {
        for my $ip ( sort keys %ip ) {
            push @ip, $ip{$ip};
        }
    }
    $c->render( json => \@ip );
}

#sub handle_get_ip
#{
#	my $ip = param("ip");
#	my $ipn = N($ip);
#	return {error => "invalid IP"} unless $ipn;
#	$ip = $ipn->ip;  # our canonical form
#	return get_ip_info($ip);
#}
#
#sub handle_ip_history
#{
#	my $ip = param("ip");
#	return {error => "IP must be specified"} unless $ip;
#	my $ipn = N($ip);
#	return {error => "invalid IP"} unless $ipn;
#	$ip = $ipn->ip;  # our canonical form
#
#	my $dbh = connect_db();
#	my @ip = db_fetch {
#		my $i : ips;
#		my $e : ip_extras;
#
#		join $i < $e => db_fetch { $i->id == $e->id };
#		$i->ip == $ip;
#
#		sort $i->created;
#	};
#	for my $i (@ip) {
#		for my $k (qw(descr location phone owner hostname comments created_by invalidated_by)) {
#			$i->{$k} ||= "";
#			$i->{$k} = u2p($i->{$k});
#		}
#	}
#	my @r;
#	my $last;
#	for my $i (@ip) {
#		if ($last && $last->{invalidated} < $i->{created}) {
#			my %fake;
#			for my $k (qw(descr location phone owner hostname comments)) {
#				$fake{$k} = "";
#			}
#			$fake{ip}			= $ip;
#			$fake{id}			= 0;
#			$fake{created}		= $last->{invalidated};
#			$fake{invalidated}	= $i->{created};
#			$fake{created_by}	= $last->{invalidated_by};
#			push @r, \%fake;
#		}
#		push @r, $i;
#		$last = $i;
#	}
#	if (@r && $r[-1]->{invalidated} > 0) {
#		my %fake;
#		for my $k (qw(descr location phone owner hostname comments)) {
#			$fake{$k} = "";
#		}
#		$fake{ip}			= $ip;
#		$fake{id}			= 0;
#		$fake{created}		= $r[-1]->{invalidated};
#		$fake{invalidated}	= 0;
#		$fake{created_by}	= $r[-1]->{invalidated_by};
#		push @r, \%fake;
#	}
#	unless (@r) {
#		my $start = db_fetch {
#			my $n : networks;
#			inet_contains($n->net, $ip);
#			sort $n->created;
#			return $n->created;
#		};
#		$start = -1 unless $start;
#		my %fake;
#		for my $k (qw(descr location phone owner hostname comments)) {
#			$fake{$k} = "";
#		}
#		$fake{ip}			= $ip;
#		$fake{id}			= 0;
#		$fake{created}		= $start;
#		$fake{invalidated}	= 0;
#		$fake{created_by}	= "";
#		push @r, \%fake;
#	}
#	@r = reverse @r;
#	return \@r;
#}
#
#sub handle_edit_ip
#{
#	my %p;
#	for my $p (qw(ip descr location phone owner hostname comments)) {
#		$p{$p} = param($p);
#		$p{$p} = "" unless defined $p{$p};
#		$p{$p} = u2p($p{$p});
#	}
#	my $containing_net = jsparam("containing_net");
#	my $only_new = jsparam("only_new");
#	return {error => "IP must be specified"} unless $p{ip};
#	my $ipn = N($p{ip});
#	return {error => "invalid IP"} unless $ipn;
#	$p{ip} = $ipn->ip;  # our canonical form
#
#	my $dbh = connect_db();
#	my $within = db_fetch {
#		my $n : networks;
#		inet_contains($n->net, $p{ip});
#		$n->invalidated == 0;
#		return $n->net, $n->class_id;
#	};
#	return { error => "The address is outside a valid network" } unless $within;
#	return { error => "Permission \"ip\" denied" } unless perm_check("ip", $within->{class_id});
#
#	if ($containing_net) {
#		my $net = N($containing_net);
#		return {error => "invalid containing network"} unless $net;
#		return {error => "The address is outside the network"}
#			unless $net->contains($ipn);
#		# XXX shall we also test that the network in question
#		# is present and not invalid?
#	}
#
#	my $old = get_ip_info($p{ip});
#	if ($old->{id} && $only_new) {
#		return {error => "This address is already allocated"};
#	}
#	my $changed = 0;
#	for my $p (qw(descr location phone owner hostname comments)) {
#		$changed = 1 if $old->{$p} ne $p{$p};
#	}
#	unless ($changed) {
#		$old->{msg} = "IP $p{ip} was not updated because nothing has changed";
#		return $old;
#	}
#
#	my $need_extras = 0;
#	for my $p (qw(location phone owner hostname comments)) {
#		$need_extras = 1 if $p{$p} ne "";
#	}
#
#	my $when = time;
#	my $who = remote_user();
#	db_update {
#		my $ip : ips;
#		$ip->ip == $p{ip};
#		$ip->invalidated == 0;
#
#		$ip->invalidated = $when;
#		$ip->invalidated_by = $who;
#	};
#	my $msg = "IP $p{ip} updated successfully";
#	if ($p{descr} ne "" || $need_extras) {
#		my $id = db_fetch { return `nextval('ips_id_seq')`; };
#		db_insert 'ips', {
#			id			=> $id,
#			ip			=> $p{ip},
#			descr		=> $p{descr},
#			created		=> $when,
#			invalidated	=> 0,
#			created_by	=> $who,
#		};
#		if ($need_extras) {
#			db_insert 'ip_extras', {
#				id			=> $id,
#				location	=> $p{location},
#				phone		=> $p{phone},
#				owner		=> $p{owner},
#				hostname	=> $p{hostname},
#				comments	=> $p{comments},
#			};
#		}
#		log_change(ip => "Modified IP $p{ip}", when => $when);
#	} else {
#		$msg = "IP $p{ip} removed successfully";
#		log_change(ip => "Removed IP $p{ip}", when => $when);
#	}
#	my $new = get_ip_info($p{ip});
#	$new->{msg} = $msg;
#	$dbh->commit;
#	return $new;
#}
#
#sub xhandle_edit_range_list
#{
#}
#
#sub handle_remove_net
#{
#	my $dbh = connect_db();
#	my $netinfo = db_fetch {
#		my $n : networks;
#		$n->id == $id;
#	};
#	return { error => "Network not found" } unless $netinfo;
#	return { error => "Permission \"net\" denied" } unless perm_check("net", $netinfo->{class_id});
#	my $net = $netinfo->{net};
#	my $when = time;
#	my $who = remote_user();
#	db_update {
#		my $ip : ips;
#		inet_contains($net, $ip->ip);
#		$ip->invalidated == 0;
#
#		$ip->invalidated = $when;
#		$ip->invalidated_by = $who;
#	};
#	db_update {
#		my $n : networks;
#		$n->invalidated == 0;
#		$n->net == $net;
#
#		$n->invalidated = $when;
#		$n->invalidated_by = $who;
#	};
#	log_change(network => "Removed network $net", when => $when);
#	$dbh->commit;
#	return {msg => "Network $net successfully removed"};
#}
#
#sub handle_search
#{
#	my $s = u2p(param("q") || "");
#
#	return {error => "search string not specified"} if $s eq "";
#	my @s = grep { $_ ne "" } split /\s+/, $s;
#	return {error => "blank search string"} unless @s;
#
#	my %r = (search_networks(@s), search_ips(0, @s), search_ips(1, @s));
#	$r{n}  ||= [];
#	$r{i}  ||= [];
#	$r{hi} ||= [];
#	return \%r;
#}
#
sub handle_suggest_network
{
    my $c = shift;

    my $id = $c->param('id');

    my $sz = $c->param("sz");
    my $limit = $c->param("limit") || "";
    unless ($sz) {
        $c->render( json => { error => "Network size is not specified" } );
        return;
    }
    $sz =~ s/.*?(\d+)$/$1/;
    unless ( $sz =~ /^\d+$/ ) {
        $c->render( json => { error => "Bad network size" } );
        return;
    }
    unless ( $sz >= 8 && $sz <= 128 ) {
        $c->render( json => { error => "Invalid network size" } ) unless $sz >= 8 && $sz <= 128;
        return;
    }
    my ( %cr, @all );
    my $dbh       = $c->dbh;
    my $ipv6_only = $sz > 32;
    if ($limit) {
        my $n_limit = $c->N($limit);
        unless ($n_limit) {
            $c->render( json => { error => "Invalid network limit" } );
            return;
        }
        $limit = "$n_limit";
        @all = map { { range => $limit, net => $_ } }
          db_fetch {
            my $n : networks;

            inet_contains( $limit, $n->net );
            $n->invalidated == 0;
            family( $n->net ) == 6 if $ipv6_only;

            return $n->net;
          };
        $cr{$limit} = [];
    } else {
        @all = db_fetch {
            my $cr : classes_ranges;
            my $n : networks;

            $cr->class_id == $id;
            family( $cr->net ) == 6 if $ipv6_only;
            join $cr < $n => db_fetch {
                inet_contains( $cr->net, $n->net );
                $n->invalidated == 0;
                family( $n->net ) == 6 if $ipv6_only;
            };

            return range => $cr->net, net => $n->net;
        };
    }
    for my $b (@all) {
        $cr{ $b->{range} } ||= [];
        next unless $b->{net};
        my $n = $c->N( $b->{net} );
        push @{ $cr{ $b->{range} } }, $n if $n;
    }
    my %sz;
    for my $r ( keys %cr ) {
        my $b = $c->N($r);
        if ( @{ $cr{$r} } ) {
            my @miss = $c->ip->calculate_gaps( $r, @{ $cr{$r} } );
            for my $m (@miss) {
                push @{ $sz{ $m->masklen } }, $m;
            }
        } else {
            push @{ $sz{ $b->masklen } }, $b;
        }
    }
    my $check_sz = $sz;
    while ( $check_sz >= 8 ) {
        if ( $sz{$check_sz} ) {
            my $n = $sz{$check_sz}->[ rand @{ $sz{$check_sz} } ];
            $c->render( json => { n => $n->network->addr . "/$sz" } );
            return;
        }
        $check_sz--;
    }
    $c->render(
        json => {
                error => "Cannot find a free "
              . ( $ipv6_only ? "IPv6 " : "" )
              . "network of size $sz"
              . ( $limit ? " inside $limit" : "" )
        }
    );
}

#sub handle_split
#{
#	my $ip = param("ip") || "";
#	return {error => "split IP must be specified"} unless $ip;
#	return {error => "invalid split IP"} unless $ip =~ /^$RE{net}{IPv4}$/;
#	my $dbh = connect_db();
#	my $nf = db_fetch {
#		my $n : networks;
#		$n->invalidated == 0;
#		inet_contains($n->net, $ip);
#	};
#	return {error => "network to split not found"} unless $nf;
#	return { error => "Permission \"net\" denied" } unless perm_check("net", $nf->{class_id});
#	my $net = $nf->{net};
#	my $n = N($net);
#	return {error => "invalid network to split"} unless $n;
#	my $sz;
#	for my $sz0 (reverse (8..32)) {
#		$sz = $sz0;
#		my $sp = N("$ip/$sz");
#		last unless $sp;
#		last unless $sp->broadcast->addr eq $ip;
#		last if $sz < $n->masklen;
#	}
#	return {error => "unable to find split point [sz $sz]"} if $sz >= 32;
#	$sz++;
#	my $extra_msg = $sz >= 31 ? "The split will have networks of size $sz - this looks like a mistake" : "";
#	my $sn = N("$ip/$sz")->network;
#	my @n = calculate_gaps($n, $sn);
#	@n = sort { $a cmp $b } (@n, $sn);
#	if (param("confirmed")) {
#		my $when = time;
#		my $who = remote_user();
#		my $descr = $nf->{descr};
#		$descr = "[split] $descr" unless $descr =~ /^\[split\]/;
#		my $tags = fetch_tagstring_for_id($nf->{id});
#		for my $nn (@n) {
#			my $new_id = db_fetch { return `nextval('networks_id_seq')`; };
#			db_insert 'networks', {
#				id			=> $new_id,
#				net			=> "$nn",
#				class_id	=> $nf->{class_id},
#				descr		=> $descr,
#				created		=> $when,
#				invalidated	=> 0,
#				created_by	=> $who,
#			};
#			insert_tagstring($new_id, $tags);
#			log_change(network => "Added network $nn (via split)", when => $when);
#			my $ip_network   = $nn->network->addr;
#			unless (db_fetch { my $i : ips; $i->ip == $ip_network; $i->invalidated == 0; return $i->id; }) {
#				my $id = db_fetch { return `nextval('ips_id_seq')`; };
#				db_insert 'ips', {
#					id			=> $id,
#					ip			=> $ip_network,
#					descr		=> "Subnet",
#					created		=> $when,
#					invalidated	=> 0,
#					created_by	=> $who,
#				};
#				log_change(ip => "Recorded IP $ip_network as a subnet address (via split)", when => $when);
#			}
#			my $ip_broadcast = $nn->broadcast->addr;
#			unless (db_fetch { my $i : ips; $i->ip == $ip_broadcast; $i->invalidated == 0; return $i->id; }) {
#				my $id = db_fetch { return `nextval('ips_id_seq')`; };
#				db_insert 'ips', {
#					id			=> $id,
#					ip			=> $ip_broadcast,
#					descr		=> "Broadcast",
#					created		=> $when,
#					invalidated	=> 0,
#					created_by	=> $who,
#				};
#				log_change(ip => "Recorded IP $ip_broadcast as a broadcast address (via split)", when => $when);
#			}
#		}
#		db_update {
#			my $n : networks;
#			$n->invalidated == 0;
#			$n->net == $net;
#
#			$n->invalidated = $when;
#			$n->invalidated_by = $who;
#		};
#		my @new = db_fetch {
#			my $cr : classes_ranges;
#			my $n : networks;
#			my $c : classes;
#			inet_contains($net, $n->net);
#			$n->invalidated == 0;
#			inet_contains($cr->net, $n->net);
#			$c->id == $n->class_id;
#			sort $n->net;
#			return ($n->id, $n->net,
#				$n->class_id, class_name => $c->name,
#				$n->descr, $n->created, $n->created_by,
#				parent_class_id => $cr->class_id,
#				wrong_class => ($n->class_id != $cr->class_id));
#		};
#		unless (@new) {
#			$dbh->rollback;
#			return { error => "Cannot split network $net" };
#		}
#		my %c = map { $_->{net} => $_ } @new;
#		for my $new_net (@new) {
#			$new_net->{descr} = u2p($new_net->{descr}||"");
#			$new_net->{tags} = u2p($tags);
#			$new_net->{created_by} ||= "";
#
#			# find mergeable neighbours
#			my $this = N($new_net->{net});
#			my $super = N($this->network->addr . "/" . ($this->masklen - 1));
#			my $neighbour;
#			if ($super->network->addr eq $this->network->addr) {
#				$neighbour = N($super->broadcast->addr . "/" . $this->masklen)->network;
#			} else {
#				$neighbour = N($super->network->addr . "/" . $this->masklen);
#			}
#			my $merge_with = $c{$neighbour};
#			if ($merge_with && $merge_with->{class_id} == $new_net->{class_id}) {
#				$new_net->{merge_with} = "$neighbour";
#			}
#
#			gen_calculated_params($new_net);
#		}
#		log_change(network => "Removed network $net (via split)", when => $when);
#		$dbh->commit;
#		return {msg => "Network $net successfully split", n => \@new};
#	} else {
#		@n = map { "$_" } @n;
#		return {n => \@n, o => "$n", extra_msg => $extra_msg };
#	}
#}
#
#sub handle_changelog
#{
#	my $filter = param("filter") || "";
#	my $page = param("page") || 0;
#	$page = 0 if $page < 0;
#	my $pagesize = param("pagesize") || 30;
#	my $dbh = connect_db();
#
#	my @s = split / /, $filter;
#	for (@s) { s/\s+//g }
#	@s = grep { $_ ne "" } @s;
#
#	my @filter = ('?');
#	my @bind;
#	for my $s (@s) {
#		# XXX daylight savings troubles!!!
#		push @filter, "(text(timestamp with time zone 'epoch' at time zone '$TIPP::timezone' + created * interval '1 second') ilike ? ".
#			"or who ilike ? or change ilike ?)";
#		push @bind, "%$s%", "%$s%", "%$s%";
#	}
#	unless (perm_check("view_changelog")) {
#		push @filter, "who = ?";
#		push @bind, remote_user();
#	}
#
#=pod
#This is possibly an efficient but horrible way to match dates.
#The above way is probably inefficient but works good enough.
#
#		if ($s =~ /^XY(\d+)-(\d+)-(\d+)$/) {
#			# looks like a date
#			push @filter, "((timestamp 'epoch' + created * interval '1 second')::date " .
#				" = ?::date or who ilike ? or change ilike ?)";
#			push @bind, $s, "%$s%", "%$s%";
#		} elsif ($s =~ /^XY(\d+)-(\d+)$/) {
#			# looks like a month
#			push @filter,
#				"((timestamp 'epoch' + created * interval '1 second')::date ".
#				"<= (date_trunc('month', ?::date) + ".
#				"interval '1 month' - interval '1 day')::date ".
#				"and ".
#				"(timestamp 'epoch' + created * interval '1 second')::date ".
#				">= ?::date or who ilike ? or change ilike ?)";
#			push @bind, "$s-01", "$s-01", "%$s%", "%$s%";
#=cut
#
#	my @e = @{
#		$dbh->selectall_arrayref("select * " .
#			" from changelog where " .
#			join(" and ", @filter) . " order by created desc, id limit ? offset ?",
#			{Slice=>{}}, 't', @bind, $pagesize + 1, $page * $pagesize)
#		|| []
#	};
#
#	my $next = 0;
#	if (@e > $pagesize) {
#		pop @e;
#		$next = 1;
#	}
#	return {
#		p => $page,
#		n => $next,
#		e => \@e,
#	};
#}
#
sub handle_nslookup
{
    my $c = shift;

    my $ip = $c->param("ip") || "";
    unless ($ip) {
        $c->render( json => { error => "IP must be specified" } );
        return;
    }
    my $ipn = $c->N($ip);
    unless ($ipn) {
        $c->render( json => { error => "invalid IP" } );
        return;
    }
    $ip = $ipn->ip;    # our canonical form

    my $res = Net::DNS::Resolver->new;
    $res->udp_timeout(2);
    my $query = $res->query($ip);

    if ($query) {
        for my $rr ( $query->answer ) {
            next unless $rr->type eq "PTR";
            $c->render( json => { host => $rr->ptrdname } );
            return;
        }
        $c->render( json => { error => "PTR record for $ip not found" } );
    }
    $c->render( json => { error => "DNS query for $ip failed: " . $res->errorstring } );
}

sub handle_paginate
{
    my $c = shift;

    my $nn = $c->param("net");
    unless ($nn) {
        $c->render( json => { error => "Network must be specified" } );
        return;
    }
    my $n = $c->N($nn);
    unless ($n) {
        $c->render( json => { error => "Invalid network: $nn" } );
        return;
    }
    if ( $n->version == 4 ) {
        if ( $n->masklen >= 26 ) {
            my $l = $n->broadcast->addr;
            $l =~ s/.*\.//;
            $c->render( json => [ { base => $n->network->addr, last => $l, bits => $n->masklen } ] );
        } else {
            my @r;
            for my $ip ( $n->split(26) ) {
                my $l = $ip->broadcast->addr;
                $l =~ s/.*\.//;
                push @r, { base => $ip->network->addr, last => $l, bits => 26 };
            }
            $c->render( json => \@r );
        }
    } else {
        $c->render( json => [] );
    }
}

#sub handle_describe_ip
#{
#	my $ip = param("ip") || "";
#	return {error => "IP must be specified"} unless $ip;
#	my $ipn = N($ip);
#	return {error => "invalid IP"} unless $ipn;
#	$ip = $ipn->ip;  # our canonical form
#
#	my $start = param("start") || "";
#	return {error => "start must be specified"} unless $start;
#	return {error => "start is not a number"} unless $start =~ /^\d+$/;
#
#	my $stop = param("stop") || "";
#	return {error => "stop must be specified"} unless $stop;
#	return {error => "stop is not a number"} unless $stop =~ /^\d+$/;
#
#	my $dbh = connect_db();
#	my @info = db_fetch {
#		my $i : ips;
#		my $n : networks;
#		my $c : classes;
#		$i->ip == $ip;
#		$i->invalidated >= $start || $i->invalidated == 0;
#		$stop >= $i->created;
#		inet_contains($n->net, $ip);
#		$n->invalidated >= $start || $n->invalidated == 0;
#		$c->id == $n->class_id;
#		$stop >= $n->created;
#		sort $i->created;
#		return $i, class_name => $c->name;
#	};
#	for my $info (@info) {
#		my $e = db_fetch {
#			my $e : ip_extras;
#			$e->id == $info->{id};
#		};
#		%$info = (%$info, %$e) if $e;
#	}
#	my @net = db_fetch {
#		my $n : networks;
#		my $c : classes;
#		inet_contains($n->net, $ip);
#		$n->invalidated >= $start || $n->invalidated == 0;
#		$stop >= $n->created;
#		$c->id == $n->class_id;
#		sort $n->created;
#		return $n, class_name => $c->name;
#	};
#	return [@info,@net];
#}
#
#sub handle_ipexport
#{
#	my $r;
#	if (param("range")) {
#		$r = eval { do_ipexport_range($id, ignore_ip => param("ignore_ip"), with_free => param("with_free")); };
#	} else {
#		$r = eval { do_ipexport_net($id, ignore_ip => param("ignore_ip"), with_free => param("with_free")); };
#	}
#	if ($r && ref($r) && ref($r) eq "HASH" && !$r->{error}) {
#		print csv_header($r->{filename});
#		for (@{$r->{content}}) {
#			print "$_\n";
#		}
#	} else {
#		print html_header();
#		print "<html><head><title>IP Export Error</title></head>\n";
#		print "<body><h1>IP Export Error</h1><p>\n";
#		if ($r && $r->{error}) {
#			print "$r->{error}\n";
#		} elsif ($r) {
#			print "$r\n";
#		} else {
#			print "$@\n";
#		}
#		print "</p></body></html>\n";
#	}
#}
#
#sub handle_tags_summary
#{
#	return [fetch_tags_summary()];
#}
#
#sub handle_networks_for_tag
#{
#	my $tag = u2p(param("tag")||"");
#	return fetch_networks_for_tag($tag);
#}
#
#sub handle_fetch_settings
#{
#	my $dbh = connect_db();
#	return { error => "Permission \"superuser\" denied" } unless perm_check("superuser");
#	my @users = db_fetch {
#		my $u : users;
#		sort $u->name;
#	};
#	my @groups = db_fetch {
#		my $g : groups;
#		sort $g->id;
#	};
#	my %groups = map { $_->{id} => $_ } @groups;
#	for my $g (@groups) {
#		$g->{permissions} = expand_permissions(eval { decode_json($g->{permissions}); } || {});
#	}
#	my @classes = db_fetch {
#		my $t : classes;
#		sort $t->ord;
#	};
#	return {
#		users   => \@users,
#		groups  => \%groups,
#		classes => \@classes,
#		default_group => $TIPP::default_group_id,
#	};
#}
#
#sub handle_update_user
#{
#	my $dbh = connect_db();
#	return { error => "Permission \"superuser\" denied" } unless perm_check("superuser");
#	my $user = param("user");
#	return { error => "user parameter is required" } unless defined $user;
#	my $group_id = param("group_id");
#	return { error => "group_id parameter is required" } unless defined $group_id;
#
#	my $old_u = db_fetch {
#		my $u : users;
#		$u->name == $user;
#	};
#	if ($old_u && $old_u->{group_id} == $group_id) {
#		return $old_u;
#	}
#	my $g = db_fetch {
#		my $g : groups;
#		$g->id == $group_id;
#	};
#	return { error => "group_id $group_id not found" } unless $g;
#	if ($old_u) {
#		db_update {
#			my $u : users;
#			$u->name == $user;
#
#			$u->group_id = $group_id;
#		};
#		log_change(user => "Modified user $user, group $group_id", when => time);
#	} else {
#		db_insert 'users', {
#			name        => $user,
#			group_id    => $group_id,
#		};
#		log_change(user => "Created user $user, group $group_id", when => time);
#	}
#	$dbh->commit;
#	my $new_u = db_fetch {
#		my $u : users;
#		$u->name == $user;
#	};
#	return $new_u;
#}
#
#sub handle_update_group
#{
#	return { error => "Permission \"superuser\" denied" } unless perm_check("superuser");
#	my @p = param();
#	my %globals = map { $_ => 1 } qw(superuser view_changelog view_usage_stats);
#	my $gid = param("gid");
#	return { error => "gid parameter is required" } unless defined $gid;
#	my $dbh = connect_db();
#	my $g = {};
#	for my $p (@p) {
#		if ($globals{$p}) {
#			$g->{$p} = param($p);
#		} elsif ($p =~ /^(range|net|ip)-(\d+)$/) {
#			if ($2) {
#				$g->{by_class}{$2}{$1} = param($p);
#			} else {
#				$g->{$1} = param($p);
#			}
#		}
#	}
#	my @extra;
#	if ($gid) {
#		my $old = db_fetch {
#			my $g : groups;
#
#			$g->id == $gid;
#		} || "{}";
#
#		my $old_g = expand_permissions(eval { decode_json($old->{permissions}); } || {});
#		my $new_g = expand_permissions($g);
#		my $comments = param("comments");  $comments = "" unless defined $comments;
#		if (Data::Compare::Compare($old_g, $new_g) && $comments eq $old_g->{comments}) {
#			$old->{permissions} = $old_g;
#			return $old;
#		}
#		my $json_permissions = encode_json($g);
#		db_update {
#			my $g : groups;
#			$g->id == $gid;
#
#			$g->permissions = $json_permissions;
#			$g->comments = $comments;
#		};
#		log_change(group => "Modified group $old->{name}", when => time);
#		$dbh->commit;
#		my $new = $old;
#		$new->{permissions} = $g;
#		$new->{comments} = $comments;
#		return $new;
#	} else {
#		my $group_name = param("name");
#		if (!$group_name) {
#			return { error => "Group name is required" };
#		} elsif ($group_name eq "change me!") {
#			return { error => "Please choose reasonable group name" };
#		}
#		my $comments = param("comments");  $comments = "" unless defined $comments;
#		my $new_id = db_fetch { return `nextval('groups_id_seq')`; };
#		db_insert 'groups', {
#			id			=> $new_id,
#			name        => $group_name,
#			comments    => $comments,
#			permissions => encode_json($g),
#		};
#		log_change(group => "Created group $group_name", when => time);
#		$dbh->commit;
#		my $new = db_fetch {
#			my $g : groups;
#
#			$g->id == $new_id;
#		} || "{}";
#		$new->{permissions} = expand_permissions(eval { decode_json($new->{permissions}); } || {});
#		return $new;
#	}
#}

# == PART OF THE NEW API ==

sub ping
{
    my $c = shift;

    $c->render( json => { response => 'pong' } );
}

# == END OF HANDLERS ==


1;
