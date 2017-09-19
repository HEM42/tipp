use Test::More;
use Test::Mojo;

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

my $t = Test::Mojo->new('TIPP::Site');

is 'TIPP::NetAddr::IP', ref $t->app->N('10.0.0.0/24'), 'Returns correct object';
is '10.0.0.0/24', $t->app->N('10.0.0.0/24'), 'Returns correct network';
is '10.0.0.1', $t->app->N('10.0.0.1/24')->ip, 'ip returns correct value';

is 'TIPP::NetAddr::IP', ref $t->app->N('2000:1000::/64'), 'Returns correct object';
is '2000:1000::/64', ''.$t->app->N('2000:1000::/64'), 'Returns correct network';
is '2000:1000::1', $t->app->N('2000:1000::1/64')->ip, 'ip returns correct value';

# Compacting networks into a single large one
my $net1 = $t->app->N('10.0.0.0/25');
my $net2 = $t->app->N('10.0.0.128/25');

my @nets = $t->app->ip->compact($net1,$net2);
is '10.0.0.0/24', $nets[0], 'Returns correct network';

$t->app->dbh->rollback;
done_testing();
