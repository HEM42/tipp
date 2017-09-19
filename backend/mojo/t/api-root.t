use Test::More;
use Test::Mojo;

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

my $t = Test::Mojo->new('TIPP::Site');

my $url = $t->ua->server->url->userinfo('superuser:superuser')->path('/api/');
$t->get_ok($url)->status_is(200)->json_has( [ { id => 10, name => 'Customer' }, { id => 20, name => 'Infratructure' } ] );

$t->app->dbh->rollback;
done_testing();
