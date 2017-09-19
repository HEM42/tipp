use Test::More;
use Test::Mojo;

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

my $t = Test::Mojo->new('TIPP::Site');

my $url = $t->ua->server->url->userinfo('superuser:superuser')->path('/api/fetch-settings');

#pp $t->get_ok($url)->tx->res->json;
$t->get_ok($url)->status_is(200)->json_has( { classes => [], users => [], groups => {} } );

$t->app->dbh->rollback;
done_testing();
