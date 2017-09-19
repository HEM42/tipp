use Test::More;
use Test::Mojo;

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

my $t = Test::Mojo->new('TIPP::Site');
$t->get_ok('/api/ping')->status_is(200)->json_is({response => 'pong'});
$t->get_ok('/api?what=ping')->status_is(200)->json_is({response => 'pong'});
$t->post_ok('/api/ping')->status_is(200)->json_is({response => 'pong'});
$t->post_ok('/api?what=ping')->status_is(200)->json_is({response => 'pong'});

done_testing();
