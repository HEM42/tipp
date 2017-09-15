package TIPP::Site::Plugin::Routes::Api;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

sub register
{
    my ( $me, $app ) = @_;
    my $api = $app->routes->under('/api');

    $api->any( [qw(get post)] => '' )->to('api#handle_root')->name('api-root');
    $api->any( [qw(get post)] => 'config' )->to('api#handle_config')->name('api-config');
    $api->any( [qw(get post)] => 'ping' )->to('api#ping')->name('api-ping');
}

1;
