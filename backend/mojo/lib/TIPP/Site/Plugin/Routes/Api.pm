package TIPP::Site::Plugin::Routes::Api;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

sub register
{
    my ( $me, $app ) = @_;
    my $api = $app->routes->under('/api');

    $api->any( [qw(get post)] => '' )->to('api#handle_root')->name('api-root');

    my @cmds = qw/config class net paginate addresses nslookup/;
    for my $cmd ( @cmds, 'suggest-network') {
        ( my $path = $cmd ) =~  s/-/_/g;
        $api->any( [qw(get post)] => $cmd )->to("api#handle_$path")->name("api-$path");
    }
    
    $api->any( [qw(get post)] => 'ping' )->to('api#ping')->name('api-ping');
}

1;
