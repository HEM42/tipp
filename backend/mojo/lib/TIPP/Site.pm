package TIPP::Site;
use Mojo::Base 'Mojolicious';

our $VERSION = v0.2.0;

use File::Basename;

# This method will run once at server start
sub startup {
    my $me = shift;

    # Setup TIPP App with auth routes and default config
    $me->plugin('TIPP::Site', {
        moniker           => 'tipp-site',
        session_key       => 'tipp',
        configfile        => File::Spec->catfile('config', 'tipp-site.conf'),
        cookie_name       => 'tipp',
        cookie_expiration => 3600 * 24 * 7,
    });

    $me->plugin('Routes::Api');
}

1;
