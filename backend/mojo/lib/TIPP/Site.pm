package TIPP::Site;
use Mojo::Base 'Mojolicious';

our $VERSION = v0.5.0;

use File::Basename;
use Mojolicious::Plugin::Database;

has [ 'db_user', 'db_pass', 'db_dsn' ];

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

    $me->db_user( $me->config->{tipp}{db_user} // 'tippuser' );
    $me->db_pass( $me->config->{tipp}{db_pass} // '' );
    $me->db_dsn(
        sprintf(
            'dbi:Pg:dbname=%s;host=%s',
            ( $me->config->{tipp}{db_name} // 'tippdb' ),
            ( $me->config->{tipp}{db_host} // '127.0.0.1' )
        )
    );

    $me->plugin(
        'database',
        {
            dsn      => $me->db_dsn,
            username => $me->db_user,
            password => $me->db_pass,
            options  => { 'pg_enable_utf8' => 1, AutoCommit => 0 },
            helper   => 'dbh',
        }
    );

    $me->plugin('Helpers::Auth');
    $me->plugin('Helpers::Export');
    $me->plugin('Helpers::Ip');
    $me->plugin('Helpers::Log');
    $me->plugin('Helpers::Permissions');
    $me->plugin('Helpers::Search');
    $me->plugin('Helpers::Tags');
    $me->plugin('Helpers::Utils');
    $me->plugin('Routes::Api');
}

1;
