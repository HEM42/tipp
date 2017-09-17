package TIPP::Site;
use Mojo::Base 'Mojolicious';

our $VERSION = v0.5.0;

use File::Basename;
use Mojolicious::Plugin::Database;

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

    my $db_host = $me->config->{tipp}{db_host} // '127.0.0.1';
    my $db_name = $me->config->{tipp}{db_name} // 'tippdb';
    my $db_user = $me->config->{tipp}{db_user} // 'tippuser';
    my $db_pass = $me->config->{tipp}{db_pass} // '';
    my $dsn = sprintf 'dbi:Pg:dbname=%s;host=%s', $db_name, $db_host;

    $me->plugin(
        'database',
        {
            dsn      => $dsn,
            username => $db_user,
            password => $db_pass,
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
