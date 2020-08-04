package TIPP::Site;
use Mojo::Base 'Mojolicious';

our $VERSION = v0.5.0;

use File::Basename;
use Mojo::Pg;

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
    my $db_name = $me->config->{tipp}{db_name} // 'tippdblocal';
    my $db_user = $me->config->{tipp}{db_user} // 'tippuser';
    my $db_pass = $me->config->{tipp}{db_pass} // '';

    $me->helper(
        'pg',
        sub {
            my $connect = "postgresql://$db_user:$db_pass\@$db_host/$db_name";

            state $pg = Mojo::Pg->new($connect);
            unless ( $pg->db->ping ) {
                $pg = Mojo::Pg->new($connect);
            }

            # Remove quote_char '"', which is default by SQL::Abstract::Pg,
            # Making it possible to have "complex" keys in where clause as : "ifmib->>'ifName'"
            $pg->abstract( SQL::Abstract::Pg->new( array_datatypes => 1, name_sep => '.' ) );
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
