package Mojolicious::Plugin::TIPP::Site;
use Mojo::Base 'Mojolicious::Plugin';

use Data::Printer alias => 'pp', use_prototypes => 0, colored => 1;

sub register {
    my ($self, $app, $plugin_config) = @_;

    # Make sure we have a config hash
    $plugin_config //= {};

    # Look for plugins under TIPP::Site
    push @{$app->plugins->namespaces}, qw[
        TIPP::Site::Plugin
    ];

    # Set custom moniker (Can be used to prevent spaces in moniker if package is in all-caps)
    $app->moniker($plugin_config->{moniker}) if $plugin_config->{moniker};

    # Session options
    $app->sessions->cookie_name($plugin_config->{cookie_name} // 'tipp');
    $app->sessions->default_expiration($plugin_config->{cookie_expiration} // 3600 * 24 * 7);

    # Load config plugin
    $app->plugin('ConfigHashMerge' => {
        file => $plugin_config->{configfile},
    });

    # Setup security
    $app->secrets([ $app->config->{mojo}{secrets} ]);

    # Add name spaces where we should look for controllers
    $app->routes->namespaces([
        'TIPP::Site::Controller',
    ]);
    if ( ref($app) ne 'TIPP::Site' ) {
        push(
            @{$app->routes->namespaces},
            ref($app).'::Controller'
        );
    }

    $app->hook(
        before_dispatch => sub {
            my $c = shift;
            $c->pg->db->dbh->{AutoCommit} = 0;

            # canonicalize path
            my $what = $c->req->param('what');                                          # old api style, support replacement of the backend
            $c->req->url->path->trailing_slash(1)->merge($what) if $what;               # append 'what' to url

            # get the 'what' part
            my @parts = @{ $c->req->url->path->parts };
            $c->stash( what => $parts[-1] || '' );

        }
    );
    $app->hook(
        after_dispatch => sub {
            my $c = shift;
            $c->pg->db->dbh->{AutoCommit} = 1;
        }
    );

}

1;
