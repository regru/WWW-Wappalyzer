package WWW::Wappalyzer;

use 5.006;
use strict;
use warnings;

use base qw ( Exporter );
our @EXPORT_OK = qw( detect get_categories add_clues_file );

use lib::abs;
use JSON qw();

my %_categories;
my @_clues_file_list = ( lib::abs::path( './apps.json' )  );

# List of multi per web page application categories
my %MULTIPLE_APP_CATS = map { $_ => 1 } qw( 
    widgets analytics javascript-frameworks video-players
    font-scripts miscellaneous advertizing-networks
);

=head1 NAME

WWW::Wappalyzer - Perl port of Wappalyzer (L<http://wappalyzer.com>)

=head1 DESCRIPTION

Uncovers the technologies used on websites: detects content management systems, web shops,
web servers, JavaScript frameworks, analytics tools and many more.

Lacks 'version' and 'confidence' support of original Wappalyzer in favour of speed.

Clues:      L<https://github.com/ElbertF/Wappalyzer/blob/master/share/apps.json>

More info:  L<https://github.com/ElbertF/Wappalyzer/blob/master/README.md>

=head1 VERSION

Version 0.11

=cut

our $VERSION = '0.11';


=head1 SYNOPSIS

    use WWW::Wappalyzer;
    use LWP::UserAgent;

    my $response = LWP::UserAgent->new->get( 'http://www.drupal.org' );
    my %detected = WWW::Wappalyzer::detect(
        html    => $response->decoded_content,
        headers => $response->headers,
    );

    # %detected = (
    #     'web-servers'       => [ 'Apache' ],
    #     'cms'               => [ 'Drupal' ],
    #     'cache-tools'       => [ 'Varnish' ],
    #     'analytics'         => [ 'Google Analytics' ],
    #     'operating-systems' => [ 'CentOS' ]
    # );

=head1 EXPORT

None by default.

=head1 SUBROUTINES/METHODS

=head2 detect

    my %detected = detect( %params )

Tries to detect CMS, framework, etc for given html code, http headers, url.

Available parameters:

    html    - html code of web page
    headers - hash ref to http headers list
    url     - url of web page
    cats    - array ref to a list of trying categories, defaults to all categories;
              less cats => less cpu usage

Returns the hash of detected applications by categorie:

    (
        cms  => [ 'Joomla' ],
        'javascript-frameworks' => [ 'jQuery', 'jQuery UI' ],
    )

=cut

sub detect {
    my %params = @_;

    return () unless $params{html} || $params{headers} || $params{url};

    # Lazy load and process clues from JSON file
    _load_categories() unless scalar keys %_categories;

    my @cats = $params{cats} && ( ref( $params{cats} ) || '' ) eq 'ARRAY'
        ? @{ $params{cats} } : get_categories();

    my $headers_ref;
    if ( $params{headers} ) {
        # make all headers name lowercase
        while ( my ( $name, $value ) = each %{ $params{headers} } ) {        
            $headers_ref->{ lc $name } = $value;
        }
    }

    my %detected;
    my %tried_multi_cat_apps;
    for my $cat ( @cats ) {
        my $apps_ref = $_categories{ $cat } or die "Unknown categorie $cat";

        APP:
        for my $app_ref ( @$apps_ref ) {

            my $detected;

            # Some speed optimizations
            if ( @cats > 1 && $app_ref->{multi_cat}
                && exists $tried_multi_cat_apps{ $app_ref->{name} }
            ) {
                $detected = $tried_multi_cat_apps{ $app_ref->{name} };
            }
            else {
                # Try regexes...

                if ( defined $headers_ref && exists $app_ref->{headers_re} ) {
                    my %headers_re = %{ $app_ref->{headers_re} };
                    while ( my ( $header, $re ) = each %headers_re ) {
                        my $header_val = $headers_ref->{ $header } or next;

                        if ( $header_val =~ m{$re}ims ) {
                            $detected = 1;
                            last;
                        }
                    }
                }

                unless ( $detected ) {
                    # try from most to least relevant method
                    for my $re_type ( qw( html url ) ) {
                        if ( defined $params{ $re_type } && exists $app_ref->{ $re_type. '_re' }
                            && $params{ $re_type } =~ m{$app_ref->{ $re_type. '_re' }}ims
                        ) {
                            $detected = 1;
                            last;
                        }
                    }
                }

                # Some speed optimizations
                if ( @cats > 1 && $app_ref->{multi_cat} ) {
                    $tried_multi_cat_apps{ $app_ref->{name} } = $detected;
                }
            }

            next unless $detected;

            # Detected!
            push @{ $detected{ $cat } }, $app_ref->{name};

            last APP unless $MULTIPLE_APP_CATS{ $cat };
        }
    }

    return %detected;
}

=head2 get_categories

    my @cats = get_categories()

Returns the array of all application categories.

=cut

sub get_categories {
    # Lazy load and process clues from JSON files
    _load_categories() unless scalar keys %_categories;

    return keys %_categories;
}

# Loads and processes clues from JSON files
sub _load_categories {

    for my $clue_file ( @_clues_file_list ) {
        open my $fh, '<', $clue_file
            or die "Can not read clues file $clue_file.";

        local $/ = undef;
        my $json = <$fh>;
        close $fh;

        # Do not support "Optional fields"
        $json =~ s{ \\\\; (?: version | confidence ) [^"]+? " }{"}xig;

        # Replace html entities with oridinary symbols
        $json =~ s{&gt;}{>}xig;
        $json =~ s{&lt;}{<}xig;

        my $cfg_ref = eval { JSON::decode_json( $json ) };

        die "Can't parse clue file $clue_file: $@" if $@;

        my $cats_ref = $cfg_ref->{categories}
            or die "Broken clues file $clue_file. Can not find categories.";

        my $apps_ref = $cfg_ref->{apps}
            or die "Broken clues file $clue_file. Can not find applications.";

        # Process apps
        while ( my ( $app, $app_ref ) = each %$apps_ref ) {

            my $new_app_ref = _process_app_clues( $app, $app_ref ) or next;

            my @cats = @{ $app_ref->{cats} } or next;

            $new_app_ref->{multi_cat} = 1 if @cats > 1;

            for my $cat_id ( @cats ) {
                my $cat = $cats_ref->{ $cat_id } or next;

                push @{ $_categories{ $cat } }, $new_app_ref;
            }
        }
    }
}

# Process clues of given app
sub _process_app_clues {
    my ( $app, $app_ref ) = @_;

    my $new_app_ref = { name => $app };

    my @fields = grep { exists $app_ref->{$_} } qw( script html meta headers url );
    my @html_re;
    # Precompile regexps
    for my $field ( @fields ) {
        my $re_ref = $app_ref->{ $field };
        my @re_list =   !ref $re_ref ? _escape_re( $re_ref )
            : ref $re_ref eq 'ARRAY' ? ( map { _escape_re( $_ ) } @$re_ref )
            : () ;

        if ( $field eq 'html' ) {
            push @html_re, map { qr/(?-x:$_)/ } @re_list;
        }
        elsif ( $field eq 'script' ) {
            push @html_re,
                map {
                    qr/
                        < \s* script [^>]+ src \s* = \s* ["'] (?-x:[^"']*$_[^"']*) ["']
                    /x
                } @re_list;
        }
        elsif ( $field eq 'url' ) {
            $new_app_ref->{url_re} = join ' | ', map { qr/(?-x:$_)/ } @re_list;
            $new_app_ref->{url_re} = qr/$new_app_ref->{url_re}/x;
        }
        elsif ( $field eq 'meta' ) {
            for my $key ( keys %$re_ref ) {
                my $name_re = qr{ name \s* = \s* ["']? $key ["']? }x;
                my $re = _escape_re( $re_ref->{$key} );
                $re = qr/$re/;
                my $content_re = qr{ content \s* = \s* ["'] (?-x:[^"']*$re[^"']*) ["'] }x;

                push @html_re, qr/
                    < \s* meta \s+
                    (?:
                          (?: $name_re    \s+ $content_re )
                        # | (?: $content_re \s+ $name_re    ) # hangs sometimes
                    )
                /x;
            }
        }
        elsif ( $field eq 'headers' ) {
            for my $key ( keys %$re_ref ) {
                my $re = _escape_re( $re_ref->{$key} );
                $new_app_ref->{headers_re}{ lc $key } = qr/$re/;
            }
        }
    }

    if ( @html_re ) {
        # Clue all html regexps into one regexp
        $new_app_ref->{html_re} = join ' | ', map { "(?: $_ )" } @html_re;
        $new_app_ref->{html_re} = qr/$new_app_ref->{html_re}/x;
    }

    return $new_app_ref;
}

# Escape special symbols in regexp string of config file
sub _escape_re {
    my ( $re ) = @_;
    
    # Escape { } braces
    $re =~ s/ ([{}]) /[$1]/xig;

    # Escape [^]
    $re =~ s{\Q[^]\E}{[\\^]}ig;

    # Escape \\1
    $re =~ s{\Q\1\E}{\\\\1}ig;
   
    return $re;
}

=head2 add_clues_file

    add_clues_file( $filepath )

Puts additional clues file to a list of processed clues files.
See apps.json as format sample.

=cut

sub add_clues_file {
    my ( $filepath ) = @_;

    push @_clues_file_list, $filepath;

    # just clear out categories to lazy load later
    %_categories = ();
}

=head1 AUTHOR

Alexander Nalobin, C<< <alexander at nalobin.ru> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-www-wappalyzer at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=WWW-Wappalyzer>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc WWW::Wappalyzer


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=WWW-Wappalyzer>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/WWW-Wappalyzer>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/WWW-Wappalyzer>

=item * Search CPAN

L<http://search.cpan.org/dist/WWW-Wappalyzer/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2013 Alexander Nalobin.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of WWW::Wappalyzer
