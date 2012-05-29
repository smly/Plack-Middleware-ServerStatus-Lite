package Plack::Middleware::ServerStatus::Lite;

use strict;
use warnings;
use parent qw(Plack::Middleware);
use Plack::Util::Accessor qw(scoreboard path allow display_ss display_totalaccess);
use Parallel::Scoreboard;
use Net::CIDR::Lite;
use IPC::Shareable;
use Try::Tiny;
use JSON;

our $VERSION = '0.06';

sub prepare_app {
    my $self = shift;
    $self->{uptime}   = time;
    $self->{ipc_glue} = 'access_count';

    if ( $self->allow ) {
        my $cidr = Net::CIDR::Lite->new();
        my @ip = ref $self->allow ? @{$self->allow} : ($self->allow);
        $cidr->add_any( $_ ) for @ip;
        $self->{__cidr} = $cidr;
    }

    if ( $self->scoreboard ) {
        my $scoreboard = Parallel::Scoreboard->new(
            base_dir => $self->scoreboard
        );
        $self->{__scoreboard} = $scoreboard;
    }
}

sub call {
    my ($self, $env) = @_;

    $self->set_state("A", $env);

    my $res;
    try {
        if( $self->path && $env->{PATH_INFO} eq $self->path ) {
            $res = $self->_handle_server_status($env);
            $self->set_state("_");
        }
        else {
            eval {
                tie my $shm_counter, 'IPC::Shareable', $self->{ipc_glue},
                { create => 'yes', exclusive => 0, mode => 644, destroy => 0 };

                (tied $shm_counter)->shlock;
                ++$shm_counter;
                (tied $shm_counter)->shunlock;
            };

            my $app_res = $self->app->($env);

            if ( ref $app_res eq 'ARRAY' ) {
                $res = $app_res;
                $self->set_state("_");
            }
            else {
                $res = sub {
                    my $respond = shift;

                    my $writer;
                    try {
                        $app_res->(sub { return $writer = $respond->(@_) });
                    } catch {
                        if ($writer) {
                            $writer->close;
                        }
                        die $_;
                    } finally {
                        $self->set_state("_");
                    };
                };
            }
        }
    } catch {
        $self->set_state("_");
        die $_;
    };
    return $res;
}

my $prev='';
sub set_state {
    my $self = shift;
    return if !$self->{__scoreboard};

    my $status = shift || '_';
    my $env = shift;
    if ( $env ) {
        no warnings 'uninitialized';
        $prev = join(" ", $env->{REMOTE_ADDR}, $env->{HTTP_HOST} || '', 
                          $env->{REQUEST_METHOD}, $env->{REQUEST_URI}, $env->{SERVER_PROTOCOL});
    }
    $self->{__scoreboard}->update(
        sprintf("%s %d %s",$status, time, $prev)
    );
}

sub _handle_server_status {
    my ($self, $env ) = @_;

    if ( ! $self->allowed($env->{REMOTE_ADDR}) ) {
        return [403, ['Content-Type' => 'text/plain'], [ 'Forbidden' ]];
    }

    my $access_count;
    eval {
        tie my $shm_counter, 'IPC::Shareable', $self->{ipc_glue},
        { create => 'yes', exclusive => 0, mode => 0644, destroy => 0 };
    };

    my $upsince = time - $self->{uptime};
    my $duration = "";
    my @spans = (86400 => 'days', 3600 => 'hours', 60 => 'minutes');
    while (@spans) {
        my ($seconds,$unit) = (shift @spans, shift @spans);
        if ($upsince > $seconds) {
            $duration .= int($upsince/$seconds) . " $unit, ";
            $upsince = $upsince % $seconds;
        }
    }
    $duration .= "$upsince seconds";

    my $body="Uptime: $self->{uptime} ($duration)\n";
    $body .= "Total Accesses: $access_count\n";
    my %stats = ( 'Uptime' => $self->{uptime} );
    if ( my $scoreboard = $self->{__scoreboard} ) {
        my $stats = $scoreboard->read_all();
        my $raw_stats='';
        my $idle = 0;
        my $busy = 0;

        my $parent_pid = getppid;
        my $ps = `LC_ALL=C command ps -e -o ppid,pid`;
        $ps =~ s/^\s+//mg;
        my @all_workers;
        for my $line ( split /\n/, $ps ) {
            next if $line =~ m/^\D/;
            my ($ppid, $pid) = split /\s+/, $line, 2;
            push @all_workers, $pid if $ppid == $parent_pid;
        }

        my @raw_stats;
        for my $pid ( @all_workers  ) {
            if ( exists $stats->{$pid} && $stats->{$pid} =~ m!^A! ) {
                $busy++;
            }
            else {
                $idle++;
            }
            my $status_line = $stats->{$pid};
            my $worksince = 0;
            if ( exists $stats->{$pid} && $stats->{$pid} =~ m/^([A_])\s(\d+)\s(.+)$/ ) {
                my $ss = time - $2;
                $status_line = sprintf "%s SS=%d %s", $1, $ss, $3;
            }
            $raw_stats .= sprintf "%s %s\n", $pid, $status_line || '.';
            my @pstats = split /\s/, $stats->{$pid} || '.';
            push @raw_stats, {
                pid => $pid,
                status => defined $pstats[0] ? $pstats[0] : undef, 
                remote_addr => defined $pstats[1] ? $pstats[1] : undef,
                host => defined $pstats[2] ? $pstats[2] : undef,
                method => defined $pstats[3] ? $pstats[3] : undef,
                uri => defined $pstats[4] ? $pstats[4] : undef,
                protocol => defined $pstats[5] ? $pstats[5] : undef
            };
        }
        $body .= <<EOF;
BusyWorkers: $busy
IdleWorkers: $idle
--
pid status remote_addr host method uri protocol
$raw_stats
EOF
        $stats{BusyWorkers} = $busy;
        $stats{IdleWorkers} = $idle;
        $stats{stats} = \@raw_stats;
    }
    else {
       $body .= "WARN: Scoreboard has been disabled\n";
       $stats{WARN} = 'Scoreboard has been disabled';
    }
    if ( ($env->{QUERY_STRING} || '') =~ m!\bjson\b!i ) {
        return [200, ['Content-Type' => 'application/json; charset=utf-8'], [ JSON::encode_json(\%stats) ]];
    }
    return [200, ['Content-Type' => 'text/plain'], [ $body ]];
}

sub allowed {
    my ( $self , $address ) = @_;
    return unless $self->{__cidr};
    return $self->{__cidr}->find( $address );
}


1;
__END__

=head1 NAME

Plack::Middleware::ServerStatus::Lite - show server status like Apache's mod_status

=head1 SYNOPSIS

  use Plack::Builder;

  builder {
      enable "Plack::Middleware::ServerStatus::Lite",
          path => '/server-status',
          allow => [ '127.0.0.1', '192.168.0.0/16' ],
          scoreboard => '/var/run/server';
      $app;
  };

  % curl http://server:port/server-status
  Uptime: 1234567789
  BusyWorkers: 2
  IdleWorkers: 3
  --
  pid status remote_addr host method uri protocol
  20060 A 127.0.0.1 localhost:10001 GET / HTTP/1.1
  20061 .
  20062 A 127.0.0.1 localhost:10001 GET /server-status HTTP/1.1
  20063 .
  20064 .

  # JSON format
  % curl http://server:port/server-status?json
  {"Uptime":"1332476669","BusyWorkers":"2",
   "stats":[
     {"protocol":null,"remote_addr":null,"pid":"78639",
      "status":".","method":null,"uri":null,"host":null},
     {"protocol":"HTTP/1.1","remote_addr":"127.0.0.1","pid":"78640",
      "status":"A","method":"GET","uri":"/","host":"localhost:10226"},
     ...
  ],"IdleWorkers":"3"}

=head1 DESCRIPTION

Plack::Middleware::ServerStatus::Lite is a middleware that display server status in multiprocess Plack servers such as Starman and Starlet. This middleware changes status only before and after executing the application. so cannot monitor keepalive session and network i/o wait. 

=head1 CONFIGURATIONS

=over 4

=item path

  path => '/server-status',

location that displays server status

=item allow

  allow => '127.0.0.1'
  allow => ['192.168.0.0/16', '10.0.0.0/8']

host based access control of a page of server status

=item scoreboard

  scoreboard => '/path/to/dir'

Scoreboard directory, Middleware::ServerStatus::Lite stores processes activity information in

=back

=head1 AUTHOR

Masahiro Nagano E<lt>kazeburo {at} gmail.comE<gt>

=head1 SEE ALSO

Original ServerStatus by cho45 <http://github.com/cho45/Plack-Middleware-ServerStatus>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
