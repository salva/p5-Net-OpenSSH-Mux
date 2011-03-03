package Net::OpenSSH::Mux;

use 5.010;

our $VERSION = '0.01';

use strict;
use warnings;
use Carp;

use Net::OpenSSH::Mux::Packer;
use Net::OpenSSH::Mux::Constants qw(:all);

use Socket::PassAccessRights;
use Errno ();

our $debug;

sub _debug { print STDERR '# ', (map { defined($_) ? $_ : '<undef>' } @_), "\n" }

sub _hexdump {
    no warnings qw(uninitialized);
    my $data = shift;
    while ($data =~ /(.{1,32})/smg) {
        my $line=$1;
        my @c= (( map { sprintf "%02x",$_ } unpack('C*', $line)),
                (("  ") x 32))[0..31];
        $line=~s/(.)/ my $c=$1; unpack("c",$c)>=32 ? $c : '.' /egms;
        print STDERR "#> ", join(" ", @c, '|', $line), "\n";
    }
}

sub new {
    my ($class, %opts) = @_;
    my $socket = delete $opts{socket} // croak "missing argument 'socket'";
    my $self = { _socket => $socket,
                 _error => '',
                 _rid => 1 };
    bless $self, $class;
    $self->hello;
    $self;
}

sub _next_rid { shift->{_rid}++ }

sub _set_error {
    my $self = shift;
    $self->{_error} = join(': ', @_);
    $debug and _debug "error set to $self->{_error}"
}

sub _send_msg {
    my ($self) = @_;
    my $len = length $_[1];
    my $off = 0;
    my $socket = $self->{_socket};

    if ($debug) {
        _debug "_send_msg(socket: $socket, buffer len: $len)";
        _hexdump $_[1];
    }

    while ($off < $len) {
        my $bytes = syswrite($socket, $_[1], 16 * 1024, $off);
        if ($bytes) {
            $off += $bytes;
        }
        else {
            $self->_set_error("connection to master lost: $!");
            return undef;
        }
    }
    for my $fh (@_[2..$#_]) {
        unless (Socket::PassAccessRights::sendfd(fileno($socket), fileno($fh))) {
            redo if ($! == Errno::EAGAIN() or $! == Errno::EINTR());
            $self->_set_error("unless to sendfd: $!");
            return undef;
        }
    }
    return 1;
}

sub _recv_data {
    my ($fd, $len) = @_;
    $_[2] = '';
    while (1) {
        my $off = length($_[2]);
        if ($off >= $len) {
            if ($debug) {
                _debug "recv_data($fd, $len) => ", length($_[2]), " bytes read";
                _hexdump($_[2]);
            }
            return 1
        }
        my $bytes = sysread($fd, $_[2], $len - $off, $off);
        unless ($bytes) {
            redo if ($! == Errno::EAGAIN() or $! == Errno::EINTR());
            $debug and _debug "sysread failed: $!";
            return undef;
        }
    }
}

sub _recv_msg {
    my ($self) = @_;
    my $socket = $self->{_socket};
    if (_recv_data($socket, 8, $_[1])) {
        my ($size, $cmd) = unpack NN => $_[1];
        if (_recv_data($socket, $size - 4, $_[1])) {
            $debug and _debug "received message of $size bytes, $cmd = $cmd";
            return $cmd;
        }
    }
    $self->_set_error("connection to master lost");
    return undef;
}

sub hello {
    my $self = shift;
    my $buf = '';
    pack_msg_hello_msg($buf, 'keep-alive' => 1);
    $self->_send_msg($buf);
    my $cmd = $self->_recv_msg($buf);
    unless ($cmd == MUX_MSG_HELLO) {
        $self->_set_error("response missmatch, expecting " . MUX_MSG_HELLO . " cmd, got $cmd");
        return undef;
    }
    my @r = unpack_msg_hello($buf);
    unless (@r) {
        $self->_set_error("corrupted msg_hello packed");
        return undef;
    }
    return (wantarray ? @r : $r[0]);
}

sub _send_c_new_session {
    my ($self, $cmd, $opts, $fdin, $fdout, $fderr) = @_;
    $opts //= {};
    my $rid = $self->_next_rid;
    my $buf = '';
    pack_c_new_session_msg($buf, $rid, $cmd, %$opts);
    $self->_send_msg($buf, $fdin, $fdout, $fderr) or return ();
    return $rid;
}

sub _c_new_session {
    my $self = shift;
    my $rid = $self->_send_c_new_session(@_) // return ();
    my $cmd = $self->_recv_msg(my $buf);
    given ($cmd) {
        when(MUX_S_SESSION_OPENED) {
            my ($rid1, $sid) = unpack_s_session_opened_msg($buf);
            unless ($rid == $rid1) {
                $self->_set_error("query/reply id mismatch");
                return ();
            }
            return $sid;
        }
        when ([MUX_S_PERMISSION_DENIED, MUX_S_FAILURE]) {
            my ($rid1, $reason) = unpack_s_error_msg($buf);
            unless ($rid == $rid1) {
                $self->_set_error("query/reply id mismatch");
                return ();
            }
            $self->_set_error("unable to open new session: ", $reason);
            return ();
        }
        default {
            $self->_set_error("unexpected response $cmd");
            return ();
        }
    }
}

sub _wait_for_exit_message {
    my ($self, $sid) = @_;
    my $cmd = $self->_recv_msg(my $buf) // return ();
    if ($cmd != MUX_S_EXIT_MESSAGE) {
        $self->_set_error("unexpected response $cmd");
        return ();
    }
    my ($sid1, $exit) = unpack_s_exit_message_msg($buf);
    unless ($sid == $sid1) {
        $self->_set_error("session id mismatch, received $sid1, expected $sid");
        return ();
    }
    return $exit;
}

sub system {
    my ($self, $cmd) = @_;
    my $sid = $self->_c_new_session($cmd, undef, \*STDIN, \*STDOUT, \*STDERR) // return ();
    return $self->_wait_for_exit_message($sid)
}

1;
__END__

=head1 NAME

Net::OpenSSH::Mux - OpenSSH Mux client

=head1 SYNOPSIS

  use Net::OpenSSH::Mux;

=head1 DESCRIPTION

Stub documentation for Net::OpenSSH::Mux, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Salvador Fandino E<lt>sfandino@yahoo.comE<gt>.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.2 or,
at your option, any later version of Perl 5 you may have available.

=cut
