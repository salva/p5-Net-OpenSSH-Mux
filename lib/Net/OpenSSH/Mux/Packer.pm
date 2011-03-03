package Net::OpenSSH::Mux::Packer;

use 5.010;

our $VERSION = '0.01';

use strict;
use warnings;
use Carp;

use Net::OpenSSH::Mux::Constants qw(:msg);

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = do { no strict; grep /^(?:un)?pack_/, keys %{__PACKAGE__ . '::'}};

sub _pack_string { $_[0] .= pack(N => length $_[1]) . $_[1] }

sub _pack_start {
    my $start = length $_[0];
    $_[0] .= "\x00\x00\x00\x00";
    $start;
}

sub _pack_end {
    my $start = $_[1];
    my $end = length $_[0];
    substr($_[0], $start, 4, pack(N => $end - $start - 4));
}

sub pack_msg_hello_msg {
    my $start = _pack_start($_[0]);
    $_[0] .= "\x00\x00\x00\x01\x00\x00\x00\x04"; # $_[0] .= pack(NN => MUX_MSG_HELLO, 4);
    _pack_string($_[0], $_) for (@_[1..$#_]);
    _pack_end($_[0], $start);
}

sub pack_c_alive_check_msg {
    my $start = _pack_start($_[0]);
    $_[0] .= pack NN => MUX_C_ALIVE_CHECK, $_[1];
    _pack_end($_[0], $start)
}

sub pack_c_new_session_msg {
    my (undef, $rid, $cmd, %opts) = @_;
    my $flags = 0;
    my $want_tty = delete $opts{want_tty} || 0;
    my $want_X11_forwarding = delete $opts{want_X11_forwarding} || 0;
    my $want_agent = delete $opts{want_agent} || 0;
    my $subsystem = delete $opts{subsystem} || 0;
    my $escape = delete $opts{escape_char} // 0xffffffff;
    my $term = delete $opts{term} // $ENV{TERM} // 'vt100';
    my $env = delete $opts{env} // [];

    my $start = _pack_start($_[0]);
    $_[0] .= pack('N*' => MUX_C_NEW_SESSION, $rid, 0,
                  $want_tty, $want_X11_forwarding, $want_agent,
                  $subsystem, $escape);
    _pack_string($_[0], $term);
    _pack_string($_[0], $cmd);
    _pack_string($_[0], $_) for @$env;
    _pack_end($_[0], $start);
}

sub pack_c_new_stdio_fwd {
    my (undef, $rid, $connect_host, $connect_port) = @_;
    my $start = _pack_start($_[0]);
    $_[0] .= pack NN => MUX_C_NEW_STDIO_FWD, $rid;
    _pack_string($_[0], $_) for ('', $connect_host, $connect_port);
    _pack_end($_[0], $start);
}

sub pack_c_terminate_msg {
    my $start = _pack_start($_[0]);
    $_[0] .= pack(NN => MUX_C_TERMINATE, $_[1]);
    _pack_end($_[0], $start);
}

sub pack_c_open_fwd {
    my (undef, $rid, $type, $listen_host, $listen_port, $connect_host, $connect_port) = @_;
    my $start = _pack_start($_[0]);
    $_[0] .= pack(NNN => MUX_C_OPEN_FWD, $rid, $type);
    $_[0] .= _pack_string($_) for ($listen_host, $listen_port, $connect_host, $connect_port);
    _pack_end($_[0], $start);
}

sub _unpack_string {
    length $_[0] >= 4 or return ();
    my $len = unpack N => substr($_[0], 0, 4, '');
    return substr($_[0], 0, $len, '');
}

sub unpack_msg_hello {
    length $_[0] >= 4 or return ();
    my $ver = unpack N => substr($_[0], 0, 4);
    my @ext;
    while (length $_[0]) {
        my $ext = _unpack_string($_[0]) // last;
        push @ext, $ext;
    }
    return $ver, @ext;
}

sub unpack_s_alive_msg {
    length $_[0] >= 8 or return ();
    unpack NN => substr($_[0], 0, 8, ''); # rid, pid
}

sub unpack_s_ok_msg {
    length $_[0] >= 4 or return ();
    unpack N => substr($_[0], 0, 4, '');
}

sub unpack_s_error_msg {
    length $_[0] >= 4 or return ();
    my $rid = unpack N => substr($_[0], 0, 4, '');
    my $reason = _unpack_string($_[0]);
    return ($rid, $reason);
}

sub unpack_s_remote_port {
    length $_[0] >= 12 or return ();
    unpack NNN => substr($_[0], 0, 12, '');
}

sub unpack_s_session_opened_msg {
    length $_[0] >= 8 or return ();
    unpack NN => substr($_[0], 0, 8, ''); # rid, sid.
}

sub unpack_s_exit_message_msg {
    length $_[0] >= 8 or return ();
    unpack NN => substr($_[0], 0, 8, ''); # sid, exit code
}

1;
