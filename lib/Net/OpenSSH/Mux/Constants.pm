package Net::OpenSSH::Mux::Constants;

use strict;
use warnings;

require Exporter;
our @ISA = qw(Exporter);

use constant MUX_MSG_HELLO           => 0x00000001;
use constant MUX_C_NEW_SESSION       => 0x10000002;
use constant MUX_C_ALIVE_CHECK       => 0x10000004;
use constant MUX_C_TERMINATE         => 0x10000005;
use constant MUX_C_OPEN_FWD          => 0x10000006;
use constant MUX_C_CLOSE_FWD         => 0x10000007;
use constant MUX_C_NEW_STDIO_FWD     => 0x10000008;
use constant MUX_S_OK                => 0x80000001;
use constant MUX_S_PERMISSION_DENIED => 0x80000002;
use constant MUX_S_FAILURE           => 0x80000003;
use constant MUX_S_EXIT_MESSAGE      => 0x80000004;
use constant MUX_S_ALIVE             => 0x80000005;
use constant MUX_S_SESSION_OPENED    => 0x80000006;
use constant MUX_S_REMOTE_PORT       => 0x80000007;

use constant MUX_FWD_LOCAL   => 1;
use constant MUX_FWD_REMOTE  => 2;
use constant MUX_FWD_DYNAMIC => 3;

our %EXPORT_TAGS;
$EXPORT_TAGS{msg} = [do { no strict; grep /^MUX_(?:C|S|MSG)_/, keys %{__PACKAGE__ ."::"} }];
$EXPORT_TAGS{fwd} = [do { no strict; grep /^MUX_FWD_/,         keys %{__PACKAGE__ ."::"} }];

our @EXPORT_OK = map @$_, values %EXPORT_TAGS;

$EXPORT_TAGS{all} = [@EXPORT_OK];

1;
