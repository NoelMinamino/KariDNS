#!/usr/bin/perl
# ==============================================================================
# mock_dnstap_receiver.pl
#
# Standalone UNIX Domain Socket Frame Streams (fstrm) receiver for dnstap.
# Performs the fstrm bidirectional handshake with KariDNS and captures/decodes
# dnstap Protobuf frames.
#
# Usage:
#   perl tests/mock_dnstap_receiver.pl --socket /path/to/socket [--output <file>]
#                                      [--max-frames <N>] [--timeout <sec>]
# ==============================================================================

use strict;
use warnings;
use IO::Socket::UNIX;
use IO::Select;
use Getopt::Long;

my $socket_path = '/tmp/dnstap_test.sock';
my $output_file = '';
my $max_frames  = 0;
my $timeout_sec = 10;
my $verbose     = 0;

GetOptions(
    'socket=s'     => \$socket_path,
    'output=s'     => \$output_file,
    'max-frames=i' => \$max_frames,
    'timeout=i'    => \$timeout_sec,
    'verbose|v'    => \$verbose,
    'help|h'       => sub {
        print "Usage: $0 --socket <path> [--output <file>] [--max-frames <N>] [--timeout <sec>]\n";
        exit 0;
    }
);

unlink($socket_path) if -e $socket_path;

my $server = IO::Socket::UNIX->new(
    Type   => SOCK_STREAM,
    Local  => $socket_path,
    Listen => 5,
) or die "Cannot listen on UNIX socket $socket_path: $!\n";
chmod(0777, $socket_path);

print "[mock_dnstap] Listening on $socket_path\n";

my $out_fh;
if ($output_file) {
    open($out_fh, '>', $output_file) or die "Cannot open output file $output_file: $!\n";
} else {
    $out_fh = \*STDOUT;
}

my $sel = IO::Select->new($server);
my @ready = $sel->can_read($timeout_sec);
if (!@ready) {
    die "[mock_dnstap] Timeout waiting for connection on $socket_path\n";
}

my $client = $server->accept();
die "[mock_dnstap] Accept failed: $!\n" unless $client;
print "[mock_dnstap] Client connected\n";

# Handshake: Receive READY frame
# Format: escape (4B, 0) + len (4B) + type (4B, 4) + field (4B, 1) + ct_len (4B) + content_type
my $hdr;
read_exact($client, \$hdr, 8) or die "[mock_dnstap] Failed to read READY header\n";
my ($esc, $ready_len) = unpack('NN', $hdr);
die "[mock_dnstap] Invalid escape in READY frame: $esc\n" if $esc != 0;

my $ready_payload;
read_exact($client, \$ready_payload, $ready_len) or die "[mock_dnstap] Failed to read READY payload\n";
my ($ready_type, $ready_field, $ct_len) = unpack('NNN', substr($ready_payload, 0, 12));
die "[mock_dnstap] Expected READY type 4, got $ready_type\n" if $ready_type != 4;
my $content_type = substr($ready_payload, 12, $ct_len);
print "[mock_dnstap] Received READY with content-type: $content_type\n";

# Send ACCEPT frame
# escape (4B, 0) + len (4B) + type (4B, 1) + field (4B, 1) + ct_len (4B) + content_type
my $accept_payload = pack('NNN', 1, 1, length($content_type)) . $content_type;
my $accept_frame = pack('NN', 0, length($accept_payload)) . $accept_payload;
$client->syswrite($accept_frame) or die "[mock_dnstap] Failed to send ACCEPT frame: $!\n";
print "[mock_dnstap] Sent ACCEPT frame\n";

# Receive START frame
# escape (4B, 0) + len (4B) + type (4B, 2) + optional field/content_type
read_exact($client, \$hdr, 8) or die "[mock_dnstap] Failed to read START header\n";
my ($start_esc, $start_len) = unpack('NN', $hdr);
die "[mock_dnstap] Invalid START escape: $start_esc\n" if $start_esc != 0;
my $start_payload;
read_exact($client, \$start_payload, $start_len) or die "[mock_dnstap] Failed to read START payload\n";
my $start_type = unpack('N', substr($start_payload, 0, 4));
die "[mock_dnstap] Expected START type 2, got $start_type\n" if $start_type != 2;
print "[mock_dnstap] Handshake completed successfully. Receiving data frames...\n";

# Data loop
my $frame_count = 0;
my $client_sel = IO::Select->new($client);

while (1) {
    last if ($max_frames > 0 && $frame_count >= $max_frames);

    my @readable = $client_sel->can_read($timeout_sec);
    if (!@readable) {
        print "[mock_dnstap] Read timeout reached ($timeout_sec s), exiting data loop\n";
        last;
    }

    my $len_buf;
    my $r = $client->sysread($len_buf, 4);
    last if (!defined $r || $r == 0);
    if ($r != 4) {
        read_exact($client, \$len_buf, 4, $r) or last;
    }

    my $data_len = unpack('N', $len_buf);
    if ($data_len == 0) {
        # Control frame (e.g. STOP)
        my $ctrl_len_buf;
        read_exact($client, \$ctrl_len_buf, 4) or last;
        my $ctrl_len = unpack('N', $ctrl_len_buf);
        my $ctrl_buf;
        read_exact($client, \$ctrl_buf, $ctrl_len) or last;
        my $ctrl_type = unpack('N', $ctrl_buf);
        print "[mock_dnstap] Received control frame type $ctrl_type\n";
        if ($ctrl_type == 3) { # STOP
            # Send FINISH frame
            my $finish = pack('NNN', 0, 4, 5);
            $client->syswrite($finish);
            last;
        }
        next;
    }

    my $payload;
    read_exact($client, \$payload, $data_len) or last;
    $frame_count++;

    # Basic Protobuf decode
    my $info = decode_dnstap_pb($payload);
    my $mtype_str = ($info->{msg_type} == 1) ? 'AUTH_QUERY' :
                    ($info->{msg_type} == 2) ? 'AUTH_RESPONSE' : "TYPE_$info->{msg_type}";

    if ($output_file) {
        print "[mock_dnstap] Captured frame #$frame_count: type=$mtype_str (" . ($info->{wire_len} || 0) . " bytes)\n";
    }
    print $out_fh sprintf("[DNSTAP] Frame #%d: type=%s (%d), identity=%s, version=%s, wire_len=%d, client=%s\n",
                          $frame_count,
                          $mtype_str,
                          $info->{msg_type} || 0,
                          $info->{identity} || '',
                          $info->{version} || '',
                          $info->{wire_len} || 0,
                          $info->{client_addr} || '');
    $out_fh->flush();
}

close($client);
close($server);
unlink($socket_path) if -e $socket_path;
close($out_fh) if $output_file;
print "[mock_dnstap] Finished. Total frames captured: $frame_count\n";

sub read_exact {
    my ($sock, $buf_ref, $needed, $already) = @_;
    $already ||= 0;
    while ($already < $needed) {
        my $chunk;
        my $n = $sock->sysread($chunk, $needed - $already);
        return 0 unless (defined $n && $n > 0);
        if ($already == 0) {
            $$buf_ref = $chunk;
        } else {
            $$buf_ref .= $chunk;
        }
        $already += $n;
    }
    return 1;
}

sub decode_varint {
    my ($data, $offset) = @_;
    my $val = 0;
    my $shift = 0;
    my $len = length($data);
    while ($offset < $len) {
        my $b = ord(substr($data, $offset++, 1));
        $val |= (($b & 0x7F) << $shift);
        last unless ($b & 0x80);
        $shift += 7;
    }
    return ($val, $offset);
}

sub decode_dnstap_pb {
    my ($pb) = @_;
    my %info = (identity => '', version => '', msg_type => 0, wire_len => 0, client_addr => '');
    my $off = 0;
    my $len = length($pb);

    while ($off < $len) {
        my ($tag, $new_off) = decode_varint($pb, $off);
        last if ($new_off <= $off);
        $off = $new_off;
        my $field_num = $tag >> 3;
        my $wire_type = $tag & 0x07;

        if ($wire_type == 0) { # Varint
            my ($val, $noff) = decode_varint($pb, $off);
            $off = $noff;
        } elsif ($wire_type == 2) { # Length-delimited
            my ($flen, $noff) = decode_varint($pb, $off);
            $off = $noff;
            my $fdata = substr($pb, $off, $flen);
            $off += $flen;

            if ($field_num == 1) { # identity
                $info{identity} = $fdata;
            } elsif ($field_num == 2) { # version
                $info{version} = $fdata;
            } elsif ($field_num == 14) { # Message
                decode_message_pb($fdata, \%info);
            }
        } elsif ($wire_type == 5) { # 32-bit
            $off += 4;
        } elsif ($wire_type == 1) { # 64-bit
            $off += 8;
        } else {
            last;
        }
    }
    return \%info;
}

sub decode_message_pb {
    my ($pb, $info) = @_;
    my $off = 0;
    my $len = length($pb);

    while ($off < $len) {
        my ($tag, $new_off) = decode_varint($pb, $off);
        last if ($new_off <= $off);
        $off = $new_off;
        my $field_num = $tag >> 3;
        my $wire_type = $tag & 0x07;

        if ($wire_type == 0) { # Varint
            my ($val, $noff) = decode_varint($pb, $off);
            $off = $noff;
            if ($field_num == 1) { # Message.Type
                $info->{msg_type} = $val;
            }
        } elsif ($wire_type == 2) { # Length-delimited
            my ($flen, $noff) = decode_varint($pb, $off);
            $off = $noff;
            my $fdata = substr($pb, $off, $flen);
            $off += $flen;

            if ($field_num == 4) { # query_address
                if ($flen == 4) {
                    $info->{client_addr} = join('.', unpack('C4', $fdata));
                }
            } elsif ($field_num == 10 || $field_num == 14) { # query_message / response_message
                $info->{wire_len} = $flen;
            }
        } elsif ($wire_type == 5) { # 32-bit
            $off += 4;
        } elsif ($wire_type == 1) { # 64-bit
            $off += 8;
        } else {
            last;
        }
    }
}
