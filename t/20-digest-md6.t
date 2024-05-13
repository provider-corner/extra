# -*- perl -*-

# SPDX-FileCopyrightText: 2023-2024 "extra" provider collective
#
# SPDX-License-Identifier: LGPL-3.0-or-later

use strict;
use warnings;
use File::Temp qw(tempfile);
use Test2::V0;

# The cases are taken from "Sample MD6 calculations" in
# http://www.jayantkrish.com/papers/md6_report.pdf
my @cases = (
    # First example
    {
        message => 'abc',
        size => 256,
        rounds => 5,
        result => '8854c14dc284f840ed71ad7ba542855ce189633e48c797a55121a746be48cec8',
        enabled => 1,
    },
    # Second example (currently untested because our md6 implementation
    # doesn't support keyed hashes yet)
    {
        # Generate 600 chars by concatenating '11223344556677' multiple times
        message_length => 600,
        key => 'abcde12345',
        rounds => 5,
        size => 224,
        result => '894cf0598ad3288ed4bb5ac5df23eba0ac388a11b7ed2e3dd5ec5131',
        enabled => 0,
    },
    # Third example
    {
        # Generate 800 chars by concatenating '11223344556677' multiple times
        message_length => 800,
        size => 256,
        mode => 0,
        result => '4e78ab5ec8926a3db0dcfa09ed48de6c33a7399e70f01ebfc02abb52767594e2',
        enabled => 1,
    },
);

# Additional cases are things that are supposed to go wrong in diverse ways
# For these, the result is always checked against stderr, and may be a regexp
my @badcases = (
    # Invalid key size
    {
        message => 'abc',
        size => 7,
        result => qr/:invalid output size:/,
    },
);

plan(scalar(grep { $_->{enabled} } @cases) * 2 + scalar @badcases * 2);

sub generate_chars {
    my $num = shift;
    my $base = "\x11\x22\x33\x44\x55\x66\x77";
    my $chunks = int($num / length($base)) + 1;

    return substr($base x $chunks, 0, $num);
}

delete local $ENV{MD6_ROUNDS};
delete local $ENV{MD6_MODE};
foreach (@cases) {
    next unless $_->{enabled};

    local $ENV{MD6_ROUNDS} = $_->{rounds}   if exists $_->{rounds};
    local $ENV{MD6_MODE}   = $_->{mode}     if exists $_->{mode};
    local $ENV{MD6_DEBUG}  = 1;

    my $message = $_->{message} // generate_chars($_->{message_length});
    (my $fh, my $input) = tempfile();
    print $fh $message;
    close $fh;

    my $title =
        defined $_->{message}
        ? "check that dsgt('$message') becomes '$_->{result}'"
        : "check that dsgt(generated $_->{message_length} characters) becomes '$_->{result}'";

    is(`openssl dgst -provider extra -md6-$_->{size} < $input`,
       "md6-$_->{size}(stdin)= $_->{result}\n",
       $title." using md6-$_->{size}");

    local $ENV{MD6_BITS}   = $_->{size};

    is(`openssl dgst -provider extra -md6 < $input`,
       "md6(stdin)= $_->{result}\n",
       $title." using MD6_BITS=$_->{size}");

    unlink $input;
}

use IPC::Cmd qw(run);
foreach (@badcases) {
  SKIP:
    skip "Can't run IPC::Cmd::run()", 2
        unless ( IPC::Cmd->can_use_ipc_open3()
                 || IPC::Cmd->can_use_ipc_run() );

    local $ENV{MD6_BITS}   = $_->{size};

    my $message = $_->{message} // generate_chars($_->{message_length});
    (my $fh, my $input) = tempfile();
    print $fh $message;
    close $fh;

    my $title_run =
        defined $_->{message}
        ? "failing to run dsgt('$message') when"
        : "failing to run dsgt(generated $_->{message_length} characters) when";
    my $title_compare =
        "checking that the error message includes '$_->{result}'";

    local $ENV{MD6_BITS}   = $_->{size};

    my ($ok, $err, $full_buf, $stdout_buff, $stderr_buff)
        = run(command => "openssl dgst -provider extra -md6 < $input");
    print STDERR join("\n", @$stderr_buff);
    ok(!$ok, $title_run." using MD6_BITS=$_->{size}");
    unlink $input;

    skip "The run was bad (successful), so no need to compare", 1
        if $ok;

    like(join("\n", @$stderr_buff), $_->{result},
         $title_compare." using MD6_BITS=$_->{size}");
}
