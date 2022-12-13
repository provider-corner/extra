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

plan(scalar(grep { $_->{enabled} } @cases));

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

    is(`cat $input | openssl dgst -provider extra -md6-$_->{size}`,
       "md6-$_->{size}(stdin)= $_->{result}\n",
       $title);
    unlink $input;
}
