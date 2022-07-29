use strict;
use warnings;
use Test2::V0;

plan(2);

like(`openssl list -provider extra -providers`,
     qr/Providers:\n\s+extra\n\s+version:/,
     'check that the extra provider is listed');
