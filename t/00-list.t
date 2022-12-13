use strict;
use warnings;
use Test2::V0;

plan(3);

like(`openssl list -provider extra -providers`,
     qr/Providers:\n\s+extra\n\s+version:/,
     'check that the extra provider is listed');
like(`openssl list -provider extra -kdf-algorithms`,
     qr/crypt \@ extra\n/,
     'check that crypt @ extra is listed');
like(`openssl list -provider extra -digest-algorithms`,
     qr/md6 \@ extra\n/,
     'check that md6 @ extra is listed');
