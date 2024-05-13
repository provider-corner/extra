# -*- perl -*-

# SPDX-FileCopyrightText: 2023-2024 "extra" provider collective
#
# SPDX-License-Identifier: LGPL-3.0-or-later

use strict;
use warnings;
use Test2::V0;

plan(2);

my @cases = ( [ 'testing', 'ef', 'efGnQx2725bI2' ],
              [ 'bca76;23', 'yA', 'yA1Rp/1hZXIJk' ] );

foreach (@cases) {
    is(`openssl kdf -provider extra -keylen 13 -kdfopt pass:"$_->[0]" -kdfopt salt:"$_->[1]" -binary crypt`,
       $_->[2],
       "check that crypt('$_->[0]', '$_->[1]') becomes '$_->[2]'");
}
