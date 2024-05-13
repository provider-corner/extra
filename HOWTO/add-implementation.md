<!--
SPDX-FileCopyrightText: 2023-2024 "extra" provider collective

SPDX-License-Identifier: LGPL-3.0-or-later
-->

# HOWTO Add a new implementation

A new implementation of an algorithm should be fairly self contained,
and the changes in `extra.c` should be quite small as a result.

Whan adding a new implementation, it's recommended to do so in at
least three files.  In this list, `{algo}` works as a placeholder for
the name of the algorithm (main algorithm name if there are variants),
`{ALGO}` is the same name in upper case.

-   `{algo}.c`

    The main implementation should be located in this file.  Most of
    the contents can remain private, but if any `OSSL_DISPATCH` tables
    are produced, they should be made non-static.

-   `{algo}_data.h`

    A header file with data about `{algo}` that `extra.c` needs to
    know about.  This should contain:

    -   declarations of all the non-static `OSSL_DISPATCH` tables
        found in `{algo}.c`.
    -   definition of the macro `{ALGO}_ALGORITHMS` that expands
        to the `OSSL_ALGORITHM` table for `{algo}`.
    -   definition of the macro `{ALGO}_REASONS` that expands to the
        table of `OSSL_ITEM` with the error reasons, indexed by error
        code.

    It's *important* that the error codes used in `{ALGO}_REASONS`
    don't clash with any error code used in any other `*_data.h`.
    The recommended way to make this easy is to have a well defined
    base code to start from.  See the currently available `*_data.h`
    to get an idea.

-   `{algo}.md`

    The user documentation for using this implementation.  See
    existing such files to see what should be included.

## Changes in `extra.c`

`extra.c` should only need these minimal modifications:

-   Make sure to include `{algo}_data.h`
-   In the `OSSL_ITEM` table `reason_strings`, add a line with
    `{ALGO}_REASONS`.
-   In the appropriate `OSSL_ALGORITHM` table (thereis more than one),
    add a line with `{ALGO}_ALGORITHMS`.

NOTE: it's possible that there isn't a table yet for the appropriate
algorithm type.  In that case, you will have to add one, and add a
corresponding `case` statement in the function `extra_prov_operation()`.
