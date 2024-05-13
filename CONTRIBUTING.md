<!--
SPDX-FileCopyrightText: 2022-2024 "extra" provider collective

SPDX-License-Identifier: LGPL-3.0-or-later
-->

# Contributing code

When writing code for this project, have a look into the [HOWTO](HOWTO/)
directory and read the documents that are applicable for the work you want
to do.

To work on an item that you want to contribute, do so by forking this
repository (unless you have already done so), cloning the resulting
repository onto your computer, and creating a branch in that clone to do
your work in.  Using the excellent [github CLI](https://github.com/cli/cli),
these are the commands to do so:

    $ gh repo fork github.com/provider-corner/extra
    $ gh repo clone extra
    $ cd extra
    $ git checkout -b {your-branch}

Of course, it's just as viable to fork this repository using github.com's
web UI and to clone using the usual `git clone` command.

## License and attribution

If you're adding a new file, please add a copyright and license boilerplate
in the same SPDX style as in already existing files.  If you use the [REUSE]
tool, this is a simple command line to do this:

    $ reuse annotate --no-replace \
      --copyright='"extra" provider collective' \
      --license=LGPL-3.0-or-later \
      FILE

If you're modifying an existing file, please update the copyright year range
to include the current year.

If you want attribution, please consider adding your name in COLLECTIVE.md.

[REUSE]: https://reuse.software/

## Commits

### Commit messages should tell a story

Unless the change is small and obvious, the commit message for each commit
cannot be just a one liner.

Instead, tell the story behind the change in the commit, to help convince
the reviewer that this is a problem worth fixing and that you fix is a
viable, reasonable one.  This could include:

-   What are you trying to fix?  The problem you're trying to fix may not be
    obvious by the fix alone.
-   Why are you fixing it this way?  A problem may have multiple possible
    fixes, and your choice may be obvious by the fix alone.

### Solve a single problem per commit

If your story is becoming long, it may be a sign that your commit needs to
be split into several.  It's recommended to split them in logical changes.

Each commit should be justifiable on its own merit, making it easy to review
without having to keep a set of other commits in mind.  It's ok, however, if
one commit relies on changes made by a previous commit in the same pull
request.

## Sign your work - [DCO](https://developercertificate.org/)

To sign your work, a simple 'sign-off' procedure is used.

The sign-off is a simple line at the end of the commit message, which
certifies that you wrote the patch or otherwise have the right to pass it on
to this project.

If you can certify according to what's written on <https://developercertificate.org/>,
then you add a line saying, but using your name and email address:

    Signed-off-by: Random J Developer <dev@example.com>

If you're passing on someone else's work, their sign-off must be included as
well, before yours, thus forming a history that goes from oldest to newest
sign-off:

    Signed-off-by: Random Original Developer <origdev@example.com>
    Signed-off-by: Random J Developer <dev@example.com>

Many `git` commands have a `-s` / `--signoff` flag that does this for you,
such as `git commit`, `git revert`.

### Forgot to sign off?

If you forgot to sign off, you can do this:

    $ git commit --amend --signoff
    $ git push -f

If you need to do this with multiple commits, `git rebase` may help (where
`{starting-point}` is the current starting point for your PR's branch, in
your local clone):

    $ git rebase --signoff {starting-point}

## Pull requests

Contribute work by making pull requests.
Using the [github CLI](https://github.com/cli/cli), this is how you do that:

    $ gh pr create -B main

If you have only one commit in your branch, the PR title and description
will be exactly the same as the commit's subject and body.

If not, the default PR title becomes the branch name with dashes and other
"offending" characters removed, and the PR description becomes a list of
commit subject lines.  You may want to edit those in this case.

Of course, it's just as viable to push your branch to your fork, to submit
the PR for that branch using github.com's web UI.

## Reviews

Pull requests are subject to reviews, change requests and eventually,
approval.  They *must* be approved before they can be merged into the main
branch.

### Keep the set of commits clean

As you respond to change requests, please avoid commits with messages such
as "PR review updates"; they make it very difficult to see the progression
of changes.  Instead, you are *strongly encouraged* to use `git commit`'s
fixup commit features:

-   `git commit --fixup={commit-id}`
-   `git commit --fixup=amend:{commit-id}`
-   `git commit --fixup=reword:{commit-id}`

### Cleaning up the PR [optional]

If you feel safe doing so, you may rebase your PR to clean away fixup
commits, by integrating them into the commits that they fix up.  That's done
like this (where `{starting-point}` is the current starting point for your
PR's branch, in your local clone):

    $ git rebase --interactive --autosquash {starting-point}
    $ git push -f
