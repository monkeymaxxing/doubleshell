# Contributing to doubleshell

Issues and pull requests are welcome.

## Reporting a bug or asking for a feature

Open an issue on GitHub. For a bug, include:

- the output of `doubleshell version`;
- your laptop's operating system and your server's Linux distribution;
- the wg-quick file with every key removed, and the `ProxyCommand` line from your SSH configuration;
- what you expected, and what happened, with the full error message.

For a feature, start with the problem: what you are trying to do, and how you
do it today.

## Reporting a security problem

Do not open an issue for a security problem: everyone can read issues. Report
the problem privately with **Report a vulnerability** on the repository's
**Security** tab on GitHub. Only the maintainers see the report and reply to it.

## A pull request is a proposal

We read a pull request as a proposal. Maintainers write every change that
lands, using their own tools. We do not merge outside code. doubleshell
carries your SSH connections, so the origin of every line is known.

When we use a proposal, the commit message credits its proposer:

```text
Proposed by @your-github-name in #123
```

We close the pull request with a link to that commit. A proposal we do not
use is closed with the reason.

A proposal is easiest to use when it changes one thing, says why, and includes
a test that fails without the change.

## Where the rules for changes live

[AGENTS.md](AGENTS.md) has the development commands and the rules for names
that users read. [docs/design.md](docs/design.md) explains how doubleshell
works, and [docs/acceptance.md](docs/acceptance.md) says what every change
must keep working.

## License

doubleshell is licensed under the [Apache License 2.0](LICENSE). Submissions in
an issue or a pull request are offered under the Apache License 2.0, as
section 5 of the license says.
