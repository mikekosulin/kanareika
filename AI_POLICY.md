# AI policy

Use any AI tool or model you like, or none. You don't have to say whether you used one or which. Kanareika itself
is developed with AI assistance, so the bar is the same for everyone: we judge the result, not the tool.

What we do ask is that a human stands behind every contribution. That human is you.

## Pull requests

- you understand every line you submit, and can explain and defend it in review without going back to the tool;
- you ran `make test` and `make lint` (or `make check`) locally, and tried the change yourself;
- one topic per PR: no drive-by rewrites, renames or reformatting the change doesn't need;
- the description says, in your own words, what changed, why, and how you tested it;
- answers to review comments come from you, not pasted from a chat;
- test data stays fake ([CONTRIBUTING.md](CONTRIBUTING.md#test-data-must-be-fake)), and real hosts, addresses and
  org files don't go into prompts of tools you don't control.

## Issues and discussions

Describe what you saw yourself: the command, the output, the version. Don't paste unverified AI output: a
generated analysis of a bug you haven't reproduced, invented flags or config keys, a summary of code nobody read.
If a tool's output helps, quote the relevant part and say what you checked.

## Security reports

Reports go through [SECURITY.md](SECURITY.md). A report must be reproduced against a real kanareika build (a
release or `make bin` from `main`), with the version, the exact steps or org file, and what you observed. "This
code looks like it could be vulnerable" is not a report. Speculative or hallucinated vulnerability reports take
hours to disprove; curl
[ended its bug bounty](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/) over them. We
close such reports without a detailed answer.

## What maintainers do with slop

Maintainers may close, without long discussion, a PR or issue that is low-effort, untested, unverified, or that
its author can't explain. One opened by an agent that no human reviewed first counts as unverified. That is not a
judgement of you; it is how a small team keeps time for real work. You are welcome to come back with a reworked
version.

Repeated slop after that falls under the [Code of Conduct](CODE_OF_CONDUCT.md) and may lead to a block from the
repository.
