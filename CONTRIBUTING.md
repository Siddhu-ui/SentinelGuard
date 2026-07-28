# Contributing to SentinelGuard

Thanks for helping improve SentinelGuard.

## Local setup

Set up the backend and frontend using the commands in the [README](README.md). Never commit `.env`, upload data, SQLite databases, or any file submitted for analysis.

## Pull requests

1. Create a focused branch from the default branch.
2. Keep changes small and explain the security impact in the pull request.
3. Run the relevant checks before opening the pull request.
4. Do not add malware samples or other sensitive files to the repository.

## Security-sensitive changes

Changes to authentication, upload handling, file parsing, report generation, or dependency versions should include a brief description of the threat model and validation performed.
