# Security policy

## Supported versions

Only the latest release on the default branch receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability.
Report it privately through GitHub's advisory form:

https://github.com/hellpuffyt/portwatch/security/advisories/new

Include the version or commit, a description of the issue, and steps or
input that reproduce it. You should receive an acknowledgement within a
few days; once a fix is available it will be released and credited in
the advisory unless you prefer otherwise.

## Scope

portwatch is often run as root. Relevant reports include anything that lets local, unprivileged input (socket tables, process names, `/proc` contents, a snapshot or history file) make it execute code, write outside the paths given by `--state`/`--log`, or misreport a listener. The Windows backend contains `unsafe` FFI calls into the IP Helper API; issues there are in scope.
