# A fake `/proc` tree

`ProcSource::with_root` reads this instead of the real `/proc`, which is what
lets the Linux backend's *file plumbing* — not just its parsers — be exercised
by CI on Windows and macOS runners as well as on Linux.

One deliberate difference from a real `/proc`: the `fd` entries here are
regular files whose contents are the link target, because git cannot portably
store the symlinks a real kernel exposes. `ProcSource` falls back from
`read_link` to reading the file, so the same code path is under test.

Inodes are joined to `/proc/net/*`: 25142 and 25143 belong to pid 812
(systemd-resolve), 31980 belongs to pid 1103 (postgres). The sshd socket
(inode 22765) is deliberately left unattributed, which is what an unprivileged
run on a real machine looks like.
