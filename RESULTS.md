# Local Verification Results

Test date: October 27, 2026 (Asia/Bangkok)

## Summary

| Target | Version | Port | Result |
|---|---:|---:|---|
| `node2shell-vuln` | Node.js `v24.22.0` | `127.0.0.1:3000` | RCE and active command shell confirmed |
| `node2shell-fixed` | Node.js `v24.22.1` | `127.0.0.1:3002` | No activation or RCE in 32 attempts |

The direct vulnerable PoC executed the `/activate` ELF helper after two
attempts; the independent end-to-end `verify-lab.sh` run landed after 24
attempts. The helper was reached only through the ROP chain and returned a
random one-run token over the exploit socket. That token unlocked the
target-backed command console, which then produced the following proof:

```text
node@node2shell:/app$ whoami
node

node@node2shell:/app$ id
uid=1000(node) gid=1000(node) groups=1000(node)

node@node2shell:/app$ pwd
/app

node@node2shell:/app$ cd /tmp

node@node2shell:/tmp$ pwd
/tmp

node@node2shell:/tmp$ printf NODE2SHELL_ACTIVE_SHELL
NODE2SHELL_ACTIVE_SHELL
```

This confirms multiple target-side commands and working-directory state, not
just a one-shot output string. The client revoked the token when the session
ended, returning the vulnerable console to HTTP 403.

The patched control used the same trigger stream, write position, socket file
descriptor, `/activate` path, endpoint, and 32-attempt budget. It returned no
activation token, never unlocked the console, and exited with status `1`, which
is the expected negative-control result.

## Evidence

- `evidence/active-shell-vulnerable.txt`: successful RCE, token activation,
  multi-command shell output, and working-directory state.
- `evidence/active-shell-patched-control.txt`: identical 32-attempt payload
  against the patched runtime with no RCE.
- `evidence/shell-lock-state.txt`: console lock checks before exploitation and
  after token revocation.
- `evidence/runtime-verify.txt`: container state, loopback bindings, and Node
  versions.
- `evidence/labcheck-verify.txt`: process user, non-PIE binary, and live ASLR.

## Lab safety conditions

- Docker ports are published only on `127.0.0.1`.
- The PoC rejects non-loopback targets.
- Containers run as `uid=1000(node)`, not root.
- Kernel ASLR remains enabled (`randomize_va_space=2`), and the libc base was
  observed changing between worker lifetimes.
- The command console accepts a random token created by the exploited process,
  enforces a 4096-byte command limit and 10-second timeout, and revokes its
  token when the client exits.
- The patched image disables the console independently of token state.
- No reverse shell or outbound callback is used.
