# sshcfg-lint

Lint your OpenSSH client config (`~/.ssh/config`). In ssh_config the **first** value found for an option wins, so a `Host *` block placed above a specific host silently overrides it. sshcfg-lint finds that and other common mistakes. Stdlib only, Python 3.9+.

## Checks
- an option in a `Host x` block overridden by an earlier matching block (the classic `Host *` / `User` trap)
- duplicate `Host` patterns and options repeated within one block
- `IdentityFile`/`CertificateFile` that do not exist; private keys readable by others; config writable by others (ssh refuses these)
- `ProxyJump` loops or hops with no matching `Host`
- deprecated options (`UseRoaming`, `Protocol`, ...)

## Usage
```console
$ sshcfg-lint
/home/me/.ssh/config:7: warn: user 'deploy' for web is overridden by 'root' at line 2 (Host * (line 1)); first match wins
/home/me/.ssh/config:12: error: ~/.ssh/id_work is accessible by others (mode 0o644); ssh will refuse it
$ sshcfg-lint --strict other_config   # exit 1 on warnings too
```
Options: `--no-files` (skip disk checks), `--strict`. Exit code 1 on errors, 2 if the file is unreadable. Not checked: `Match` blocks and `Include`.

## Install
`pip install sshcfg-lint` (once published) or copy `sshcfg_lint.py`.

## Support
MIT licensed. If it saves you time: https://paypal.me/RafalBaranowski
