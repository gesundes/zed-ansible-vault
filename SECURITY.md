# Security policy

Ansible Vault workflows handle passwords and decrypted material. Do not report a suspected secret
disclosure, arbitrary command execution, unsafe file replacement, checksum bypass, or prompt
spoofing in a public issue.

Use GitHub's private vulnerability reporting form:

[Open a private security advisory](https://github.com/gesundes/zed-ansible-vault/security/advisories/new).

Include the affected extension version, Zed version, operating system, `ansible-vault` version, and
minimal reproduction using synthetic secrets. Remove passwords, password-file contents, plaintext,
private Vault payloads, usernames, and identifying paths from all logs and attachments.

You should receive an acknowledgement within seven days. A fix will be prepared privately, tested
against the supported platform and Ansible matrix, and released as a new version. Existing release
assets are never replaced.

Security fixes are provided for the newest catalog release. Users should update through Zed's
extension registry rather than remaining on an older companion binary.
