# securitytxt-tools

Tools related to [RFC 9116][1] (`/.well-known/security.txt`). I am
optimistically using the plural, even though only one tool has been released.

## RFC 9116 helper; security.txt formatter & PGP signer

#### [`securitytxt-signer.sh`](securitytxt-signer.sh)

This command line tool (Bash script) helps building RFC 9116 compliant, valid
& well formatted security.txt files as well as automating the PGP signing & 
expire date updating process.

**Usage:** `securitytxt-signer.sh input.txt [0xPGPKEY [output.txt]]`

The script removes any lines not matching the specification: only valid fields,
blank lines and comments are allowed. HTTPS URLs are fetched with `curl` and
non-working links are removed. Validation fails if valid mandatory fields are
missing.

The `Expires` field is updated to be 364 days in future (configurable) unless
the (optional) PGP key used for signing expires earlier; in that case the key
expiration date is used instead. The script does not test whether the same key
is used for signing and referenced in the `Encryption` fields. However, the
logic used for updating the `Expires` field assumes this (rather obvious) use
case.

The script can also be used to re-sign a security.txt file with an updated
`Expires` field as the validation removes the current signature.

**Requirements:**
 - GNU Bash
 - `curl` for HTTPS URL validation
 - `gpg` (GnuPG) for signing the security.txt
 - Standard commands `sed`, `awk`, `grep` & `date`.

[1]: https://www.rfc-editor.org/rfc/rfc9116
