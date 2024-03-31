# securitytxt-tools

Tools related to [RFC 9116][1] (`/.well-known/security.txt`). I am
optimistically using the plural, even though only one tool has been released.

![ShellCheck](https://github.com/oh2fih/securitytxt-tools/workflows/ShellCheck/badge.svg)

## RFC 9116 helper; security.txt formatter & PGP signer

### [`securitytxt-signer.sh`](securitytxt-signer.sh)

This command line tool (Bash script) helps building RFC 9116 compliant, valid
& well formatted security.txt files as well as automating the PGP signing &
expire date updating process.

Requires Bash >= 4.0. Compatible with both GNU coreutils & BSD `date`.

### Usage

```bash
securitytxt-signer.sh input.txt [0xPGPKEY [output.txt]]
```

The script removes any lines not matching the specification: only valid fields,
blank lines and comments are allowed. HTTPS URLs are fetched with `curl` and
non-working links are removed. Validation fails if valid mandatory fields are
missing.

The `Expires` field is updated to be 364 days in future (configurable) unless
the (optional) PGP key used for signing expires earlier; in that case the key
expiration date is used instead. The script also warns if the `Encryption`
fields are referensing a different key than the one used for signing.

The script can also be used to re-sign a security.txt file with an updated
`Expires` field as the validation removes the current signature.

### Requirements

- GNU Bash
- `curl` for HTTPS URL validation
- `gpg` (GnuPG) for signing the security.txt
- Standard commands `sed`, `awk`, `grep` & `date`.

### Rationale behind validation decisions

The script removes lines it does not support, but informs the user why the line
was removed. The errors and warnings should be read and the invalid lines should
be corrected before signing the results. Here are explanation on why the script
makes these decions. It is rather strict on purpose.

- Only allow empty lines, comment lines (beginning with `#`) and lines with
  fields from [2.5 Field Definitions][2] & IANA ["security.txt Fields"][3]
  registry. Remove everything else; including current PGP signatures.
- `Contact` field supports `mailto:`, `tel:` and `https:` URI schemes. While
  other URI schemes are allowed, supporting everything is not feasible.
  Therefore, the script support the URI schemes present in the examples.
  - If the mandatory `Contact` field is missing after the validation has
    removed invalid contents, the script will fail.
  - Email addresses without the `mailto:` URI scheme will be removed.
  - `mailto:` URI supports email addresses with `[[:alnum:]._%+-]+`
    local-parts and `[[:alnum:].-]+\.[[:alpha:].]{2,4}` domains.
  - `https:` URLs are fetched. The content is not inspected, but the site must
    answer without any HTTP errors. HTTP codes `200` and HTTP redirects are
    considered as valid responses; a redirect will give a warning.
  - `tel:` URIs ([RFC 3966][4]) must consist of numbers and `-` separators.
    A `+` for the country code is allowed at the beginning of the number.
    A common mistake is to use space as a separator, which is not allowed in
    [RFC 3966, 5.1.1][5]; space in the middle of the number are automatically
    replaced with `-`. Local numbers ([RFC 3966, 5.1.5][6]) using the
    `;phone-context=` syntax are not supported; please use global numbers.
- `Expires` is the other mandatory field. If the field is present it will be
   updated to either to be (configurable) `DAYS_MAX="364"` days in future or to
   the expiration date of the key used for PGP signing; which comes first. If
   the field is missing it will be added at the end of the security.txt file.
- Fields `Acknowledgments`, `Canonical`, `Hiring` & `Policy` are expected to be
   `https:` URLs are validated the same way HTTPs URLs in `Contact`.
- `Encryption` field supports `https:`, `openpgp4fpr:` and `dns:` URI schemes.
  - `https:` URLs are validated the same way HTTPs URLs in `Contact`, but the
    key is also fetched and its fingerprint is compared with the key used for
    PGP signing. If the fingerprints do not match it gives a warning.
  - `openpgp4fpr:` URIs must be exactly 40 hexadecimal characters or they will
    be removed. The fingerprint is compared to the fingerprint of the key used
    for PGP signing. If the fingerprints do not match it gives a warning.
  - `dns:` URIs must reference `OPENPGPKEY` records ([RFC 7929][7]): exactly 40
    hexadecimal characters followed by `._openpgpkey.`. The existence and the
    contents of this records are not currently tested. E.g.,
    `dns:50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccac._openpgpkey.example.com?type=OPENPGPKEY`
- `Preferred-Languages` must not appear more than once. The first valid field
  seen is used and the rest are removed. Valid field consists of comma
  separated list of language tags ([RFC 5646][8]), recognized as one to eight
  `a-z` characters with a possible subtag: `[a-z]{1,8}(-[a-z]{1,8})?`.

#### Line breaks

- Multiple consecutive blank lines are replaced with one.
- If the input file is missing a line break at EOF it will be added.
- For operational reasons, `CRLF` line breaks are replaced with `LF` line
  breaks. This is not required by the specification; [RFC 9116, 2.2][9] allows
  both.
  - The ABNF Grammar ([RFC 9116, 4][10]) suggests only CRLF would be allowed
    elsewhere whereas LF is an option in `cleartext` & `eol`. For consistency,
    the `CRLF` should either be mandatory or optional on the entire file, and
    only `CRLF` or `LF` should be used in a single file instead of mixing them.
  - Using `LF` is not an issue in the context of [RFC 4880][11] that
    canonicalizes the signed text documents by converting `LF` to `CRLF` before
    signing ([RFC 4880, 5.4.2][12]), and the receiving software should convert
    them to native line endings ([RFC 4880, 5.9][13]).
  - The [section 4][10] references MIME ([RFC 2046, 4.1.1][14]) & `Net-Unicode`
    ([RFC 5198, 2][15]) that have chosen the `CRLF` sequence as a MUST. As the
    intention of [section 2.2][9] is to treat line separators more liberally,
    I have reported [Errata ID 7743][16] to address this by locally redefining
    `CRLF` as `[CR] LF` in the ABNF Grammar.

[1]: https://www.rfc-editor.org/rfc/rfc9116
[2]: https://www.rfc-editor.org/rfc/rfc9116#section-2.5
[3]: https://www.iana.org/assignments/security-txt-fields/security-txt-fields.xhtml
[4]: https://www.rfc-editor.org/rfc/rfc3966
[5]: https://www.rfc-editor.org/rfc/rfc3966#section-5.1.1
[6]: https://www.rfc-editor.org/rfc/rfc3966#section-5.1.5
[7]: https://www.rfc-editor.org/rfc/rfc7929
[8]: https://www.rfc-editor.org/rfc/rfc5646
[9]: https://www.rfc-editor.org/rfc/rfc9116#section-2.2
[10]: https://www.rfc-editor.org/rfc/rfc9116#section-4
[11]: https://www.rfc-editor.org/rfc/rfc4880.html
[12]: https://www.rfc-editor.org/rfc/rfc4880.html#section-5.2.4
[13]: https://www.rfc-editor.org/rfc/rfc4880.html#section-5.9
[14]: https://www.rfc-editor.org/rfc/rfc2046#section-4.1.1
[15]: https://www.rfc-editor.org/rfc/rfc5198#section-2
[16]: https://www.rfc-editor.org/errata/eid7743
