# Releasing rypt

Pushing a tag that starts with `v` runs
[.github/workflows/release.yml](../.github/workflows/release.yml). It runs
`make vet test race`, builds the six binaries with GoReleaser
([.goreleaser.yaml](../.goreleaser.yaml)), signs and notarizes the two macOS
binaries, and publishes a GitHub release with the binaries, `SHA256SUMS`, and a
changelog of the commits since the previous tag.

```sh
git tag -a v1.0.0 -m v1.0.0
git push origin v1.0.0
```

A tag with a pre-release suffix, such as `v1.1.0-rc.1`, is published as a
pre-release. `rypt version` prints the tag.

The release binaries are named and checksummed the same way as `make dist`
output: `rypt-linux-amd64`, `rypt-darwin-arm64`, `rypt-windows-amd64.exe`, and
so on.

[.github/workflows/ci.yml](../.github/workflows/ci.yml) runs the same tests on
every push to `main` and every pull request, and builds all six targets with
the release configuration, unsigned.

To build locally with the release configuration, unsigned, install
[GoReleaser](https://goreleaser.com/install/) v2 and run
`goreleaser release --snapshot --clean`. The binaries are in
`dist/rypt_<os>_<arch>*/`.

## macOS signing and notarization

GoReleaser signs the darwin binaries with a Developer ID Application
certificate and sends them to Apple's notary service. It does this on the
Linux runner, with [quill](https://github.com/anchore/quill), so no macOS
runner is needed. A bare binary cannot have its notarization ticket stapled to
it. macOS looks the ticket up online the first time the binary runs.

The release workflow needs five repository secrets. It stops before building
if any is missing, rather than publishing unsigned macOS binaries.

| Secret | Contents |
| --- | --- |
| `MACOS_SIGN_P12` | Base64 of a `.p12` holding the Developer ID Application certificate and its private key |
| `MACOS_SIGN_PASSWORD` | The password of that `.p12` |
| `MACOS_NOTARY_KEY` | Base64 of an App Store Connect API key (`AuthKey_<key ID>.p8`) |
| `MACOS_NOTARY_KEY_ID` | The ID of that key |
| `MACOS_NOTARY_ISSUER_ID` | The issuer ID shown above the list of API keys |

### The certificate

1. On a Mac, open Keychain Access and choose Keychain Access > Certificate
   Assistant > Request a Certificate From a Certificate Authority. Enter your
   email address, choose "Saved to disk", and save the `.certSigningRequest`
   file.
2. At [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/certificates/add),
   create a **Developer ID Application** certificate (not "Apple
   Development" or "Mac App Distribution") from that request, and download
   the `.cer` file. If the option is unavailable, your role in the developer
   team cannot create Developer ID certificates; ask the team's Account
   Holder.
3. Open the `.cer` file to add it to the login keychain. Under My
   Certificates, check that "Developer ID Application: *name* (*team ID*)"
   has a private key under it.
4. Select the certificate, choose File > Export Items, and save it as
   `Certificates.p12` with a strong password.

### The API key

1. In App Store Connect, open Users and Access > Integrations > App Store
   Connect API > Team Keys, and generate a key with the **Developer** role.
2. Download `AuthKey_<key ID>.p8`. Apple lets you download it only once.
3. Note the key ID and the issuer ID shown on the same page.

### Setting the secrets

With the [GitHub CLI](https://cli.github.com/), from a checkout of this
repository (`gh secret set` prompts for a value when nothing is piped in):

```sh
base64 < Certificates.p12 | tr -d '\n' | gh secret set MACOS_SIGN_P12
gh secret set MACOS_SIGN_PASSWORD
base64 < AuthKey_ABC123DEFG.p8 | tr -d '\n' | gh secret set MACOS_NOTARY_KEY
gh secret set MACOS_NOTARY_KEY_ID      # ABC123DEFG
gh secret set MACOS_NOTARY_ISSUER_ID   # a UUID
```

Or add them under Settings > Secrets and variables > Actions. Then delete the
local copies of `Certificates.p12` and the `.p8` file, or keep them somewhere
safe; the certificate stays in your login keychain.

The certificate is valid for five years. Signatures made while it was valid
stay valid after it expires, because each one carries a timestamp from Apple.
After renewing it, update `MACOS_SIGN_P12` and `MACOS_SIGN_PASSWORD`.

### When it fails

- Signing fails if the password is wrong or the `.p12` does not hold a
  certificate issued by Apple together with its private key. Nothing is
  published.
- If Apple rejects a binary, the release fails and nothing is published. A
  certificate of the wrong type, such as Apple Development, signs but is
  rejected here.
- GoReleaser waits up to 20 minutes for each binary. If Apple has not answered
  by then, GoReleaser logs `notarize timeout` and publishes the release
  anyway. The binary is signed, and becomes notarized when Apple finishes.
  Look for `notarized` in the log of the GoReleaser step for each darwin
  binary.

A failed release leaves the tag in place. If the fix was to the secrets,
re-run the failed job from the Actions tab. If it needs a new commit, move the
tag:

```sh
git push --delete origin v1.0.0
git tag -d v1.0.0
git tag -a v1.0.0 -m v1.0.0
git push origin v1.0.0
```

### Checking a signed binary

On a Mac, the first command should show `Authority=Developer ID Application:
...` and `flags=0x10000(runtime)`, and the second
`source=Notarized Developer ID`:

```sh
codesign -dv --verbose=4 rypt-darwin-arm64
spctl -a -vvv -t install rypt-darwin-arm64
```
