# Releasing rypt

A release is a pull request from `development` into `main` (see
[CONTRIBUTING.md](../CONTRIBUTING.md)). Once it is merged, tag the merge
commit on `main`:

```sh
git switch main && git pull
git tag -a v1.0.0 -m v1.0.0
git push origin v1.0.0
```

Pushing a tag that starts with `v` runs
[.github/workflows/release.yml](../.github/workflows/release.yml). It runs
`make vet test race`, builds the six binaries with GoReleaser
([.goreleaser.yaml](../.goreleaser.yaml)), signs and notarizes the two macOS
binaries, publishes a GitHub release with the binaries, `SHA256SUMS`, and a
changelog of the commits since the previous tag, and then updates the
Homebrew cask in [x6c-co/homebrew-tap](https://github.com/x6c-co/homebrew-tap).

A tag with a pre-release suffix, such as `v1.1.0-rc.1`, is published as a
pre-release and leaves the Homebrew cask alone. `rypt version` prints the tag.

The release binaries are named and checksummed the same way as `make dist`
output: `rypt-linux-amd64`, `rypt-darwin-arm64`, `rypt-windows-amd64.exe`, and
so on.

Each binary has a CycloneDX SBOM beside it, named like it
(`rypt-linux-amd64.cdx.json`), which GoReleaser makes with Syft from the
binary's own build information: the Go version and every module compiled in.
The SBOMs are listed in `SHA256SUMS` too. The release workflow builds with
the newest Go release, whatever go.mod's `go` line says, so that binaries
get the standard library's security fixes.

[.github/workflows/ci.yml](../.github/workflows/ci.yml) runs the same tests on
every push to `main` and `development` and every pull request, and builds all six targets with
the release configuration, unsigned.

To build locally with the release configuration, unsigned, install
[GoReleaser](https://goreleaser.com/install/) v2 and run
`goreleaser release --snapshot --clean`. The binaries are in
`dist/rypt_<os>_<arch>*/`.

## The Homebrew tap

GoReleaser writes `Casks/rypt.rb` in
[x6c-co/homebrew-tap](https://github.com/x6c-co/homebrew-tap), so that
`brew install --cask x6c-co/tap/rypt` installs rypt on macOS and Linux. The
cask links the binary as `rypt`. On macOS, Homebrew quarantines what a cask
downloads, and Gatekeeper accepts rypt because it is notarized.

The workflow's own token cannot push to another repository, so the release
needs a sixth secret, `HOMEBREW_TAP_TOKEN`: a fine-grained personal access
token.

1. At [Settings > Developer settings > Fine-grained tokens](https://github.com/settings/personal-access-tokens/new),
   create a token:
   - Resource owner: **x6c-co**.
   - Repository access: **Only select repositories**, `x6c-co/homebrew-tap`.
   - Permissions: **Contents: Read and write**.
   - Expiration: the organization allows at most 366 days. Set a date, and
     note it.

   If you aren't an owner of x6c-co, an owner must approve the token
   (Organization settings > Personal access tokens > Pending requests) before
   it can push.
2. Save it as a repository secret:

   ```sh
   gh secret set HOMEBREW_TAP_TOKEN -R x6c-co/rypt-cli
   ```

The token used by x6c-co/age-plugin-rypt works too, if you have its value.

GoReleaser updates the tap after it publishes the GitHub release, so the
workflow first checks, with a dry-run `git push`, that the token can push to
the tap. An expired or missing token stops the release before anything is
published. Replace the secret and re-run the failed job.

If the tap update fails anyway, after the release is published, re-running the
job does not help, because the release's files already exist. Edit
`Casks/rypt.rb` in the tap by hand instead: set `version`, and the four
`sha256` values from the release's `SHA256SUMS`.

## macOS signing and notarization

GoReleaser signs the darwin binaries with a Developer ID Application
certificate and sends them to Apple's notary service. It does this on the
Linux runner, with [quill](https://github.com/anchore/quill), so no macOS
runner is needed. A bare binary cannot have its notarization ticket stapled to
it. macOS looks the ticket up online the first time the binary runs.

Signing and notarizing need five repository secrets. The release workflow
stops before building if any is missing, rather than publishing unsigned macOS
binaries.

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
