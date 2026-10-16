# Contributing

## Branches

- `main` is what has been released. It changes only through pull requests,
  and every release is a tag on it.
- `development` collects the work for the next release.
- Work happens on a short-lived branch from `development`, named for what it
  does: `feature/...`, `fix/...`, `docs/...`, `ci/...`. Open a pull request
  into `development`, and delete the branch once it is merged.
- A release is a pull request from `development` into `main`, followed by a
  tag on `main`; see [docs/releasing.md](docs/releasing.md). If `main` then
  has commits `development` lacks, merge `main` back into `development`.
- An urgent fix branches from `main` as `hotfix/...`, merges into `main` and
  is released as a patch, and is then merged into `development`.

Both `main` and `development` are protected: a change needs a pull request
whose `test` and `build` checks pass, and nobody, admins included, can push
to them directly or force-push.

Keep commits focused, with messages in the imperative. Rebase a branch onto
`development` rather than merging `development` into it.

## Tests

See [Development](README.md#development) in the README.
