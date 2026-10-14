# spotatui's librespot fork

This is a fork of [librespot-org/librespot](https://github.com/librespot-org/librespot), maintained for [spotatui](https://github.com/LargeModGames/spotatui). spotatui depends on APIs that only this fork has (see the `Fork-only.` lines in [CHANGELOG.md](CHANGELOG.md)), and the fork lets a fix for a Spotify-side change ship in a spotatui release without waiting for an upstream release.

## Base

The `spotatui` branch is upstream `dev` plus the fork's own commits. Upstream is merged in regularly; to see how far it was last merged, run:

```bash
git remote add upstream https://github.com/librespot-org/librespot.git
git fetch upstream
git log -1 "$(git merge-base origin/spotatui upstream/dev)"
```

The upstream changes since that merge-base are not in the fork yet.

## Branches

- `spotatui`: the default branch. PRs target it, and the crates are published from it.
- Other branches are feature branches; merged ones can be deleted. `dev` is an old copy of upstream `dev` and is not used.

## Published crates

The seven library crates are on crates.io as `spotatui-librespot-{protocol, oauth, core, metadata, audio, playback, connect}`, all with the same version. spotatui pins the ones it uses with `=` and renames them, so its imports stay `librespot_*`:

```toml
librespot-core = { package = "spotatui-librespot-core", version = "=<version>" }
```

The root `librespot` binary crate and `librespot-discovery` are `publish = false`; spotatui does not use them.

## What the fork changes

Every change that exists only here has a line in `CHANGELOG.md` that ends with `Fork-only.`. A port of an upstream PR that upstream has not merged yet names that PR. When upstream merges an equal change, the fork line goes away in the next upstream merge.

## Release

1. CI is green on `spotatui`.
2. Set the same new version everywhere it appears: the `[package]` version of each of the seven crates, every `librespot-*` dependency line in the crate manifests (discovery included), and `[workspace.dependencies]` in the root `Cargo.toml`.
3. Commit, then publish from that committed tree, in dependency order. `cargo publish --workspace` cannot continue a run that stopped partway, so publish one crate at a time:

   ```bash
   for c in protocol oauth core metadata audio playback connect; do
     cargo publish -p "spotatui-librespot-$c" || break
   done
   ```

4. In spotatui, open a PR that sets the new version in every `=` pin of `Cargo.toml`, runs a cargo command so `Cargo.lock` updates, refreshes `desktop/Cargo.lock`, and is tested with a full `cargo run`.
