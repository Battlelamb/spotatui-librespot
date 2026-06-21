# spotatui's maintained librespot fork

This is a fork of [librespot-org/librespot](https://github.com/librespot-org/librespot),
maintained for [spotatui](https://github.com/LargeModGames/spotatui) because upstream is
slow to merge and release fixes (the `dev` branch had no commits between 2026-02-09 and at
least mid-2026, while Spotify keeps changing audio delivery).

## Branch `spotatui`

Based on the upstream **v0.8.0** tag plus the patches spotatui needs. spotatui pins this
branch via `[patch.crates-io]` in its `Cargo.toml`; its `Cargo.lock` pins the exact commit.

## Carried patches

- **CDN 530 fallback** (backport of upstream PR #1722, issue #1725): in
  `audio/src/fetch/mod.rs`, move the 206 check inside the CDN-URL retry loop so a non-206
  response falls through to the next URL instead of failing the track. Spotify serves HTTP
  530 from some CDN nodes while other URLs from the same `storage-resolve` work; without
  this, native playback is silent.

## Upstream status

- PR #1722: open, unmerged as of 2026-06-21.
- librespot `dev` branch: dormant since 2026-02-09.

## Maintenance

When upstream ships a release containing these fixes, drop the `[patch]` in spotatui and
bump the crates.io librespot version. Until then, rebase this branch onto each new librespot
release and update spotatui's pin.
