# spotatui's maintained librespot fork

This is a fork of [librespot-org/librespot](https://github.com/librespot-org/librespot),
maintained for [spotatui](https://github.com/LargeModGames/spotatui) because upstream is
slow to merge and release fixes (the `dev` branch had no commits between 2026-02-09 and at
least mid-2026, while Spotify keeps changing audio delivery).

## Published crates

The seven library crates are published on crates.io under fork names, versioned in
lockstep, starting at **0.8.1** (= upstream v0.8.0 + the patches below):

`spotatui-librespot-{core, connect, playback, audio, metadata, protocol, oauth}`

Consumers depend on them with Cargo's `package =` rename so imports stay `librespot_*`:

```toml
librespot-core = { package = "spotatui-librespot-core", version = "=0.8.1" }
```

The root `librespot` binary crate and `librespot-discovery` are `publish = false`;
spotatui does not use them.

## Branch `spotatui`

The publishing branch: upstream **v0.8.0** plus the patches spotatui needs.

## Carried patches

- **CDN 530 fallback** (backport of upstream PR #1722, issue #1725): in
  `audio/src/fetch/mod.rs`, move the 206 check inside the CDN-URL retry loop so a non-206
  response falls through to the next URL instead of failing the track. Spotify serves HTTP
  530 from some CDN nodes while other URLs from the same `storage-resolve` work; without
  this, native playback is silent.
- **Dealer reconnect / session-loss recovery** (port of upstream PR #1692): reconnect the
  dealer WebSocket and recover the session without interrupting playback.
- **OAuth callback listener hardening** (fork-only): keep the login callback listener
  alive through browser noise (empty lines, header blocks, connection reuse), handle one
  request per connection, and bound the deadline at the read layer so a captured code is
  never discarded.
- **Session disconnect reason** (fork-only API): `connect` reports why a session ended
  (external device handoff vs. unexpected loss vs. local stop) so spotatui can classify
  teardowns instead of inferring them. spotatui depends on this API; the fork cannot be
  swapped for upstream 0.8.
- **Previous on the first track restarts it** (fork-only, 0.8.2): upstream's
  `handle_prev` stops playback when there is no previous track, stranding the player in
  `Stopped` (which `handle_play` cannot leave). Spotify's own clients restart the first
  track; the fork does the same. spotatui #366.
- **Play status follows `PlayerEvent::Seeked`** (fork-only, 0.8.2): seeks issued directly
  on the `Player` (spotatui does this) now update spirc's play status, so its position and
  the previous-track 3-second rule stay accurate.
- **`Player::load` returns its play request id, Spirc keeps its own** (fork-only API,
  0.8.3): upstream Spirc learned its play request id from the `PlayRequestIdChanged`
  event, so it adopted every load an embedder sent straight to the `Player`. At that
  track's end it ran `handle_next` against a context it never loaded and stopped the
  player, silencing the embedder's next load (spotatui's native queue slot). Now `load`
  hands the id back and Spirc records only the loads it issues. spotatui ignores the
  return value but depends on the filter.

## Upstream status

- PR #1722: open, unmerged as of 2026-06-21.
- librespot `dev` branch: dormant since 2026-02-09.

## Maintenance

The fork is maintained standalone: cherry-pick what spotatui needs from upstream onto the
`spotatui` branch, bump all seven crate versions in lockstep, and republish with
`cargo publish --workspace` (order is resolved automatically; the dirty-tree check means
you publish from a committed tree). Then bump the `=`-pinned versions in spotatui's
`Cargo.toml`. Fork-only API additions (like the disconnect reason) mean upstream releases
can no longer be dropped in as-is.
