# spotatui-librespot

[![crates.io](https://img.shields.io/crates/v/spotatui-librespot-core.svg?label=spotatui-librespot-core)](https://crates.io/crates/spotatui-librespot-core)
[![ci](https://github.com/LargeModGames/spotatui-librespot/actions/workflows/ci.yml/badge.svg?branch=spotatui)](https://github.com/LargeModGames/spotatui-librespot/actions/workflows/ci.yml)

The [librespot](https://github.com/librespot-org/librespot) fork that [spotatui](https://github.com/LargeModGames/spotatui) plays Spotify with: the Spotify session and login, Spotify Connect, audio playback, and the calls spotatui makes to Spotify.

## Why a fork

- **spotatui needs APIs that upstream does not have.** Examples: the reason a session ended, the play request id that `Player::load` returns, `SpClient` calls for the library, playlists, other Connect devices and Pathfinder search, and a session that reports a non-Premium account instead of exiting. Because of these, upstream librespot cannot replace this fork.
- **Spotify changes things.** When playback breaks, a fix can ship in a spotatui release the same week.

The fork follows upstream: it merges upstream `dev` regularly. The changes made only here are the lines that end with `Fork-only.` in the [changelog](../CHANGELOG.md); [SPOTATUI_FORK.md](../SPOTATUI_FORK.md) has the details.

## Use it

The seven library crates are on crates.io as `spotatui-librespot-*`, all with the same version. Rename them in `Cargo.toml` so your code keeps the `librespot_*` imports:

```toml
librespot-core = { package = "spotatui-librespot-core", version = "=0.8.5" }
```

The fork is built for spotatui. Other programs can use it, but its API changes whenever spotatui needs it to. Like librespot, it works only with Spotify Premium.

## Report a bug

- Something wrong in spotatui: report it on the [spotatui tracker](https://github.com/LargeModGames/spotatui/issues/new/choose), even when the cause may be here.
- A bug you know is in the library code: [open an issue here](https://github.com/LargeModGames/spotatui-librespot/issues/new/choose).
- A security problem: follow [spotatui's security policy](https://github.com/LargeModGames/spotatui/security/policy).

## Contribute

Read [CONTRIBUTING.md](CONTRIBUTING.md): the checks, the changelog rule, and how to test your change inside spotatui. A merged PR here counts as a spotatui contribution and puts you on [spotatui's contributor list](https://github.com/LargeModGames/spotatui#spotatui-contributors).

## Credits and license

All credit for librespot goes to its [authors and maintainers](https://github.com/librespot-org/librespot/graphs/contributors). The upstream README is [in the repository root](../README.md). MIT license, as upstream: see [LICENSE](../LICENSE).

This project is not affiliated with Spotify.
