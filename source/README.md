# ds2stuffs

Private work-in-progress repository for Dark Souls II: Scholar of the First Sin (PC) seamless co-op tooling.

## Contents

- `mod/` — gameplay mod (`dinput8.dll`) derived from the upstream Seamless DS2 project, including the requested retro control-panel menu styling.
- `src/ds2net/proxy.cpp` — first-party Steam/proxy shim. Redirects the game's login traffic to a local ds3os server and loads the genuine Steam API DLL in production mode.
- `patches/ds3os-ds2-changes.patch` — DS2-specific changes to apply on top of upstream `TLeonardUK/ds3os`.
- `scripts/` — build helpers using paths relative to this repository.

## Current snapshot

Validated against `DarkSoulsII.exe` SHA-256 `A148B82F85D1CEA1749E627A9477A8B85BA787B8D5C888801F1326E6CD1BB2CF`.

- Full hook/patch audit against the decrypted runtime image; invalid, mid-instruction, and stale targets were removed or remapped to verified entries.
- Central game-module hook guard: only `.pdata` function entries, plus seven verified leaf stubs, may be hooked.
- Removed F7 rest toggle, "crossing keeps co-op" patch group, boss-kill outer NOP, and all diagnostic probe hooks.
- Kept the verified remaps for bonfire gates, player cap, door roles, sign predicates, and boss phase-two.
- Create Lobby / Connect / in-game GUI verified working in production proxy mode.
- Production mode: Steam running, genuine Steam API DLL, `steam_appid.txt` = `480`, shim in front.
- Validated gameplay DLL SHA-256: `CD46CEC63A0995899B98113D49519EA5C37656544EAFBC77D8C690616AA15F70`.

No game binaries, keys, logs, save data, or friend packs are included.

## Build

Gameplay mod (requires Visual Studio 2022 C++ build tools):

```powershell
cmake -S mod -B build/mod -G "Visual Studio 17 2022" -A x64
cmake --build build/mod --config Release --target ds2_seamless_coop
```

Shim (MinGW-w64):

```powershell
.\scripts\build-shim.ps1
```

Server: clone upstream `TLeonardUK/ds3os`, apply `patches/ds3os-ds2-changes.patch`, then build its `Server` target. The server needs its full `WebUI` directory present or socket binding silently fails.

## Attribution

See `THIRD_PARTY_NOTICES.md`. This project is not endorsed by FromSoftware, Valve, or the upstream authors.
