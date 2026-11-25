DS2 Seamless Co-op - public test build

Validated game EXE SHA-256:
A148B82F85D1CEA1749E627A9477A8B85BA787B8D5C888801F1326E6CD1BB2CF

Gameplay DLL SHA-256:
CD46CEC63A0995899B98113D49519EA5C37656544EAFBC77D8C690616AA15F70

Install:
1. Copy every file in this folder next to DarkSoulsII.exe. Back up originals.
2. Run a ds3os server built from source/ with patches/ds3os-ds2-changes.patch applied.
   It must listen on 50031 and use the public key matching ds2net_rsa.pub.
3. Keep Steam running and logged in. steam_appid.txt must contain 480.
4. Launch DarkSoulsII.exe. Open the menu with F1.

Barely functional, requires steam open and initialized on all machines and a service to open ur ip if u dont wanna port forward

Files:
- dinput8.dll: gameplay mod
- ds2_seamless_coop.ini: tested settings
- ds2net.ini, steam_appid.txt, steam_api64.dll, steam_api64_org.dll, ds2net_rsa.pub: production proxy mode
- source/: full source, shim source, ds3os patch, and build scripts

Production proxy mode only. fake_steam is 0. Rebuilding requires VS 2022 C++ build tools; the shim requires MinGW-w64.
