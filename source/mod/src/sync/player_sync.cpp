// Player Synchronization - ACTUAL GAME MEMORY READS
//
// This file reads player position/health/state from the game's memory
// using the resolved GameManagerImp base pointer and verified offsets
// from the Bob Edition cheat table.
//
// Pointer chain: GameManagerImp -> +0x38 (PlayerData) -> offsets

#include "../../include/sync.h"
#include "../../include/mod.h"
#include "../../include/session.h"
#include "../../include/network.h"
#include "../../include/addresses.h"
#include "../../include/address_resolver.h"
#include "../../include/hooks.h"
#include "../../include/pattern_scanner.h"
#include "../../include/utils.h"
#include "../../include/ui_settings.h"
#include "../../include/ui.h"
#include <chrono>
#include <cfloat>
#include <atomic>
#include <intrin.h>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <climits>

using namespace DS2Coop::Sync;
using namespace DS2Coop::Utils;
using namespace DS2Coop::Addresses;

namespace DS2Coop::Sync {
// Flag groups loaded after the join, handed over once both players share the map (below).
void HandOverNewGroups(const std::map<uint32_t, std::vector<uint8_t>>& Current);
}

namespace {

// ============================================================================
// Dump the running, SteamStub-decrypted image of DarkSoulsII.exe to disk.
//
// The on-disk exe is encrypted, so a static disassembler sees noise where the
// code should be. Since this DLL already lives inside the process, it can just
// copy the mapped image after the stub has done its work.
//
// Section headers are rewritten so the file is laid out the way it sits in
// memory (PointerToRawData = VirtualAddress), which is what a disassembler
// expects from a dump. Pages that are not committed are written as zeroes
// instead of faulting.
//
// Triggered with HOME.
// ============================================================================
// ============================================================================
// Open the bonfire interaction gate.
//
// Found by decompiling the dumped, SteamStub-decrypted image in Ghidra:
// MapObjBonfireComponent's vftable slot 7 (exe+0x3F2500) is the predicate that
// decides whether the bonfire action may run.
//
//   exe+0x3F2550   E8 DB 4B DE FF   CALL  exe+0x1D7130   ; ~(bit2 of [rcx+0x50])
//   exe+0x3F2555   84 C0            TEST  AL, AL
//   exe+0x3EB737   75 D5            JNZ   -> refuse
//   exe+0x3F2559   ...              CALL  [RAX+0x48]     ; the action itself
//
// NOPing the two-byte JNZ makes that refusal unreachable while leaving the null
// checks above it intact. The helper at exe+0x1D7130 has three callers, so it is
// deliberately NOT stubbed — only this one branch is touched.
// ============================================================================
// ============================================================================
// Instrument the bonfire predicate instead of guessing at it.
//
// Both refusal branches inside exe+0x3F2500 are NOPed and the guest still can
// not sit down, so the refusal has to come from further up: either this
// predicate is never reached for a guest, or its caller decides on its own.
//
// Hooking it answers that directly. Every call logs the return address, so the
// caller chain can be walked upwards, and the return value shows whether the
// predicate itself says yes or no. Compare the log while standing at a bonfire
// as a guest against the same thing in your own world.
//
// Logging is throttled to one line per second per outcome — this runs inside
// the game's interaction polling and would otherwise flood the file.
// ============================================================================
using BonfireGateFn = uint64_t(__fastcall*)(void*, void*, void*, void*);
static BonfireGateFn g_origBonfireGate = nullptr;
static std::atomic<uint32_t> g_gateCallCount{ 0 };

uint64_t __fastcall BonfireGateHook(void* a1, void* a2, void* a3, void* a4) {
    void* Caller = _ReturnAddress();
    const uint64_t Result = g_origBonfireGate(a1, a2, a3, a4);

    const uint32_t Count = g_gateCallCount.fetch_add(1) + 1;
    static ULONGLONG s_lastLog = 0;
    const ULONGLONG Now = GetTickCount64();
    if (Now - s_lastLog >= 1000) {
        s_lastLog = Now;
        const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
        LOG_INFO("[GATE] exe+0x3F2500 call #%u from exe+0x%llX -> %llu",
                 Count,
                 (unsigned long long)(reinterpret_cast<uintptr_t>(Caller) - ExeBase),
                 (unsigned long long)Result);
    }
    return Result;
}

// A guest's own sign, touched while it waits to be summoned.
//
// The sign goes down where the host stands, and when both players stand on the
// same spot of their own worlds that is under the guest's own feet. The game
// then offers the guest "summon" on it, and going through with it withdraws the
// sign: exe+0x20D010 takes the id and a second later RequestRemoveSign goes out,
// so the host has nothing left to summon. 17.09, 00:29-00:31, three joins in a
// row ended that way. This player's own sign carries 0x6 in the top nibble of
// its id (0x60000001, 0x60000011, 0x60000021 as they were put down); signs from
// other players carry 0x8 (0x80000011 for the joiner's sign at the host).
// Answering 0 is the path exe+0x20D010 takes itself for a sign it does not know.
//
// 0x6 is only known from this player's own signs; whether other local signs (an
// NPC's) share it is not. So the refusal holds only while a sign of this
// player's is fresh -- five minutes after the last RequestCreateSign, which is
// how long a join waits -- and any sign is touchable again after that.
constexpr ULONGLONG kOwnSignFreshMs = 5 * 60 * 1000;

bool RefuseOwnSignTouch(void* IdPtr) {
    auto& Lobby = DS2Coop::Session::SessionManager::GetInstance();
    if (!Lobby.IsActive() || Lobby.IsHost() || !IdPtr) return false;
    const ULONGLONG Now = GetTickCount64();
    const ULONGLONG Placed = DS2Coop::Hooks::GetLastSignCreateTime();
    if (!Placed || Now - Placed > kOwnSignFreshMs) return false;
    uint32_t Id = 0;
    if (!Memory::Read<uint32_t>(reinterpret_cast<uintptr_t>(IdPtr), &Id) || (Id >> 28) != 0x6) return false;

    static std::atomic<ULONGLONG> LastToast{ 0 };
    if (Now - LastToast.load() > 5000) {
        LastToast.store(Now);
        DS2Coop::UI::Overlay::GetInstance().ShowNotification(
            DS2Coop::UI::Tr("That is your own sign -- the host summons you, nothing to press.",
                            "Это твой знак \xE2\x80\x94 хост призовёт тебя сам, нажимать ничего не нужно."),
            5.0f, DS2Coop::UI::NotifyKind::Info);
    }
    LOG_INFO("[SUMMON] own sign 0x%08X touched as a guest -- left alone, the host summons it", Id);
    return true;
}

// The bonfire refused while the players are set to fight each other: the game only says "cannot use
// this bonfire", which tells nobody why (21.09, point 6).
void TellAboutPvpBonfire() {
    if (DS2Coop::Sync::GetDamageMode() != 2 || !DS2Coop::Session::SessionManager::GetInstance().IsActive()) return;
    static std::atomic<ULONGLONG> s_last{ 0 };
    const ULONGLONG Now = GetTickCount64();
    if (Now - s_last.load() < 8000) return;
    s_last.store(Now);
    DS2Coop::UI::Overlay::GetInstance().ShowNotification(
        DS2Coop::UI::Tr("A bonfire takes nobody while you are set to fight each other -- turn PvP off in the menu.",
                        "К костру не сесть, пока стоит режим PvP — выключи его в меню мода."),
        6.0f, DS2Coop::UI::NotifyKind::Warning);
    LOG_INFO("[PVP] the bonfire said no while the damage mode is PvP -- told the player to turn it off");
}

using GameFn4 = uint64_t(__fastcall*)(void*, void*, void*, void*);
using SummonByIdFn = uint8_t(__fastcall*)(void*, void*);

static SummonByIdFn g_origSummonById = nullptr;
static GameFn4 g_origBonfireActivate = nullptr;

uint8_t __fastcall SummonByIdHook(void* Manager, void* IdPtr) {
    if (RefuseOwnSignTouch(IdPtr)) return 0;
    return g_origSummonById(Manager, IdPtr);
}

uint64_t __fastcall BonfireActivateHook(void* a1, void* a2, void* a3, void* a4) {
    const uint64_t Result = g_origBonfireActivate(a1, a2, a3, a4);
    NoteLocalRestForPose();
    if ((Result & 0xFF) == 0) TellAboutPvpBonfire();
    return Result;
}

using MpActiveFn = uint64_t(__fastcall*)(void*);
static MpActiveFn g_origMpActive = nullptr;

static bool IsGuestInHostWorld();   // below, with the IsHost detour

uint64_t __fastcall MpActiveHook(void* Session) {
    const uintptr_t Caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
    if (DS2Coop::Sync::IsTalkOpenNearby() && DS2Coop::Session::SessionManager::GetInstance().IsActive()) {
        static std::atomic<uint32_t> s_told{ 0 };
        static std::atomic<uintptr_t> s_sites[16] = {};
        bool Known = false;
        for (const std::atomic<uintptr_t>& Site : s_sites) Known = Known || Site.load() == Caller;
        if (!Known) {
            const uint32_t N = s_told.fetch_add(1);
            if (N < 16) {
                s_sites[N].store(Caller);
                LOG_INFO("[GATES] a talk asked whether this is someone else's world (from exe+0x%llX) -- "
                         "answered no while talking",
                         static_cast<unsigned long long>(Caller - reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr))));
            }
        }
        return 0;
    }
    return g_origMpActive(Session);
}

// Event flags — the thing that actually decides whether a fog gate is there.
//
// A guest sees fog at bosses the host already killed, sees emptied chests and no
// items: their client renders the world from THEIR OWN event flags, never the
// host's. So sharing progress, loot and boss state all come down to reading and
// writing these flags. The game even has a NetP2pPacketEventFlag class, so it
// already ships flags between players — just very few of them.
//
// EventFlagManager (vftable exe+0x10EFF58) holds a buffer pointer at +0x120; the
// constructor at exe+0x474150 zeroes 0xF8 bytes from +0x20. Find the instance by
// scanning for its vftable, then dump the object so the real layout can be read
// off live memory rather than guessed.
//
// F4 snapshots; pressing it again diffs against the previous snapshot and logs
// which bits changed — do something in between (open a door, kill something) and
// the flag for that event falls out of the diff.
// Layout, read straight off the game's own getter (exe+0x474220) and setter
// (exe+0x47500D):
//
//   manager   = [[global+0x70]+0x20]
//   buckets   = manager+0x20, 31 entries, index = ((id/10000) * 0x89) % 0x1F
//   node      = { +0x00 data, +0x08 size, +0x0C groupId, +0x10 next }
//   bit       = data[(id%10000)/8] & (1 << (7 - (id%10000 & 7)))   // MSB first
//
// The setter also notifies listeners when a bit actually changes, which is what
// makes the world react immediately — fog appearing or vanishing on the spot.
using GetFlagFn = bool(__fastcall*)(void*, uint32_t);
using SetFlagFn = bool(__fastcall*)(void*, uint32_t, char);

uintptr_t g_flagMgr = 0;
uint32_t  g_lastFlagId = 0;
std::map<uint32_t, std::vector<uint8_t>> g_flagSnapshot;

uintptr_t GetFlagManager() {
    const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    uintptr_t g = 0, s70 = 0, mgr = 0;
    if (Memory::Read<uintptr_t>(ExeBase + 0x16148F0, &g) && g &&
        Memory::Read<uintptr_t>(g + 0x70, &s70) && s70) {
        Memory::Read<uintptr_t>(s70 + 0x20, &mgr);
    }
    return mgr;
}

bool ReadFlag(uint32_t Id) {
    const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    uintptr_t Mgr = GetFlagManager();
    if (!Mgr) return false;
    auto Fn = reinterpret_cast<GetFlagFn>(ExeBase + 0x474220);
    return Fn(reinterpret_cast<void*>(Mgr), Id);
}

bool WriteFlag(uint32_t Id, bool Value) {
    const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    uintptr_t Mgr = GetFlagManager();
    if (!Mgr) {
        LOG_INFO("[FLAGS] manager not available");
        return false;
    }
    auto Fn = reinterpret_cast<SetFlagFn>(ExeBase + 0x47500D);
    const bool Changed = Fn(reinterpret_cast<void*>(Mgr), Id, Value ? 1 : 0);
    LOG_INFO("[FLAGS] flag %u -> %d (%s)", Id, Value ? 1 : 0, Changed ? "changed" : "already that value");
    return Changed;
}

// The same write without a line in the log: handing over a whole save's worth of
// progress is thousands of flags, and one line each would drown everything else.
bool WriteFlagQuiet(uint32_t Id, bool Value) {
    const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    const uintptr_t Mgr = GetFlagManager();
    if (!Mgr) return false;
    auto Fn = reinterpret_cast<SetFlagFn>(ExeBase + 0x47500D);
    return Fn(reinterpret_cast<void*>(Mgr), Id, Value ? 1 : 0) != 0;
}

// Copy every group's bit array out of the hash table.
std::map<uint32_t, std::vector<uint8_t>> CaptureFlags() {
    std::map<uint32_t, std::vector<uint8_t>> Out;
    const uintptr_t Mgr = GetFlagManager();
    if (!Mgr) return Out;

    for (int bucket = 0; bucket < 31; bucket++) {
        uintptr_t Node = 0;
        if (!Memory::Read<uintptr_t>(Mgr + 0x20 + bucket * 8, &Node)) continue;

        for (int guard = 0; Node && guard < 64; guard++) {
            uintptr_t Data = 0;
            uint32_t Size = 0, Group = 0;
            Memory::Read<uintptr_t>(Node, &Data);
            Memory::Read<uint32_t>(Node + 0x8, &Size);
            Memory::Read<uint32_t>(Node + 0xC, &Group);

            if (Data && Size && Size < 0x8000) {
                std::vector<uint8_t> Bits(Size);
                bool ok = true;
                for (uint32_t i = 0; i < Size && ok; i++) ok = Memory::Read<uint8_t>(Data + i, &Bits[i]);
                if (ok) Out[Group] = std::move(Bits);
            }

            uintptr_t Next = 0;
            if (!Memory::Read<uintptr_t>(Node + 0x10, &Next)) break;
            Node = Next;
        }
    }
    return Out;
}

void SnapshotFlags() {
    auto Now = CaptureFlags();
    if (Now.empty()) {
        LOG_INFO("[FLAGS] no flag groups readable (manager=0x%llX)", (unsigned long long)GetFlagManager());
        return;
    }

    if (g_flagSnapshot.empty()) {
        size_t bytes = 0;
        for (auto& g : Now) bytes += g.second.size();
        g_flagSnapshot = std::move(Now);
        LOG_INFO("[FLAGS] baseline: %zu groups, %zu bytes. Do something, then press F4 again.",
                 g_flagSnapshot.size(), bytes);
        return;
    }

    char line[700];
    int used = snprintf(line, sizeof(line), "changed flags:");
    int changes = 0;
    for (auto& g : Now) {
        auto it = g_flagSnapshot.find(g.first);
        if (it == g_flagSnapshot.end() || it->second.size() != g.second.size()) continue;
        for (size_t i = 0; i < g.second.size(); i++) {
            uint8_t d = it->second[i] ^ g.second[i];
            if (!d) continue;
            for (int bit = 0; bit < 8; bit++) {
                if (!(d & (1 << bit))) continue;
                const uint32_t id = g.first * 10000 + (uint32_t)i * 8 + (7 - bit);
                changes++;
                g_lastFlagId = id;
                if (used < (int)sizeof(line) - 24) {
                    used += snprintf(line + used, sizeof(line) - used, " %u=%d",
                                     id, (g.second[i] & (1 << bit)) ? 1 : 0);
                }
            }
        }
    }
    g_flagSnapshot = std::move(Now);
    LOG_INFO("[FLAGS] %d flag(s) changed. %s", changes, changes ? line : "(none)");
    if (changes) LOG_INFO("[FLAGS] F5 toggles the last one (%u)", g_lastFlagId);
}

// ---------------------------------------------------------------------------
// Event flag synchronisation.
//
// Event flags are what makes two players disagree about the world. The check a
// world item goes through, exe+0x4517D0, reads straight out of the flag table
// (it calls the same getter at exe+0x474220 this file already uses), and fog
// gates, bosses and the bonfire travel list all read from there too. So "the
// guest cannot see that item", "fog is still up on a boss the host killed" and
// "the travel list shows my bonfires, not his" are one problem with one fix.
//
// The engine is a diff: capture every group's bits once a second, compare with
// the previous capture, and send what changed. A flag arriving from a peer is
// written into the local table and folded into the baseline in the same breath,
// so it is not sent straight back — without that the two clients would echo
// each other forever.
//
// This writes into the receiving player's own game state, and that state is
// saved. Asked for on 12.09 with that said plainly, so it is on by default now:
//
//   flag_sync=on    changes are broadcast, and flags from peers are applied
//   flag_sync=off   nothing happens
//
// The whole table is written to ds2_flags_backup.bin before the first thing is
// ever applied, so a save that comes out wrong can be compared against what it
// held. "log" is still accepted and means on: it was the old default, and
// leaving it meaning "watch only" would have left both players editing an ini by
// hand for the feature they asked for.
// ---------------------------------------------------------------------------
enum class FlagSyncMode { Off, Log, On };
std::atomic<int> g_flagSyncMode{ static_cast<int>(FlagSyncMode::On) };

std::mutex                          g_flagSyncMutex;
std::map<uint32_t, std::vector<uint8_t>> g_flagBaseline;
// Flags that arrived from the other player, waiting to be written.
//
// They are NOT written where they arrive: that is the network thread, and
// calling one of the game's own functions off the game's thread is what crashed
// an earlier attempt at replaying a bonfire rest. The tick below drains this on
// the game thread instead.
std::vector<std::pair<uint32_t, bool>> g_pendingRemoteFlags;
ULONGLONG                           g_flagLastTick = 0;
bool                                g_flagBackedUp = false;

// A guest's own world after a stay in the host's (18.09, point 1: both characters were made at the
// crones' in the host's world, and at home the crones asked the guest for its name again -- and the
// name would not take). While a guest is in the host's world its flag table is the host's copy:
// what happens there, the character creation among it, is gone once the guest's own table comes
// back. The last settled table seen in the host's world is kept, and once the guest's own table has
// settled at home every bit set there and missing here is set here too -- what the host hands a
// joining guest anyway, only at the moment it matters (ini flags_carry_home).
std::atomic<bool>                        g_carryHomeOn{ true };
std::map<uint32_t, std::vector<uint8_t>> g_hostWorldFlags;
bool                                     g_carryHomePending = false;

// Flags of this player's own that the partner is not told about (KeepFlagLocal).
std::mutex                                   g_localFlagsMutex;
std::vector<std::pair<uint32_t, bool>>       g_localFlags;

// ...and the same flags kept for the whole run, to put back on every arrival in the host's world
// (21.09 morning, checklist 4: "go into my friend's world again and I have to skip my own lines a
// second time"). While a guest is in the host's world its flag table is the host's copy, so a talk
// finished there is written in that copy; flags_carry_home brings it to this player's own table when
// it goes home, and the next arrival starts from the host's copy again, which has none of it. Only
// the ones this player's own talk scripts wrote, only those that are set, and always folded back into
// the diff baseline so the partner is not told: its own NPCs are its own (§3.44).
std::mutex               g_myTalkMutex;
std::map<uint32_t, bool> g_myTalkFlags;

// Fold a value into the baseline so the next diff does not report it as ours.
void AbsorbIntoBaseline(uint32_t Id, bool Value) {
    const uint32_t Group = Id / 10000;
    const uint32_t Index = Id % 10000;
    auto it = g_flagBaseline.find(Group);
    if (it == g_flagBaseline.end()) return;
    const size_t Byte = Index / 8;
    if (Byte >= it->second.size()) return;
    const uint8_t Mask = static_cast<uint8_t>(1 << (7 - (Index & 7)));
    if (Value) it->second[Byte] |= Mask;
    else       it->second[Byte] &= static_cast<uint8_t>(~Mask);
}

// Write the whole table to a file, once, before anything is ever applied.
void BackupFlagsOnce(const std::map<uint32_t, std::vector<uint8_t>>& Flags) {
    if (g_flagBackedUp) return;
    g_flagBackedUp = true;

    FILE* f = nullptr;
    if (fopen_s(&f, "ds2_flags_backup.bin", "wb") != 0 || !f) {
        LOG_WARNING("[FLAGS] could not write ds2_flags_backup.bin");
        return;
    }
    size_t bytes = 0;
    for (const auto& g : Flags) {
        const uint32_t Group = g.first;
        const uint32_t Size = static_cast<uint32_t>(g.second.size());
        fwrite(&Group, sizeof(Group), 1, f);
        fwrite(&Size, sizeof(Size), 1, f);
        fwrite(g.second.data(), 1, Size, f);
        bytes += Size;
    }
    fclose(f);
    LOG_INFO("[FLAGS] backup written: ds2_flags_backup.bin (%zu groups, %zu bytes)", Flags.size(), bytes);
}

// Once per connection, the host hands the guest everything it has already done.
//
// The diff below only ever reports what changes while both players are
// connected, so a guest that joins after the host has lit five bonfires, opened
// three fog gates and killed a boss hears about none of it -- which is exactly
// what the 12.09 session looked like. Host to guest only: this dumps a whole
// save's worth of flags, and giving the host's world to the guest is what was
// asked for.
void MaybeHandOverProgress() {
    static size_t s_handedOverFor = 0;

    auto& Lobby = DS2Coop::Session::SessionManager::GetInstance();
    const size_t Peers = DS2Coop::Network::PeerManager::GetInstance().GetPeers().size();
    if (!Lobby.IsActive() || !Lobby.IsHost() || Peers == 0) {
        if (Peers == 0) s_handedOverFor = 0;   // a later session hands over again
        return;
    }
    if (Peers <= s_handedOverFor) return;

    bool HaveTable;
    {
        std::lock_guard<std::mutex> Lock(g_flagSyncMutex);
        HaveTable = !g_flagBaseline.empty();
    }
    if (!HaveTable) return;                    // the flag table is not up yet

    s_handedOverFor = Peers;
    SendFlagCatchUp();
}

void SendFlagToPeers(uint32_t Id, bool Value) {
    DS2Coop::Network::EventFlagPacket Packet{};
    Packet.header.magic = 0x44533243;
    Packet.header.type = DS2Coop::Network::PacketType::EventFlag;
    Packet.header.size = sizeof(Packet);
    Packet.header.timestamp = GetTickCount64();
    Packet.flagId = Id;
    Packet.flagValue = Value;
    DS2Coop::Network::PeerManager::GetInstance().BroadcastPacket(&Packet.header);
}

// One pass: capture, diff against the baseline, report and (in "on") send.
//
// Two things make a naive diff unusable, both seen in a real session:
//
//   * The flag table is rebuilt on a world transition. Caught mid-swap it reads
//     as all zeros, and the next tick reads it back — logged as twelve flags
//     turning off and the same twelve turning on a second later, at exactly the
//     moments RequestRemoveSign and EnableSummoning ran. Nothing changed in
//     either world. So a capture that looks like a rebuild is thrown away and
//     the baseline is retaken instead of reported.
//
//   * Clearing a flag on the other player's machine is the one move that can
//     destroy their progress — a spurious 1->0 would un-open a door or
//     un-collect an item in their save. Flags essentially only ever turn on
//     during play, so only that direction is sent, and only that direction is
//     accepted. A transient can then cost nothing worse than a flag that fails
//     to propagate.
// The join controller's state (7 in the host's world), -1 with none.
static int ReadJoinCtrlState() {
    const uintptr_t ExeB = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    uintptr_t Net = 0, Mp = 0, Ctrl = 0, Vtbl = 0;
    int State = -1;
    if (Memory::Read<uintptr_t>(ExeB + 0x1616CF8, &Net) && Net &&
        Memory::Read<uintptr_t>(Net + 0x18, &Mp) && Mp &&
        Memory::Read<uintptr_t>(Mp + 0x40, &Ctrl) && Ctrl &&
        Memory::Read<uintptr_t>(Ctrl, &Vtbl) && Vtbl == ExeB + 0x10D7BD8) {
        Memory::Read<int>(Ctrl + 0xF8, &State);
    }
    return State;
}

// While the game swaps whole flag tables -- a guest taking on the host's flags
// as it joins (the snapshot, join state 4), and getting its own back when it
// leaves -- the difference between the two tables is not anybody's progress.
// On 16.09 evening a guest's own flag 105415 went out as "0->1" when it got home
// and was written into the host's save (20:50:12, "1 changed something here").
// So nothing is sent while joining, while leaving, while loading, and for five
// seconds after: the baseline is simply retaken.
static bool FlagTablesSettling(ULONGLONG Now) {
    static ULONGLONG s_quietUntil = 0;
    static int s_lastWorld = -2;
    const int Join = ReadJoinCtrlState();
    const uintptr_t ExeB = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    uintptr_t Gm = 0, Player = 0;
    const bool Loaded = Memory::Read<uintptr_t>(ExeB + 0x16148F0, &Gm) && Gm &&
                        Memory::Read<uintptr_t>(Gm + 0xD0, &Player) && Player;
    const int World = Join == 7 ? 1 : 0;
    const bool Moving = (Join >= 0 && Join != 7) || !Loaded;
    if (Moving || World != s_lastWorld) {
        if (World != s_lastWorld && s_lastWorld != -2) {
            LOG_INFO("[FLAGSYNC] %s -- flag tables are being swapped, nothing is sent until they settle",
                     World ? "in the host's world" : "out of the host's world");
        }
        s_lastWorld = World;
        s_quietUntil = Now + 5000;
    }
    return Now < s_quietUntil;
}

// A character's own making at the crones' (m10_02 event 16000): the dialogue flags, "made" (102000015)
// and the two written at its end. Carried home only by a character that has a name -- one that never made
// itself in the host's world must still be offered the making at home.
bool CharacterMakingFlag(uint32_t Id) {
    return (Id >= 102000010 && Id <= 102000015) || Id == 105501 || Id == 106100;
}

// Every bit set in the host world's last settled table and clear in Current, written into this player's
// table (at most Limit of them). Caller holds g_flagSyncMutex.
size_t CarryHomeLocked(std::map<uint32_t, std::vector<uint8_t>>* Current, size_t Limit, size_t* Missing,
                       size_t* Groups) {
    const bool Made = !PlayerSync::GetInstance().GetOwnCharacterName().empty();
    size_t Written = 0;
    for (const auto& G : g_hostWorldFlags) {
        auto Home = Current->find(G.first);
        if (Home == Current->end() || Home->second.size() != G.second.size()) continue;
        ++*Groups;
        for (size_t I = 0; I < G.second.size(); ++I) {
            const uint8_t Absent = static_cast<uint8_t>(G.second[I] & ~Home->second[I]);
            if (!Absent) continue;
            for (int Bit = 0; Bit < 8; ++Bit) {
                if (!(Absent & (1 << Bit))) continue;
                const uint32_t Id = G.first * 10000 + static_cast<uint32_t>(I) * 8 + (7 - Bit);
                if (!Made && CharacterMakingFlag(Id)) continue;
                ++*Missing;
                if (Written >= Limit) continue;
                WriteFlagQuiet(Id, true);
                Home->second[I] |= static_cast<uint8_t>(1 << Bit);
                AbsorbIntoBaseline(Id, true);
                ++Written;
            }
        }
    }
    return Written;
}

void FlagSyncTick() {
    const FlagSyncMode Mode = static_cast<FlagSyncMode>(g_flagSyncMode.load());
    if (Mode == FlagSyncMode::Off) return;

    const ULONGLONG Now = GetTickCount64();
    if (Now - g_flagLastTick < 1000) return;
    g_flagLastTick = Now;
    const bool Settling = FlagTablesSettling(Now);

    // Flags from the other player, written here -- on the game's own thread,
    // before the capture below, so that capture already contains them and the
    // diff does not send them straight back.
    //
    // Only once a baseline exists: the baseline is what absorbs a written flag,
    // and taking it is also what writes the backup file. And bounded per pass,
    // because a catch-up hands over a whole save's worth of progress at once and
    // every write the game accepts notifies its listeners -- fog, doors and
    // bonfires all react on the spot.
    {
        constexpr size_t kWritesPerTick = 400;
        std::lock_guard<std::mutex> Lock(g_flagSyncMutex);
        if (!g_flagBaseline.empty() && !g_pendingRemoteFlags.empty()) {
            size_t Taken = 0, Written = 0, Foreign = 0;
            while (Taken < kWritesPerTick && Taken < g_pendingRemoteFlags.size()) {
                const std::pair<uint32_t, bool> F = g_pendingRemoteFlags[Taken++];
                if (!F.second) continue;                  // set only, never clear
                // A group this save does not have is not ours to invent: the
                // setter would be asked for a bucket that is not there.
                auto Group = g_flagBaseline.find(F.first / 10000);
                if (Group == g_flagBaseline.end() ||
                    static_cast<size_t>((F.first % 10000) / 8) >= Group->second.size()) {
                    ++Foreign;
                    continue;
                }
                if (WriteFlagQuiet(F.first, true)) ++Written;
                AbsorbIntoBaseline(F.first, true);
            }
            g_pendingRemoteFlags.erase(g_pendingRemoteFlags.begin(),
                                       g_pendingRemoteFlags.begin() + Taken);
            LOG_INFO("[FLAGSYNC] wrote %zu flag(s) from the other player (%zu changed something here, "
                     "%zu in a group this save does not have), %zu still queued",
                     Taken, Written, Foreign, g_pendingRemoteFlags.size());
        }
    }

    // My own talk's flags, taken into the baseline before the table is read, so the diff never sees
    // them as a change worth sending (KeepFlagLocal).
    {
        std::vector<std::pair<uint32_t, bool>> Mine;
        {
            std::lock_guard<std::mutex> Lock(g_localFlagsMutex);
            Mine.swap(g_localFlags);
        }
        if (!Mine.empty()) {
            std::lock_guard<std::mutex> Lock(g_flagSyncMutex);
            if (!g_flagBaseline.empty()) {
                for (const auto& F : Mine) AbsorbIntoBaseline(F.first, F.second);
            }
        }
    }

    MaybeHandOverProgress();

    auto Current = CaptureFlags();
    if (Current.empty()) return;
    if (!Settling) DS2Coop::Sync::HandOverNewGroups(Current);

    std::lock_guard<std::mutex> Lock(g_flagSyncMutex);

    if (g_flagBaseline.empty()) {
        BackupFlagsOnce(Current);
        g_flagBaseline = std::move(Current);
        size_t bytes = 0;
        for (const auto& g : g_flagBaseline) bytes += g.second.size();
        LOG_INFO("[FLAGSYNC] watching %zu groups (%zu bytes), mode=%s",
                 g_flagBaseline.size(), bytes, Mode == FlagSyncMode::On ? "on" : "log");
        // Which groups exist at all: the flag id of anything in group N is
        // N*10000 + 0..9999, so this says what can be synced and what cannot.
        {
            char Groups[400];
            int Used = snprintf(Groups, sizeof(Groups), "[FLAGSYNC] groups:");
            for (const auto& g : g_flagBaseline) {
                if (Used >= static_cast<int>(sizeof(Groups)) - 24) break;
                Used += snprintf(Groups + Used, sizeof(Groups) - Used, " %u(%zu B, ids %u-%u)",
                                 g.first, g.second.size(), g.first * 10000,
                                 g.first * 10000 + static_cast<uint32_t>(g.second.size()) * 8 - 1);
            }
            LOG_INFO("%s", Groups);
        }
        return;
    }

    // A group that had bits set and now reads completely empty is the table being
    // rebuilt, not a world where everything was undone at once.
    //
    // Skipping the whole pass for it was a mistake, and a fatal one: on 12.09
    // group 20 read empty on every pass for minutes (994 such lines in the
    // guest's session, 541 in the host's), and because the pass returned before
    // the baseline was replaced, nothing was ever compared again -- flag sync was
    // dead for the rest of the session. That is why it "never had any visible
    // effect". Now only that one group is left out, with its old bytes kept, and
    // every other group is compared as usual.
    std::vector<uint32_t> Stale;
    for (const auto& g : Current) {
        auto Prev = g_flagBaseline.find(g.first);
        if (Prev == g_flagBaseline.end() || Prev->second.size() != g.second.size()) continue;

        bool NowEmpty = true, WasSet = false;
        for (size_t i = 0; i < g.second.size(); i++) {
            if (g.second[i]) { NowEmpty = false; break; }
            if (Prev->second[i]) WasSet = true;
        }
        if (NowEmpty && WasSet) Stale.push_back(g.first);
    }
    {
        static std::map<uint32_t, bool> s_toldAbout;   // one line per group, not one per second
        for (uint32_t Group : Stale) {
            if (s_toldAbout.find(Group) == s_toldAbout.end()) {
                s_toldAbout[Group] = true;
                LOG_INFO("[FLAGSYNC] group %u reads empty -- keeping the bits it had and leaving it out of the diff",
                         Group);
            }
            Current[Group] = g_flagBaseline[Group];
        }
    }

    // The host's world, carried home (see g_hostWorldFlags).
    if (g_carryHomeOn.load()) {
        const int Join = ReadJoinCtrlState();
        if (Join == 7) {
            if (!Settling) {
                g_hostWorldFlags = Current;
                g_carryHomePending = true;
            }
        } else if (Join < 0 && !Settling && g_carryHomePending) {
            size_t Missing = 0, Groups = 0;
            const size_t Written = CarryHomeLocked(&Current, 400, &Missing, &Groups);
            if (Missing <= Written) {
                g_carryHomePending = false;
                g_hostWorldFlags.clear();
            }
            if (Missing) {
                LOG_INFO("[FLAGSYNC] back in my own world: %zu flag(s) set in the host's world and missing here "
                         "written here too (%zu groups compared)%s", Written, Groups,
                         Missing > Written ? " -- more next pass" : "");
            }
        }
    }

    if (Settling) {
        g_flagBaseline = std::move(Current);
        return;
    }

    // Collect first, decide after: a burst far larger than gameplay produces is
    // another shape a rebuild takes.
    struct Change { uint32_t Id; bool Value; };
    std::vector<Change> Changes;

    for (const auto& g : Current) {
        auto Prev = g_flagBaseline.find(g.first);
        if (Prev == g_flagBaseline.end() || Prev->second.size() != g.second.size()) continue;

        for (size_t i = 0; i < g.second.size(); i++) {
            const uint8_t Diff = static_cast<uint8_t>(Prev->second[i] ^ g.second[i]);
            if (!Diff) continue;
            for (int bit = 0; bit < 8; bit++) {
                if (!(Diff & (1 << bit))) continue;
                Changes.push_back({ g.first * 10000 + static_cast<uint32_t>(i) * 8 + (7 - bit),
                                    (g.second[i] & (1 << bit)) != 0 });
            }
        }
    }

    // Eight was far too low, and it was the second thing killing this feature:
    // one bonfire, one fog gate or one area load moves more flags than that at
    // once, and every such pass was thrown away without sending anything.
    //
    // A high ceiling is safe because of what is sent: only bits that read as set
    // in this game's own table, and only in the 0->1 direction. Even a pass that
    // really is a rebuild can therefore do no worse than tell the other player
    // about progress this save genuinely has. The cap that is left is there to
    // keep one pass from turning into a thousand packets.
    constexpr size_t kPlausibleBurst = 256;
    if (Changes.size() > kPlausibleBurst) {
        LOG_INFO("[FLAGSYNC] %zu flags moved at once -- too many for one pass, re-baselining instead",
                 Changes.size());
        g_flagBaseline = std::move(Current);
        return;
    }

    g_flagBaseline = std::move(Current);
    if (Changes.empty()) return;

    char Line[600];
    int Used = snprintf(Line, sizeof(Line), "local:");
    int Sent = 0;
    for (const Change& C : Changes) {
        if (Used < static_cast<int>(sizeof(Line)) - 24)
            Used += snprintf(Line + Used, sizeof(Line) - Used, " %u=%d", C.Id, C.Value ? 1 : 0);
        if (Mode == FlagSyncMode::On && C.Value) {
            SendFlagToPeers(C.Id, true);
            Sent++;
        }
    }

    LOG_INFO("[FLAGSYNC] %zu changed, %d sent%s. %s", Changes.size(), Sent,
             Mode == FlagSyncMode::On ? "" : " (mode=log)", Line);
}




// Rest replay: exe+0x44F7F0 was the wrong entry point, and the probe said so
// before any network code got written.
//
// It looked right — the rest commit at exe+0x17FFA0 calls it as
// FUN([global+0x70], bonfireId) — but hooked live it never fired once during an
// actual rest, while exe+0x44F850 on the same path fired every time. Called by
// hand it threw and left the game to crash shortly after, so the helper is gone
// rather than left lying around behind a key.
//
// Enemy respawn still does not travel between players. Whatever performs it has
// to be found the way the bonfire gates were: probe candidates, keep the one
// that fires exactly once per rest, and only then wire it to a message.

bool HookBonfireGate() {
    static bool s_installed = false;
    if (s_installed) return true;
    s_installed = true;

    {
        const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));

        void* MpTarget = reinterpret_cast<void*>(ExeBase + 0x50C400);
        if (DS2Coop::Hooks::HookManager::GetInstance().InstallHook(
                MpTarget, reinterpret_cast<void*>(&MpActiveHook),
                reinterpret_cast<void**>(&g_origMpActive))) {
            LOG_INFO("HookBonfireGate: multiplayer predicate hooked");
        } else {
            LOG_WARNING("HookBonfireGate: could not hook the multiplayer predicate at exe+0x50C400");
        }

    }

    const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));

    bool Ok = false;
    if (DS2Coop::Hooks::HookManager::GetInstance().InstallHook(
            reinterpret_cast<void*>(ExeBase + 0x20D010), reinterpret_cast<void*>(&SummonByIdHook),
            reinterpret_cast<void**>(&g_origSummonById))) {
        Ok = true;
    }
    if (DS2Coop::Hooks::HookManager::GetInstance().InstallHook(
            reinterpret_cast<void*>(ExeBase + 0x1CBCC0), reinterpret_cast<void*>(&BonfireActivateHook),
            reinterpret_cast<void**>(&g_origBonfireActivate))) {
        Ok = true;
    }
    return Ok;
}

// EventConditionNet_IsHost (exe+0x46FCD0) — the condition the game's EzState
// scripts evaluate to ask "are we in multiplayer". Boss fog gates and cutscenes
// use it to send a phantom home, which is what throws a guest out on entering
// the Pursuer's fog and during the cutscene, before any boss is even killed:
//
//   if ([global+0x22F0] == 0) return false;    ; solo -> already false
//   ...
//   return FUN_5135F0() != expected;
//
// Stubbing it to return false makes those scripts treat the session as solo.
// This cannot affect single player: with no session the function already
// returns false on its first line, so the stub only changes behaviour inside a
// session. Toggleable with F6 so the effect can be compared during a co-op run.
//
// It used to be a byte patch, and so it answered "no" for the HOST as well --
// every script that waits for the host waited forever: the Last Giant stood
// still and could not be hurt while Restez, the host, was in its arena (12.09).
// It is a detour now and answers "no" only for a guest in someone else's world;
// the host gets the game's own answer.
using IsHostFn = uint64_t(__fastcall*)(void*, uint32_t, void*, uint32_t);
static IsHostFn g_origIsHost = nullptr;
static std::atomic<bool> g_scriptHostStub{ false };

// In someone else's world: the join controller ([[netRoot+0x18]+0x40],
// NetSummonJoinMultiplayCtrl) is in state 7. Plain data only (SEH).
static bool IsGuestInHostWorld() {
    __try {
        const uintptr_t Base = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
        const uintptr_t Root = *reinterpret_cast<const uintptr_t*>(Base + 0x1616CF8);
        if (!Root) return false;
        const uintptr_t Mp = *reinterpret_cast<const uintptr_t*>(Root + 0x18);
        if (!Mp) return false;
        const uintptr_t Ctrl = *reinterpret_cast<const uintptr_t*>(Mp + 0x40);
        if (!Ctrl || *reinterpret_cast<const uintptr_t*>(Ctrl) != Base + 0x10D7BD8) return false;
        return *reinterpret_cast<const int32_t*>(Ctrl + 0xF8) == 7;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The answers of the two seconds after an object was searched (a Pharros
// contraption a guest can press but that does nothing): what the script asked,
// what the game would have said and what it got.
static void LogIsHostAfterSearch(void* Condition, uint64_t Game, uint64_t Given) {
    static std::atomic<uint32_t> s_lines{ 0 };
    if (s_lines.fetch_add(1) >= 60) return;
    uint8_t Expect = 0xFF, Flag = 0xFF;
    if (Condition) {
        Memory::Read<uint8_t>(reinterpret_cast<uintptr_t>(Condition) + 0x10, &Expect);
        Memory::Read<uint8_t>(reinterpret_cast<uintptr_t>(Condition) + 0x11, &Flag);
    }
    LOG_INFO("[GATES] IsHost after a search: +0x10 %u, +0x11 %u -- game %llu, given %llu (from exe+0x%llX)",
             Expect, Flag, static_cast<unsigned long long>(Game & 0xFF), static_cast<unsigned long long>(Given & 0xFF),
             static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(_ReturnAddress()) -
                                             reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr))));
}

static uint64_t __fastcall IsHostDetour(void* Condition, uint32_t Edx, void* Vec3, uint32_t R9d) {
    const bool Stub = g_scriptHostStub.load() && IsGuestInHostWorld();
    if (DS2Coop::Sync::RecentSearchHit()) {
        const uint64_t Game = g_origIsHost(Condition, Edx, Vec3, R9d);
        const uint64_t Given = Stub ? 0 : Game;
        LogIsHostAfterSearch(Condition, Game, Given);
        return Given;
    }
    if (Stub) return 0;
    return g_origIsHost(Condition, Edx, Vec3, R9d);
}

bool SetScriptHostCondition(bool Stubbed) {
    static bool Hooked = false;
    if (!Hooked) {
        void* Target = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr)) + 0x46FCD0);
        if (!DS2Coop::Hooks::HookManager::GetInstance().InstallHook(
                Target, reinterpret_cast<void*>(&IsHostDetour), reinterpret_cast<void**>(&g_origIsHost))) {
            LOG_ERROR("SetScriptHostCondition: could not hook exe+0x46FCD0");
            return false;
        }
        Hooked = true;
    }
    g_scriptHostStub.store(Stubbed);
    LOG_INFO("SetScriptHostCondition: EventConditionNet_IsHost %s",
             Stubbed ? "answers no for a guest in someone else's world (the host keeps the game's answer)"
                     : "restored");
    return true;
}

struct GateSite { const char* Label; uint32_t Rva; uint8_t Expect[2]; uint8_t Replace[2]; };
const GateSite Sites[] = {
    { "bonfire registration session gate", 0x44CB7C, { 0x77, 0x20 }, { 0xEB, 0x20 } },
    { "bonfire action id veto",             0x1577C5, { 0x75, 0x06 }, { 0x90, 0x90 } },
    { "door key: whose inventory",          0x1C96FA, { 0x75, 0x03 }, { 0x90, 0x90 } },
    { "map objects: a guest writes none",   0x1F30C1, { 0x84, 0xC0 }, { 0x30, 0xC0 } },
    { "map objects: a guest reads none",    0x1F3798, { 0x84, 0xC0 }, { 0x30, 0xC0 } },
    { "byte [RAX+0x1A] test",               0x3EB716, { 0x74, 0xF6 }, { 0x90, 0x90 } },
    { "helper result test",                 0x3EB737, { 0x75, 0xD5 }, { 0x90, 0x90 } },
};

bool PatchBonfireGate() {
    const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));

    int Patched = 0;
    for (const GateSite& Site : Sites) {
        const uintptr_t Addr = ExeBase + Site.Rva;

        uint8_t Actual[2] = {};
        __try {
            memcpy(Actual, reinterpret_cast<void*>(Addr), sizeof(Actual));
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("PatchBonfireGate: cannot read exe+0x%X (%s)", Site.Rva, Site.Label);
            continue;
        }

        if (Actual[0] == Site.Replace[0] && Actual[1] == Site.Replace[1]) {
            LOG_INFO("PatchBonfireGate: exe+0x%X (%s) already patched", Site.Rva, Site.Label);
            Patched++;
            continue;
        }

        if (Actual[0] != Site.Expect[0] || Actual[1] != Site.Expect[1]) {
            LOG_WARNING("PatchBonfireGate: exe+0x%X (%s) expected %02X %02X, found %02X %02X — skipping",
                        Site.Rva, Site.Label, Site.Expect[0], Site.Expect[1], Actual[0], Actual[1]);
            continue;
        }

        DWORD OldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(Addr), 2, PAGE_EXECUTE_READWRITE, &OldProtect)) {
            LOG_ERROR("PatchBonfireGate: VirtualProtect failed at exe+0x%X (%lu)", Site.Rva, GetLastError());
            continue;
        }

        memcpy(reinterpret_cast<void*>(Addr), Site.Replace, 2);
        VirtualProtect(reinterpret_cast<void*>(Addr), 2, OldProtect, &OldProtect);

        LOG_INFO("PatchBonfireGate: PATCHED exe+0x%X (%s) %02X %02X -> %02X %02X",
                 Site.Rva, Site.Label, Site.Expect[0], Site.Expect[1],
                 Site.Replace[0], Site.Replace[1]);
        Patched++;
    }

    return Patched > 0;
}

} // namespace

namespace DS2Coop::Sync {



// ---------------------------------------------------------------------------
// Boundary scanner: find the byte that says "summoning is not allowed here".
//
// The region gate leaves no trace to follow. There is no refusal message (the
// message probe caught a locked door at id 0x451 and stayed silent for the
// soapstone), the sign-list request goes out normally, the server offers the
// sign, the response arrives, and the client just declines. Statically the class
// name leads only to its own registration, the cast helper's single caller is a
// destructor, and a hardware read-watch on the class descriptor recorded zero
// hits in fifteen seconds of crossing the boundary — the descriptor is read at
// map load and never again.
//
// What cannot hide is the state itself: something in memory differs between one
// side of the boundary and the other. So compare, rather than reason.
//
// Three presses:
//   1st, where signs work    take a snapshot
//   2nd, where they do not   keep only the bytes that changed
//   3rd, back where they work keep only those that changed back
//
// Two crossings in opposite directions cut the survivors down to a handful, and
// anything that merely drifts — timers, positions, animation state — is gone by
// the third press because it does not return to its old value on cue.
// ---------------------------------------------------------------------------
struct ScanRegion { const char* Label; uintptr_t Base; size_t Size; std::vector<uint8_t> Bytes; };

// A candidate is a byte that has held exactly two values, one per side.
struct ScanCandidate { size_t Region; size_t Offset; uint8_t OnSideA; uint8_t OnSideB; };

std::vector<ScanRegion>    g_scanRegions;
std::vector<ScanCandidate> g_scanCandidates;
int  g_scanStep = 0;        // how many presses so far

std::vector<ScanRegion> CollectScanRegions() {
    std::vector<ScanRegion> Out;
    const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));

    uintptr_t Global = 0;
    if (!Memory::Read<uintptr_t>(ExeBase + 0x16148F0, &Global) || !Global) return Out;

    // Widened after the sign-manager chain turned out to be a dead end for the
    // soapstone: stubbing exe+0x2A1F30, exe+0x275E72 and exe+0x2919D0 all left
    // the item grey, so whatever greys it is not in that chain. The item system
    // hangs off other slots of the same manager — +0x40 is the one the bonfire
    // work already saw used for item lookups — so the net goes wider rather than
    // deeper.
    struct Sub { const char* Label; uint32_t Offset; size_t Size; };
    static const Sub Subs[] = {
        { "global",     0xFFFFFFFF, 0x2400 },
        { "world",      0x18,       0x800  },
        { "playerdata", 0x38,       0x1000 },
        { "items",      0x40,       0x800  },
        { "sub48",      0x48,       0x400  },
        { "sub50",      0x50,       0x400  },
        { "sub58",      0x58,       0x400  },
        { "sub60",      0x60,       0x400  },
        { "eventmgr",   0x70,       0x800  },
        { "sub78",      0x78,       0x400  },
        { "sub B8",     0xB8,       0x600  },
        { "sub C0",     0xC0,       0x400  },
        { "sub C8",     0xC8,       0x600  },
        { "playerctrl", 0xD0,       0xA00  },
        { "sub E0",     0xE0,       0x400  },
        { "sub E8",     0xE8,       0x400  },
        { "camera",     0x22E0,     0x400  },
    };

    for (const Sub& S : Subs) {
        uintptr_t Base = Global;
        if (S.Offset != 0xFFFFFFFF) {
            if (!Memory::Read<uintptr_t>(Global + S.Offset, &Base) || !Base) continue;
        }
        ScanRegion R{ S.Label, Base, S.Size, {} };
        R.Bytes.resize(S.Size);
        bool Ok = true;
        for (size_t i = 0; i < S.Size && Ok; i++) Ok = Memory::Read<uint8_t>(Base + i, &R.Bytes[i]);
        if (Ok) Out.push_back(std::move(R));
    }
    return Out;
}

// Presses alternate sides: 1st and 3rd and 5th where signs work, 2nd and 4th
// where they do not. A flag holds one value on one side and the other value on
// the other, so any byte that ever shows a third value is not a flag — that
// single rule throws out the random-number state and the pointer churn that
// otherwise drown the result, and it is why the first attempt returned a
// hundred lines of noise.
void BoundaryScanStep() {
    auto Now = CollectScanRegions();
    if (Now.empty()) { LOG_WARNING("[SCAN] game structures not readable yet"); return; }

    if (g_scanStep == 0) {
        g_scanRegions = std::move(Now);
        g_scanCandidates.clear();
        g_scanStep = 1;
        size_t bytes = 0;
        for (const auto& R : g_scanRegions) bytes += R.Size;
        LOG_INFO("[SCAN] side A recorded (%zu regions, %zu bytes). Cross to where signs do NOT "
                 "work, then press again.", g_scanRegions.size(), bytes);
        return;
    }

    if (Now.size() != g_scanRegions.size()) {
        LOG_WARNING("[SCAN] the structures moved (a reload?) — starting over, press again on the side where signs work");
        g_scanStep = 0;
        return;
    }
    for (size_t r = 0; r < Now.size(); r++) {
        if (Now[r].Base != g_scanRegions[r].Base) {
            LOG_WARNING("[SCAN] region '%s' moved — starting over", Now[r].Label);
            g_scanStep = 0;
            return;
        }
    }

    g_scanStep++;
    const bool onSideA = (g_scanStep % 2) == 1;

    if (g_scanStep == 2) {
        // First look at the other side: every byte that moved is a candidate.
        g_scanCandidates.clear();
        for (size_t r = 0; r < Now.size(); r++) {
            for (size_t i = 0; i < Now[r].Size; i++) {
                if (Now[r].Bytes[i] != g_scanRegions[r].Bytes[i]) {
                    g_scanCandidates.push_back({ r, i, g_scanRegions[r].Bytes[i], Now[r].Bytes[i] });
                }
            }
        }
        LOG_INFO("[SCAN] side B recorded, %zu byte(s) differ. Cross back and press again.",
                 g_scanCandidates.size());
        return;
    }

    // Every later press must show the value that belongs to the side we are on.
    std::vector<ScanCandidate> Survivors;
    for (const auto& C : g_scanCandidates) {
        const uint8_t Value = Now[C.Region].Bytes[C.Offset];
        if (Value == (onSideA ? C.OnSideA : C.OnSideB)) Survivors.push_back(C);
    }
    g_scanCandidates = std::move(Survivors);

    LOG_INFO("[SCAN] press %d (%s): %zu byte(s) still behave like a flag",
             g_scanStep, onSideA ? "where signs WORK" : "where they do NOT",
             g_scanCandidates.size());

    int shown = 0;
    for (const auto& C : g_scanCandidates) {
        if (shown++ >= 30) { LOG_INFO("[SCAN]   ...and %zu more", g_scanCandidates.size() - 30); break; }
        LOG_INFO("[SCAN]   %s + 0x%zX : works=%u blocked=%u",
                 g_scanRegions[C.Region].Label, C.Offset, (unsigned)C.OnSideA, (unsigned)C.OnSideB);
    }
    if (g_scanCandidates.size() > 1) {
        LOG_INFO("[SCAN] cross again and press again to narrow it further.");
    }
}


// ---------------------------------------------------------------------------
// Hold the region byte at its permissive value.
//
// Eight crossings of the boundary narrowed 199 changing bytes to three that
// behave like a flag, and only one of them is a flag rather than an address:
//
//   playerdata + 0x5E1   0x24 where signs work, 0x28 where they do not
//   playerctrl + 0x468   low bytes of a pointer that moves by 208 — the region
//   playerctrl + 0x469   object itself, not a switch, so left alone
//
// 0x24 and 0x28 differ in two bits: bit 2 set on the permissive side, bit 3 on
// the blocked one. That reads as a small state field for the region the player
// is standing in, which is exactly what the summon rules are keyed on.
//
// The game rewrites it as the player moves, so holding it means writing every
// tick rather than patching once.
// Make the sign subsystem answer "yes" where the game says no.
//
// The controlled test settled where the loss happens: with the host parked in
// Majula for four minutes, not one sign-list request or response appeared in the
// log — the only traffic was a config push. The client does not ask. So the
// server-side work could never have helped, and neither could anything about
// coordinates; the whole sign subsystem is switched off locally.
//
// The stack from a request that *did* go out named the poll, and the decision
// sits in exe+0x2A22A0:
//
//   cVar1 = FUN_2A1D50();                 ; may I ask for signs?
//   if (obj[0x208] == 0 && cVar1) { FUN_2A3530(...); }   ; the request
//
// and inside exe+0x2A1D50 the deciding clause is a pair joined by "or":
//
//   FUN_2A1F50(mgr) || FUN_2A1FE0(mgr)
//
// Each walks a list of sign types and asks exe+0x2C5EA0 whether that type is
// usable, so between them they answer "can a sign be placed or answered here".
// Forcing either to 1 is a three-byte stub, and the cycle keeps them separate so
// the one that matters can be told from the one that does not.
//
// Two dead ends before this, both worth recording: playerdata+0x5E1 looked like
// a two-state flag over eight crossings but forcing it changed nothing and it
// later read 0x00, and the region object's own +0x156 and +0x170 differ across
// the boundary yet forcing both left the soapstone exactly as grey.
// Measured: exe+0x2A1F30 is the one that matters.
//
// In Majula (map 10040000), with the hooks live at 05:02:16, not one sign-list
// request went out for eight minutes. Stubbing exe+0x2A1F30 at 05:10:29 produced
// a request in the same second and one a minute after that, indefinitely. The
// soapstone stays grey — placing a sign is gated separately — but the client
// starts asking for signs again, which is what stopped a host standing there
// from ever seeing one.
//
// exe+0x2A1FA0 alone changed nothing, so it is left alone.
//
// Shipped on by default; F10 flips it for comparison.
constexpr uint32_t kSignPollGate = 0x2A1F30;

std::atomic<int> g_signGateMode{ 0 };   // 0 off, 1 exe+0x2A1F30, 2 exe+0x2A1FA0, 3 both

bool StubSignPredicate(uint32_t Rva, bool Enable) {
    struct Saved { uint32_t Rva; uint8_t Bytes[3]; bool Saved; bool Active; };
    static Saved Slots[4] = {};

    Saved* Slot = nullptr;
    for (Saved& S : Slots) {
        if (S.Rva == Rva) { Slot = &S; break; }
        if (!Slot && S.Rva == 0) Slot = &S;
    }
    if (!Slot) return false;

    const uintptr_t Addr = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr)) + Rva;
    if (!Slot->Saved) {
        Slot->Rva = Rva;
        memcpy(Slot->Bytes, reinterpret_cast<void*>(Addr), 3);
        Slot->Saved = true;
    }
    if (Slot->Active == Enable) return true;

    const uint8_t Stub[3] = { 0xB0, 0x01, 0xC3 };
    DWORD OldProtect = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(Addr), 3, PAGE_EXECUTE_READWRITE, &OldProtect)) {
        LOG_ERROR("[SIGNGATE] VirtualProtect failed at exe+0x%X (%lu)", Rva, GetLastError());
        return false;
    }
    memcpy(reinterpret_cast<void*>(Addr), Enable ? Stub : Slot->Bytes, 3);
    VirtualProtect(reinterpret_cast<void*>(Addr), 3, OldProtect, &OldProtect);
    Slot->Active = Enable;
    LOG_INFO("[SIGNGATE] exe+0x%X %s", Rva, Enable ? "forced to return 1" : "restored");
    return true;
}

// ---------------------------------------------------------------------------
// Place a summon sign without the soapstone.
//
// Nine rounds of hunting the item gate came up empty: the sign-manager chain
// (exe+0x2A1F30, exe+0x275E72, exe+0x2919D0) is not what greys the item, the
// region object's fields are not either, and the byte the boundary scan kept
// finding turned out to be the region's identity — exe+0x417B36 writes it as
// part of a four-byte area record — rather than a permission.
//
// So go around it. The item is only a way to reach the code that places a sign,
// and that code is reachable directly:
//
//   exe+0x28FAB0(owner, type)   takes the manager from owner+0x78
//   exe+0x2A1410(manager, type) does the work — build the sign data, submit it
//
// The manager itself is not a global worth chasing: it arrives as the first
// argument of the sign-manager tick at exe+0x2A1770, so hooking that both hands
// it over and provides a place to make the call from. That matters more than it
// sounds — calling a game function off the game's own thread is what crashed the
// earlier attempt at replaying a bonfire rest, and doing it inside this tick
// avoids the whole problem.
//
// Sign type 1 is the white soapstone, matching the sign_type field seen in the
// creation messages.
bool StubReturnsOne(uint32_t Rva, bool Enable);

using SignTickFn   = void(__fastcall*)(uint32_t*, void*);
using SubmitSignFn = void(__fastcall*)(void*, uint8_t*);

void*                 g_signTickOriginal = nullptr;
std::atomic<void*>    g_signManager{ nullptr };
std::atomic<bool>     g_placeSignPending{ false };

// Can a sign that goes down now be aimed at the other player?
//
// The numbers inside a sign are read against the origin of the map it is
// summoned into, so a sign left in this player's own frame does not land near
// the host: it lands wherever those numbers fall in the host's map. On 12.09
// that was off the map in Majula, and the guest was summoned, fell and died on
// arrival within seconds -- twice in a row. So a sign that cannot be aimed is
// not placed at all: it waits for the other player's position and for that
// map's origin, which the other player sends as soon as it knows it.
//
// Only for a guest whose sign a host is meant to summon. A host, a solo game
// and sign_under_feet=false place as before.
// Host: measure the origin of the map I am standing in by putting one sign down --
// the last resort, when the game's own origin cannot be used yet.
//
// The guest needs the origin of my map to aim its sign at me from another map.
// The game's own number comes first (session_hooks.cpp, LookupMapOrigin); only
// while that is not verified, and only for a map with nothing stored, is one sign
// of mine put down to measure it. Before 0.2.2 that sign went down in every new
// map whether or not anyone was in the lobby, it was aimed at the other player
// like a real one, and it was never taken down: after the eagle flight to 10160000
// it simply stood under the host's feet (17.09 15:11:57, point 10). Now it goes
// down only while the other player stands in another map, is aimed at nobody, is
// not announced, and is taken down the moment the server has it.
std::atomic<bool> g_probeSignPending{ false };
ULONGLONG         g_probeTakeDownUntil = 0;   // game thread only: a probe sign to take down
constexpr ULONGLONG kProbeTakeDownMs = 15000;

static bool PartnerInAnotherMap(uint32_t Here, uint32_t* PartnerArea) {
    *PartnerArea = 0;
    const uint64_t LocalId = DS2Coop::Network::PeerManager::GetInstance().GetLocalPlayerId();
    for (const auto& Player : DS2Coop::Session::SessionManager::GetInstance().GetPlayers()) {
        if (Player.playerId == LocalId) continue;
        *PartnerArea = Player.onlineAreaId;
        return Player.onlineAreaId != 0 && Player.onlineAreaId != Here;
    }
    return false;   // nobody else in the lobby
}

static void ProbeOwnMapOrigin() {
    auto& Lobby = DS2Coop::Session::SessionManager::GetInstance();
    if (!Lobby.IsActive() || !Lobby.IsHost()) return;
    const uint32_t Here = DS2Coop::Hooks::GetLocalAreaId();
    if (!Here) return;
    uint32_t Area = 0;
    float X = 0, Y = 0, Z = 0;
    if (DS2Coop::Hooks::GetLocalMapOrigin(&Area, &X, &Y, &Z)) return;   // known already
    uint32_t PartnerArea = 0;
    if (!PartnerInAnotherMap(Here, &PartnerArea)) return;   // nobody needs it now

    // Game thread only (the sign-manager tick).
    static uint32_t  s_forMap = 0;
    static int       s_tries = 0;
    static ULONGLONG s_nextTry = 0;
    if (s_forMap != Here) {
        s_forMap = Here;
        s_tries = 0;
        s_nextTry = 0;
    }
    const ULONGLONG Now = GetTickCount64();
    if (s_tries >= 3 || Now < s_nextTry) return;
    ++s_tries;
    s_nextTry = Now + 30000;
    g_probeSignPending.store(true);
    LOG_INFO("[SIGN] map %u has no origin yet (the game's own origin %s) and the other player is in map %u -- "
             "one sign of mine measures it and is taken down at once (try %d of 3)",
             Here, DS2Coop::Hooks::IsGameOriginTrusted() ? "does not resolve here" : "is not verified yet",
             PartnerArea, s_tries);
}

// A probe sign comes down as soon as the server has created it.
static void TickProbeTakeDown(void* Manager) {
    if (!g_probeTakeDownUntil || !Manager) return;
    const ULONGLONG Now = GetTickCount64();
    switch (DS2Coop::Sync::TakeDownPlacedSign(Manager)) {
    case DS2Coop::Sync::PlacedSignTakeDown::NotCreatedYet:
        if (Now < g_probeTakeDownUntil) return;
        LOG_WARNING("[SIGN] the sign that measured the map got no id from the server in %llu s -- left to the game",
                    kProbeTakeDownMs / 1000);
        break;
    case DS2Coop::Sync::PlacedSignTakeDown::NoSign:
        if (Now < g_probeTakeDownUntil) return;   // the create has not reached the manager yet
        LOG_INFO("[SIGN] the sign that measured the map is not there any more");
        break;
    case DS2Coop::Sync::PlacedSignTakeDown::TakenDown:
    case DS2Coop::Sync::PlacedSignTakeDown::Failed:
        break;
    }
    g_probeTakeDownUntil = 0;
}

static bool CanAimSignAtPartner(uint32_t* PartnerArea) {
    *PartnerArea = 0;
    auto& Lobby = DS2Coop::Session::SessionManager::GetInstance();
    if (!Lobby.IsActive() || Lobby.IsHost()) return true;
    if (!DS2Coop::Hooks::GetSignUnderFeet()) return true;
    const uint64_t LocalId = DS2Coop::Network::PeerManager::GetInstance().GetLocalPlayerId();
    for (const auto& Player : Lobby.GetPlayers()) {
        if (Player.playerId == LocalId) continue;
        *PartnerArea = Player.onlineAreaId;
        return Player.onlineAreaId != 0 && DS2Coop::Hooks::IsMapOriginKnown(Player.onlineAreaId);
    }
    return false;   // nobody else in the lobby yet
}

// Ask for the sign list far more often than the game does.
//
// Left alone the client polls about once a minute, which is why a sign placed
// for someone can take that long to turn up. exe+0x2A3530 is the builder the
// poll itself calls — the sign-list request stack runs straight through it — and
// it takes the manager plus the area id the poll keeps at manager+0x5C. Calling
// it on a short timer costs one small request between two players and takes the
// wait down to seconds.
// The other player tells us when they put a sign down, and that is when we ask.
//
// Polling on a timer was the first attempt and it is wasteful in both
// directions: it spends requests when nothing has happened and still leaves a
// gap when something has. The two clients already have a channel between them
// and a working handshake, so the placer can simply say so. The timer stays
// underneath at a much slower rate, in case a message is lost or one side is
// running an older build.
constexpr uint32_t kSignPollSeconds = 20;
ULONGLONG g_lastSignPoll = 0;
std::atomic<bool> g_signPollWanted{ false };
ULONGLONG g_pollGateLogAt = 0;   // when to write the predicate line after an urgent poll

// Let a fresh sign-list request out immediately.
//
// Nudging manager+0x60 alone did nothing measurable: the next request still came
// 39 seconds later. The poll predicate also needs task 8 not to be running, and
// "flag 8" turned out to be an entry in the network task registry, not a bit —
// {state, owner id, task number, task*} records in 0x18-byte slots reached as
// *(*(*(exe+0x1616CF8)+0x30)+0x50), tested by exe+0x285530 and kicked by
// exe+0x2854D0. While the sign-list task is alive the poll stays shut.
//
// The summon task's tick (exe+0x27ABE0) shows the base class: state at +0x14
// (2 = running) and a countdown at +0x1C that ends the task when it drops below
// zero. If the sign-list task shares that base, zeroing its countdown ends it on
// the next tick and the poll can fire. Guarded: only a running task with a sane
// timer is touched, and everything seen is logged.
// Which timers to finish.
//
// Finishing timer 8 alone worked twice and failed once: at 02:16:20 the timer
// was finished and no request went out for another twenty seconds. The poll
// predicate exe+0x2A1D50 reads
//
//   service 8 up && region gate && game state 30 &&
//     ( task 9 gone                                    -> poll
//     | task 8 gone && cell changed && this cell's signs all ready -> poll )
//
// and the registry tick (exe+0x2856D0) calls a task gone on the very tick it
// finishes. Task 9 is the refresh timer the game lets run out on its own every
// 30-50 s -- that is the natural cadence in the logs. While it runs, a poll has
// to take the second branch, which also wants a changed cell and a ready cell,
// and that is where 02:16:20 stuck. Finishing 9 opens the short branch; 8 is
// finished too so the long one is open as well.
void ExpireSignTimer(void* Manager, int WantNumber) {
    __try {
        const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
        const uintptr_t ExeEnd  = ExeBase + 0x2000000;

        uintptr_t P0 = 0, P1 = 0, Registry = 0;
        if (!Memory::Read<uintptr_t>(ExeBase + 0x1616CF8, &P0) || !P0) return;
        if (!Memory::Read<uintptr_t>(P0 + 0x30, &P1) || !P1) return;
        if (!Memory::Read<uintptr_t>(P1 + 0x50, &Registry) || !Registry) return;

        // The registry keys tasks by the owner's own id, from its vtable slot +0x58.
        uintptr_t Vtbl = 0, IdFn = 0;
        if (!Memory::Read<uintptr_t>(reinterpret_cast<uintptr_t>(Manager), &Vtbl)) return;
        if (Vtbl < ExeBase || Vtbl >= ExeEnd) return;
        if (!Memory::Read<uintptr_t>(Vtbl + 0x58, &IdFn)) return;
        if (IdFn < ExeBase || IdFn >= ExeEnd) return;
        const int MyId = reinterpret_cast<int(__fastcall*)(void*)>(IdFn)(Manager);

        uintptr_t Entries = 0;
        uint32_t  Idx = 0;
        if (!Memory::Read<uintptr_t>(Registry + 0x10, &Entries) || !Entries) return;
        if (!Memory::Read<uint32_t>(Registry + 0x30, &Idx)) return;

        for (int Guard = 0; Idx != 0xFFFFFFF && Guard < 1024; Guard++) {
            const uintptr_t E = Entries + static_cast<uintptr_t>(static_cast<int>(Idx)) * 0x18;
            uint32_t Head = 0; int Owner = 0, Number = 0; uintptr_t Task = 0;
            if (!Memory::Read<uint32_t>(E, &Head)) return;
            Memory::Read<int>(E + 4, &Owner);
            Memory::Read<int>(E + 8, &Number);
            Memory::Read<uintptr_t>(E + 0x10, &Task);

            if (Owner == MyId && Number == WantNumber && Task) {
                // Measured, not guessed: task 8 is a 0x20-byte periodic timer with
                // vtable exe+0x10D47B8 —
                //
                //   +0x08  interval   30.0
                //   +0x0C  elapsed    counts UP: 7.83 -> 27.85 -> 30.02
                //   +0x14  state      2 while running, 4 the moment elapsed passes
                //                     the interval — and the sign list arrived in
                //                     that same second
                //
                // The earlier guess had both the field and the direction wrong
                // (+0x1C, counting down); it read 0.0 throughout and the guard kept
                // it from writing. Setting elapsed to the interval finishes the timer
                // on the next tick, which is what lets the poll through.
                uintptr_t TaskVtbl = 0;
                int State = 0;
                float Interval = 0.0f, Elapsed = 0.0f;
                Memory::Read<uintptr_t>(Task, &TaskVtbl);
                Memory::Read<int>(Task + 0x14, &State);
                Memory::Read<float>(Task + 0x08, &Interval);
                Memory::Read<float>(Task + 0x0C, &Elapsed);

                const bool IsTimer = (TaskVtbl == ExeBase + 0x10D47B8);
                const bool Sane = IsTimer && State == 2 && Interval > 0.0f && Interval <= 600.0f &&
                                  Elapsed >= 0.0f && Elapsed < Interval;
                LOG_INFO("[PLACE] sign timer %d: %.1f of %.1f s, state %d -> %s",
                         WantNumber, Elapsed, Interval, State,
                         Sane ? "finishing it now" : (IsTimer ? "already free" : "unknown class, left alone"));
                if (Sane) Memory::Write<float>(Task + 0x0C, Interval);
                return;
            }
            Idx = Head >> 4;
        }
        LOG_INFO("[PLACE] no sign timer %d for owner %d — nothing to finish", WantNumber, MyId);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("[PLACE] walking the task registry threw — leaving it alone");
    }
}

// One line with every term of the poll predicate, written shortly after an
// urgent poll, so a poll that does not fire names its reason in the log instead
// of costing another round of guessing.
void LogPollGate(void* Manager) {
    __try {
        const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
        const uintptr_t M = reinterpret_cast<uintptr_t>(Manager);
        using TestFn = char(__fastcall*)(void*, int);
        auto Service   = reinterpret_cast<TestFn>(ExeBase + 0x275E72);
        auto TaskAlive = reinterpret_cast<TestFn>(ExeBase + 0x2760A0);

        const bool ServiceUp = Service(Manager, 8) != 0;
        const bool Task9 = TaskAlive(Manager, 9) != 0;
        const bool Task8 = TaskAlive(Manager, 8) != 0;

        int GameState = -1;
        uintptr_t Global = 0;
        if (Memory::Read<uintptr_t>(ExeBase + 0x16148F0, &Global) && Global)
            Memory::Read<int>(Global + 0x24AC, &GameState);

        uint32_t Stored = 0, Live = 0;
        Memory::Read<uint32_t>(M + 0x60, &Stored);
        reinterpret_cast<void(__fastcall*)(uint32_t*)>(ExeBase + 0x2AAB90)(&Live);

        uint8_t Active = 0, OtherBranch = 0;
        Memory::Read<uint8_t>(M + 0xF0, &Active);
        Memory::Read<uint8_t>(M + 0x208, &OtherBranch);

        // Why service 8 is down, when it is: the capability object [netRoot+0x38]
        // keeps a mode at +8 (0-6, each with its own mask of what is allowed) and a
        // block counter per capability at +0x10+4n (docs §1.2). 17.09 a host's
        // game sat at "service 0" for twelve minutes and polled no sign at all.
        uintptr_t Root = 0, Caps = 0;
        int CapsMode = -1, Blocks8 = -1;
        if (Memory::Read<uintptr_t>(ExeBase + 0x1616CF8, &Root) && Root &&
            Memory::Read<uintptr_t>(Root + 0x38, &Caps) && Caps) {
            Memory::Read<int>(Caps + 0x08, &CapsMode);
            Memory::Read<int>(Caps + 0x10 + 4 * 8, &Blocks8);
        }

        LOG_INFO("[POLLGATE] service %d (mode %d, blocks %d), game state %d (needs 30), task9 %s, task8 %s, "
                 "cell %08X vs stored %08X, manager on %u, +0x208 %u",
                 ServiceUp ? 1 : 0, CapsMode, Blocks8, GameState, Task9 ? "running" : "gone",
                 Task8 ? "running" : "gone", Live, Stored, Active, OtherBranch);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("[POLLGATE] reading the predicate threw");
    }
}

void PollSignsNow(void* Manager, bool Urgent) {
    if (!Manager) return;
    if (Urgent) {
        ExpireSignTimer(Manager, 9);
        ExpireSignTimer(Manager, 8);
        g_pollGateLogAt = GetTickCount64() + 150;
    }

    // Nudge the game's own poll instead of issuing a request behind its back.
    //
    // The first version called the request builder exe+0x2A3530 directly, and
    // it broke sign display outright: the list kept arriving — 149 bytes every
    // time, the sign plainly in it — and nothing was ever drawn. The regular
    // poll in exe+0x2A22A0 does more than build the request; it records when it
    // asked at manager+0x60 and raises state flags 8, 9 and 3 that mark a
    // response as expected. A request sent without that bookkeeping gets an
    // answer the manager is not waiting for, and it is parsed and dropped.
    //
    // The poll fires whenever exe+0x2A1D50 sees manager+0x60 differ from the
    // current value exe+0x2A2AB90 hands back — once a minute, left alone. Making
    // the stored value stale is enough for the game to run a complete poll of
    // its own on the very next tick, flags and all. It also respects the game's
    // one-request-at-a-time rule for free: while flag 8 is up the predicate
    // stays false no matter what the timestamp says.
    //
    // The stamp is the cell the player stood in at the last poll; exe+0x2AAB90
    // derives the live one from the position. Complementing the stored value
    // was not enough -- two nudges with no poll in between cancel out -- so the
    // complement of the live cell is written instead, which always differs.
    const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    const uintptr_t Stamp = reinterpret_cast<uintptr_t>(Manager) + 0x60;
    uint32_t Live = 0;
    __try {
        reinterpret_cast<void(__fastcall*)(uint32_t*)>(ExeBase + 0x2AAB90)(&Live);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        if (!Memory::Read<uint32_t>(Stamp, &Live)) return;
    }
    Memory::Write<uint32_t>(Stamp, ~Live);
}

// Summon the offered sign without walking to it.
//
// Touching a sign is action 0xC, and its executor (exe+0x452BE0) needs the sign
// object only to read one number out of object+0x20 before calling
//
//   exe+0x20D010(summon manager = [global+0x90], &id)
//
// which checks the id with exe+0x20FA60([manager+0x68], &id) and queues the
// summon. A real summon logged id 0x80000011: not the server's sign_id (the
// server numbers them 1000, 1002, 1004) but a local handle — top bit set, a
// small slot number underneath. So there is no need to map one to the other:
// the game's own "is this sign known" check, run over the handful of possible
// handles, points straight at the live one.
//
// Runs inside the sign-manager tick, on the game's thread, like placing does.
std::atomic<bool> g_summonPending{ false };

// Automatic join. The joiner puts a sign down as soon as its handshake with the
// host is confirmed; the host, told "I placed one" over the mod's own channel,
// keeps looking for that sign for a while and summons it the moment it is known.
// Every piece already existed on a key -- F11 places, F2 summons, the ping and the
// instant poll were automatic -- so this only removes the two key presses.
std::atomic<bool>      g_autoSummonEnabled{ true };
std::atomic<ULONGLONG> g_autoSummonUntil{ 0 };
ULONGLONG              g_autoSummonNextTry = 0;
std::atomic<ULONGLONG> g_autoPollNextTry{ 0 };

// A sign-list request whose answer has not come back. Five seconds without one
// counts as lost, so a dropped response cannot stall the automatic summon.
bool SignListInFlight(ULONGLONG Now) {
    static uint32_t  LastRequests = 0;
    static ULONGLONG LastRequestAt = 0;
    const uint32_t Requests  = DS2Coop::Hooks::GetSignListRequestCount();
    const uint32_t Responses = DS2Coop::Hooks::GetSignListResponseCount();
    if (Requests != LastRequests) { LastRequests = Requests; LastRequestAt = Now; }
    return static_cast<int32_t>(Requests - Responses) > 0 && Now - LastRequestAt < 5000;
}

// Leaving the other player's world: asked for from the menu or by the host
// closing the session, carried out in the sign tick on the game's thread.
std::atomic<ULONGLONG> g_leaveWorldUntil{ 0 };
std::atomic<ULONGLONG> g_leaveWorldNextTry{ 0 };
std::atomic<int>       g_leaveLastState{ -1 };

bool SummonOfferedSign(void* SignManager, bool Quiet) {
    __try {
        const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));

        uintptr_t Global = 0, SummonMgr = 0, Known = 0;
        if (!Memory::Read<uintptr_t>(ExeBase + 0x16148F0, &Global) || !Global ||
            !Memory::Read<uintptr_t>(Global + 0x90, &SummonMgr) || !SummonMgr ||
            !Memory::Read<uintptr_t>(SummonMgr + 0x68, &Known) || !Known) {
            if (!Quiet) LOG_WARNING("[SUMMON] summon manager not available — is anyone's sign on offer?");
            return false;
        }

        using KnownFn = char(__fastcall*)(uintptr_t, uint32_t*);
        auto IsKnown = reinterpret_cast<KnownFn>(ExeBase + 0x20FA60);

        uint32_t Live[16];
        int Count = 0;
        for (uint32_t Slot = 0; Slot < 0x1000 && Count < 16; Slot++) {
            uint32_t Id = 0x80000000u | Slot;
            if (IsKnown(Known, &Id)) Live[Count++] = 0x80000000u | Slot;
        }

        if (Count == 0) {
            if (!Quiet) LOG_INFO("[SUMMON] no sign on offer right now");
            return false;
        }
        for (int i = 0; i < Count; i++) LOG_INFO("[SUMMON] sign on offer: 0x%08X", Live[i]);

        // Who hears about it. exe+0x20D010 does not summon: it marks the slot
        // pending and broadcasts through exe+0x2115B0 to the listeners kept at
        // manager+0x20 (count at +0x40), calling each one's vtable +0x10 with the
        // id. One of them opens the confirmation menu — which then closes at once,
        // because outside the touch-the-sign action it has no owner — and the
        // summon itself only starts after "yes". Naming the listeners points at
        // the one that does the real work.
        if (!Quiet) {
            uint32_t Listeners = 0;
            Memory::Read<uint32_t>(SummonMgr + 0x40, &Listeners);
            const uintptr_t List = ((0 - (SummonMgr + 0x20)) & 7) + SummonMgr + 0x20;
            LOG_INFO("[SUMMON] %u listener(s) on the summon manager", Listeners);
            for (uint32_t i = 0; i < Listeners && i < 16; i++) {
                uintptr_t Obj = 0, Vtbl = 0, OnSummon = 0;
                Memory::Read<uintptr_t>(List + i * 8, &Obj);
                if (Obj) Memory::Read<uintptr_t>(Obj, &Vtbl);
                if (Vtbl) Memory::Read<uintptr_t>(Vtbl + 0x10, &OnSummon);
                LOG_INFO("[SUMMON]   listener %u: obj %p vtable exe+0x%llX, handler exe+0x%llX",
                         i, reinterpret_cast<void*>(Obj),
                         (unsigned long long)(Vtbl ? Vtbl - ExeBase : 0),
                         (unsigned long long)(OnSummon ? OnSummon - ExeBase : 0));
            }
        }

        // Start the summon job directly, skipping the confirmation menu.
        //
        // exe+0x20D010 — what touching a sign ends in — only marks the slot pending
        // and broadcasts to the manager's listeners; one of them opens
        // FeSceneSummonSignWindow, and outside the touch-the-sign action that window
        // has no owner and is closed the same frame. That is what F2 did at first:
        // the menu flashed and vanished and no RequestSummonSign ever went out.
        //
        // Picking "yes" ends in exe+0x2A41B0(sign manager, &id), which re-checks the
        // sign type against the region — exe+0x2919D0 and exe+0x275E72, the same
        // gates that grey the soapstone out — and then calls exe+0x2A2C90 with the
        // same arguments. That is the real starter: it takes a free slot of the five
        // pending summons at manager+100, constructs NetSvrSummonSignSummonJob
        // (ctor exe+0x2A5970) and registers it as network task 0xB+slot, whose tick
        // sends the request. Calling it directly skips both the window and the
        // region gates, so a host standing in Majula can summon as well. It checks
        // its own preconditions and simply returns if they are not met.
        if (!SignManager) {
            if (!Quiet) LOG_WARNING("[SUMMON] sign manager not seen yet");
            return false;
        }
        using StartSummonFn = void(__fastcall*)(void*, uint32_t*);
        auto StartSummon = reinterpret_cast<StartSummonFn>(ExeBase + 0x2A2C90);
        uint32_t Pick = Live[Count - 1];
        DS2Coop::Sync::SetPartnerSummonStarting(true);
        StartSummon(SignManager, &Pick);
        DS2Coop::Sync::SetPartnerSummonStarting(false);
        LOG_INFO("[SUMMON] summon job started for 0x%08X — RequestSummonSign should follow",
                 Live[Count - 1]);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // A throw inside StartSummon skips the reset above; left set, the effigy
        // check would wave every later summon start through as the partner's.
        DS2Coop::Sync::SetPartnerSummonStarting(false);
        LOG_ERROR("[SUMMON] threw — leaving it alone");
        return false;
    }
}

// The host's automatic summon, aimed at the joiner's sign.
//
// "Summon the last sign the game knows" failed at 18:45: slot 0x80000019 was
// already known before the joiner's sign arrived (the sign lists had all come
// back empty), the job for it started and sent nothing, and the joiner's own
// sign -- in the list the same second, as 0x80000011 -- was never tried. So the
// signs already known when the joiner's ping arrives are noted and passed over
// for the first seconds, a summon counts only once RequestSummonSign has really
// gone out, and a slot that produced none is not tried again.
std::atomic<bool> g_autoSnapshotPending{ false };
uint32_t  g_autoKnownAtArm[16] = {};
int       g_autoKnownAtArmCount = 0;
uint32_t  g_autoTried[16] = {};
int       g_autoTriedCount = 0;
uint32_t  g_autoPendingId = 0;         // started; waiting for RequestSummonSign
uint32_t  g_autoPendingRequests = 0;   // the summon-request count when it started
ULONGLONG g_autoPendingSince = 0;
ULONGLONG g_autoArmedAt = 0;
ULONGLONG g_autoRefusedUntil = 0;       // the game refused to start a job: wait, then the same sign again
ULONGLONG g_autoRefusedToastAt = 0;

// The host's game would not even start the partner's summon. When the area's protection
// against invaders is the reason, the host is told what to do about it.
void NoteAutoSummonRefused(uint32_t Sign, ULONGLONG Now) {
    int32_t Area = 0;
    float Seconds = 0.0f;
    const bool Protected = DS2Coop::Sync::ReadAreaProtection(&Area, &Seconds);
    if (Now - g_autoRefusedToastAt < 30000) return;
    g_autoRefusedToastAt = Now;
    LOG_WARNING("[AUTO] the game started no summon for 0x%08X%s -- trying the same sign again every second", Sign,
                Protected ? " (the area is protected against invaders)" : "");
    if (!Protected) return;
    const int Minutes = static_cast<int>(Seconds) / 60, Secs = static_cast<int>(Seconds) % 60;
    DS2Coop::UI::Overlay::GetInstance().ShowNotification(
        DS2Coop::UI::Format(DS2Coop::UI::Tr(
            "This area is protected against invaders (effigy, %d:%02d left) and the game will not summon your partner. "
            "Remove the protection at a bonfire.",
            "Здесь защита от вторжений (фигурка, ещё %d:%02d), и игра не призывает напарника. Сними защиту у костра."),
            Minutes, Secs),
        8.0f, DS2Coop::UI::NotifyKind::Warning);
}

// Joiner side: an automatic placement has to end in a RequestCreateSign. In
// Majula the game submits nothing at all (20:44: "returned cleanly", no
// request), so a placement that produced none is tried again every 5 s for two
// minutes -- the player can walk out -- and the player is told once why.
std::atomic<ULONGLONG> g_autoPlaceUntil{ 0 };
std::atomic<bool>      g_autoPlaceWatch{ false };
std::atomic<bool>      g_autoPlaceWarned{ false };
ULONGLONG g_autoPlaceCheckAt = 0;
uint32_t  g_autoPlaceCreatesBefore = 0;
ULONGLONG g_autoPlaceRetryAt = 0;

// Every sign the game knows right now, as local descriptors (0x80000000 | slot).
int ListKnownSigns(uint32_t* Out, int Max) {
    __try {
        const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
        uintptr_t Global = 0, SummonMgr = 0, Known = 0;
        if (!Memory::Read<uintptr_t>(ExeBase + 0x16148F0, &Global) || !Global ||
            !Memory::Read<uintptr_t>(Global + 0x90, &SummonMgr) || !SummonMgr ||
            !Memory::Read<uintptr_t>(SummonMgr + 0x68, &Known) || !Known) return 0;
        using KnownFn = char(__fastcall*)(uintptr_t, uint32_t*);
        auto IsKnown = reinterpret_cast<KnownFn>(ExeBase + 0x20FA60);
        int Count = 0;
        for (uint32_t Slot = 0; Slot < 0x1000 && Count < Max; Slot++) {
            uint32_t Id = 0x80000000u | Slot;
            if (IsKnown(Known, &Id)) Out[Count++] = 0x80000000u | Slot;
        }
        return Count;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// Whether one of the sign manager's five pending summons (manager+0x64, 0x1C each)
// holds this sign: exe+0x2A2C90 fills one when it really starts a summon job.
bool SummonJobPendingSafe(void* SignManager, uint32_t Id) {
    __try {
        const uintptr_t Base = reinterpret_cast<uintptr_t>(SignManager) + 0x64;
        for (int Slot = 0; Slot < 5; ++Slot) {
            for (int Off = 0; Off < 0x1C; Off += 4) {
                if (*reinterpret_cast<const uint32_t*>(Base + Slot * 0x1C + Off) == Id) return true;
            }
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;   // unreadable: assume it went as usual
    }
}

// Start a summon on the newest known sign that is not in Skip. *JobMade says whether
// the game really started a job for it (it refuses by itself, e.g. while the area is
// protected against invaders).
bool SummonJoinerSign(void* SignManager, const uint32_t* Skip, int SkipCount, uint32_t* Started, bool* JobMade) {
    *JobMade = false;
    if (!SignManager) return false;
    uint32_t Live[16];
    const int Count = ListKnownSigns(Live, 16);
    for (int I = Count - 1; I >= 0; --I) {
        bool Skipped = false;
        for (int J = 0; J < SkipCount; ++J) {
            if (Skip[J] == Live[I]) { Skipped = true; break; }
        }
        if (Skipped) continue;
        const bool WasPending = SummonJobPendingSafe(SignManager, Live[I]);
        DS2Coop::Sync::SetPartnerSummonStarting(true);
        __try {
            const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
            using StartSummonFn = void(__fastcall*)(void*, uint32_t*);
            uint32_t Pick = Live[I];
            reinterpret_cast<StartSummonFn>(ExeBase + 0x2A2C90)(SignManager, &Pick);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DS2Coop::Sync::SetPartnerSummonStarting(false);
            LOG_ERROR("[SUMMON] starting a summon threw -- left alone");
            return false;
        }
        DS2Coop::Sync::SetPartnerSummonStarting(false);
        *Started = Live[I];
        *JobMade = !WasPending && SummonJobPendingSafe(SignManager, Live[I]);
        int32_t Area = 0;
        float Seconds = 0.0f;
        const bool Protected = DS2Coop::Sync::ReadAreaProtection(&Area, &Seconds);
        LOG_INFO("[SUMMON] summon of 0x%08X: job %s (%d sign(s) known, %d passed over; area %d %s)", Live[I],
                 *JobMade ? "started" : WasPending ? "already pending" : "NOT started by the game", Count, SkipCount,
                 Area, Protected ? "protected against invaders" : "not protected");
        if (WasPending) *JobMade = true;
        return true;
    }
    return false;
}

void WarnSignNotPlaced() {
    DS2Coop::UI::Overlay::GetInstance().ShowNotification(
        DS2Coop::UI::Tr("No sign here: this place does not take signs (Majula?). Step out -- it will be placed by itself.",
                        "Здесь знак не ставится (Маджула?). Отойди \xE2\x80\x94 поставится сам."),
        6.0f, DS2Coop::UI::NotifyKind::Warning);
}

// Go home through the game's own door.
//
// Closing the mod's channel ended nothing in the game: the phantom kept standing
// in the host's world. The game's way out is exe+0x2C8F30, the multiplayer
// manager's "everyone return" that the phantom-return event calls with a
// reason. It hands the reason to the join controller at manager+0x40 (vtable
// slot 0xA0), which -- once the join has settled, state 7 -- records it and
// moves to state 8: warp home, tell the host over P2P, tell the server
// (RequestNotifyLeaveSession). That last message is exactly what the log showed
// only after the Black Separation Crystal. Reason 3 is what the controller uses
// itself when a session drops; reason 1 would count as a successful co-op,
// stats and all.
//
// The manager is the network root's fourth pointer, *(exe+0x1616CF8)+0x18, the
// one the frame update ticks. Returns 1 when the game took the request, 0 while
// the join is still settling (worth another try), -1 when there is nothing to
// leave.
int ReturnToOwnWorld() {
    __try {
        const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
        const uintptr_t ExeEnd  = ExeBase + 0x2000000;
        uintptr_t Net = 0, Mp = 0, Ctrl = 0, Vtbl = 0;
        if (!Memory::Read<uintptr_t>(ExeBase + 0x1616CF8, &Net) || !Net) return -1;
        if (!Memory::Read<uintptr_t>(Net + 0x18, &Mp) || !Mp) return -1;
        if (!Memory::Read<uintptr_t>(Mp + 0x40, &Ctrl) || !Ctrl) {
            LOG_INFO("[LEAVE] no join controller -- we are not in anyone's world");
            return -1;
        }
        if (!Memory::Read<uintptr_t>(Ctrl, &Vtbl) || Vtbl < ExeBase || Vtbl >= ExeEnd) return -1;

        // NetSummonJoinMultiplayCtrl keeps its state at +0xF8; 7 = in the world.
        if (Vtbl == ExeBase + 0x10D7BD8) {
            int State = -1;
            Memory::Read<int>(Ctrl + 0xF8, &State);
            if (State != g_leaveLastState.exchange(State)) {
                LOG_INFO("[LEAVE] join controller state %d%s", State,
                         State == 7 ? " (in the host's world)" :
                         State < 7  ? " (still joining -- waiting)" : " (already on the way out)");
            }
            if (State < 7) return 0;
            if (State > 7) return -1;
        } else {
            LOG_INFO("[LEAVE] join controller of another kind (vtable exe+0x%llX) -- asking it anyway",
                     (unsigned long long)(Vtbl - ExeBase));
        }

        using ReturnAllFn = void(__fastcall*)(uintptr_t, uint32_t);
        reinterpret_cast<ReturnAllFn>(ExeBase + 0x2C8F30)(Mp, 3);
        LOG_INFO("[LEAVE] the game is sending us home (reason 3, the dropped-session path)");
        return 1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("[LEAVE] threw -- left alone");
        return -1;
    }
}

void __fastcall SignTickDetour(uint32_t* SignId, void* Manager) {
    g_signManager.store(Manager);
    DS2Coop::Hooks::ServerWatchTick();

    // Leaving, if asked: retried every half second while the join settles.
    {
        const ULONGLONG Now = GetTickCount64();
        if (Now < g_leaveWorldUntil.load() && Now >= g_leaveWorldNextTry.load()) {
            g_leaveWorldNextTry.store(Now + 500);
            if (ReturnToOwnWorld() != 0) g_leaveWorldUntil.store(0);
        }
    }

    if (g_summonPending.exchange(false)) SummonOfferedSign(Manager, false);

    // Host side of the automatic join: the other player announced a sign. Look
    // for it twice a second, for up to a minute, and summon it the moment the
    // game knows it -- the joiner's sign, not whatever sign happens to be known
    // (see SummonJoinerSign). While it is not known, keep the list coming: ask
    // again every 1.5 s, one request at a time.
    if (Manager) {
        const ULONGLONG Now = GetTickCount64();
        if (g_autoSnapshotPending.exchange(false)) {
            g_autoKnownAtArmCount = ListKnownSigns(g_autoKnownAtArm, 16);
            g_autoTriedCount = 0;
            g_autoPendingId = 0;
            g_autoArmedAt = Now;
            LOG_INFO("[AUTO] %d sign(s) were known before the joiner's -- passed over at first",
                     g_autoKnownAtArmCount);
        }
        if (Now < g_autoSummonUntil.load()) {
            if (g_autoPendingId) {
                // Started: it counts once RequestSummonSign has actually gone out.
                if (DS2Coop::Hooks::GetSummonRequestCount() != g_autoPendingRequests) {
                    LOG_INFO("[AUTO] RequestSummonSign went out for 0x%08X -- summoning the other player",
                             g_autoPendingId);
                    DS2Coop::Sync::NotePartnerSummonSent();
                    g_autoPendingId = 0;
                    g_autoSummonUntil.store(0);
                } else if (Now - g_autoPendingSince > 3000) {
                    LOG_WARNING("[AUTO] no RequestSummonSign for 0x%08X in 3 s -- not the joiner's sign, trying another",
                                g_autoPendingId);
                    if (g_autoTriedCount < 16) g_autoTried[g_autoTriedCount++] = g_autoPendingId;
                    g_autoPendingId = 0;
                }
            } else if (Now >= g_autoSummonNextTry && Now >= g_autoRefusedUntil) {
                g_autoSummonNextTry = Now + 500;
                uint32_t Skip[32];
                int SkipCount = 0;
                // For the first six seconds only signs that are new since the ping.
                if (Now - g_autoArmedAt < 6000) {
                    for (int I = 0; I < g_autoKnownAtArmCount && SkipCount < 32; ++I) Skip[SkipCount++] = g_autoKnownAtArm[I];
                }
                for (int I = 0; I < g_autoTriedCount && SkipCount < 32; ++I) Skip[SkipCount++] = g_autoTried[I];
                const uint32_t RequestsBefore = DS2Coop::Hooks::GetSummonRequestCount();
                uint32_t Started = 0;
                bool JobMade = false;
                if (SummonJoinerSign(Manager, Skip, SkipCount, &Started, &JobMade) && !JobMade) {
                    // Refused here, not by the sign: the same sign again in a second, no list requests.
                    g_autoRefusedUntil = Now + 1000;
                    NoteAutoSummonRefused(Started, Now);
                } else if (Started) {
                    g_autoPendingId = Started;
                    g_autoPendingRequests = RequestsBefore;
                    g_autoPendingSince = Now;
                } else if (Now >= g_autoPollNextTry.load() && !SignListInFlight(Now)) {
                    g_autoPollNextTry.store(Now + 1500);
                    LOG_INFO("[AUTO] the joiner's sign is not in the list yet -- asking again");
                    PollSignsNow(Manager, true);
                }
            }
        }
        if (g_pollGateLogAt && Now >= g_pollGateLogAt) {
            g_pollGateLogAt = 0;
            LogPollGate(Manager);
        }

        // Joiner side: did the automatic placement produce a sign at all?
        if (g_autoPlaceCheckAt && Now >= g_autoPlaceCheckAt) {
            g_autoPlaceCheckAt = 0;
            if (DS2Coop::Hooks::GetSignCreateCount() != g_autoPlaceCreatesBefore) {
                g_autoPlaceUntil.store(0);
            } else if (Now < g_autoPlaceUntil.load()) {
                LOG_WARNING("[AUTO] the game submitted no sign here (no RequestCreateSign) -- trying again in 5 s");
                if (!g_autoPlaceWarned.exchange(true)) WarnSignNotPlaced();
                g_autoPlaceRetryAt = Now + 5000;
            }
        }
        if (g_autoPlaceRetryAt && Now >= g_autoPlaceRetryAt) {
            g_autoPlaceRetryAt = 0;
            if (Now < g_autoPlaceUntil.load()) {
                g_autoPlaceWatch.store(true);
                g_placeSignPending.store(true);
            }
        }
    }

    // Only whoever stands in a map knows the origin its sign coordinates are
    // measured against, and the other player needs it to aim a sign here.
    DS2Coop::Hooks::ShareLocalMapOrigin();
    ProbeOwnMapOrigin();
    TickProbeTakeDown(Manager);

    if (Manager && g_lastSignPoll != ULLONG_MAX) {
        const ULONGLONG Now = GetTickCount64();
        const bool Asked = g_signPollWanted.exchange(false);
        if (Asked || Now - g_lastSignPoll >= kSignPollSeconds * 1000) {
            g_lastSignPoll = Now;
            if (Asked) LOG_INFO("[PLACE] the other player placed a sign — asking for the list now");
            PollSignsNow(Manager, Asked);
        }
    }

    // While the game would decline any summon -- at a bonfire, in a menu, in an
    // event -- the sign waits: put down there, it was summoned and declined at
    // once (12.09 23:52:29, sitting at the Majula bonfire), and the server took
    // the reject badly. It goes down the moment that is over.
    uint32_t PartnerArea = 0;
    const bool WantSign = g_placeSignPending.load() || g_probeSignPending.load();
    if (Manager && g_placeSignPending.load() && !CanAimSignAtPartner(&PartnerArea)) {
        static ULONGLONG s_aimToldAt = 0;
        const ULONGLONG Now = GetTickCount64();
        if (Now - s_aimToldAt > 20000) {
            s_aimToldAt = Now;
            if (!PartnerArea) {
                LOG_INFO("[PLACE] the other player's position has not arrived yet -- the sign waits");
            } else {
                LOG_WARNING("[PLACE] map %u has no origin here, so a sign cannot be aimed into it -- the "
                            "sign waits (an unaimed sign drops the summoned player off the map)", PartnerArea);
            }
        }
    } else if (Manager && WantSign && DS2Coop::Sync::IsSummonBusy()) {
        static ULONGLONG s_busyToldAt = 0;
        const ULONGLONG Now = GetTickCount64();
        if (Now - s_busyToldAt > 20000) {
            s_busyToldAt = Now;
            LOG_INFO("[PLACE] busy (bonfire, menu or event) -- the sign waits until that is over");
            // Only for a sign the player is waiting for, not for one that measures the map.
            if (g_placeSignPending.load()) DS2Coop::Sync::WarnBusyForSign();   // elsewhere: this function has a __try
        }
    } else if (Manager && WantSign) {
        // A real sign measures the map as well, so a probe waiting beside it is dropped.
        const bool Probe = !g_placeSignPending.exchange(false);
        g_probeSignPending.store(false);
        // Submit the sign directly instead of going through exe+0x2A1410.
        //
        // That function first passes the requested type through exe+0x29C9B0,
        // which rewrites it from a table at exe+0x157AB30 of 16-byte records —
        // {source type, area (-1 = any), cell, result type}. In a region where
        // signs are not allowed the table turns the white soapstone into a type
        // that submits to nothing, which is exactly what was seen: the call
        // returned cleanly in both places and only the permitted one produced a
        // RequestCreateSign.
        //
        // The table is shared and presumably carries legitimate substitutions,
        // so it is left alone; skipping the rewrite is enough, and since the
        // call is ours to make we can simply submit the type we want.
        // exe+0x2A2780 asks exe+0x2A1BF0 first and quietly gives up if it says
        // no — which is why the previous attempt returned cleanly in a forbidden
        // region and sent nothing. The answer is silenced for the duration of
        // this one call and restored immediately, so ordinary soapstone use is
        // unaffected; the window is a few microseconds inside the sign tick,
        // on the game's own thread.
        const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
        auto Submit = reinterpret_cast<SubmitSignFn>(ExeBase + 0x2A2780);
        uint8_t Type = 1;   // white soapstone, matching sign_type in the messages

        LOG_INFO("[PLACE] calling exe+0x2A2780(manager=%p, type=%u)%s", Manager, Type,
                 Probe ? " -- a sign that only measures the map" : "");
        const bool Watch = !Probe && g_autoPlaceWatch.exchange(false);
        const uint32_t CreatesBefore = DS2Coop::Hooks::GetSignCreateCount();
        // A create that failed before (no spot, Majula) leaves the live-sign flag
        // up with no id; the game's own cleanup takes it down first, or the next
        // create would run the remove chain with a bogus spot (summon_accept.cpp).
        DS2Coop::Sync::ClearStaleLiveSign(Manager);
        const bool Silenced = StubReturnsOne(0x2A1BF0, true);
        // Where the game finds no spot for a sign (a save loaded straight into
        // Majula), the spot where the player stands is used -- this call only.
        DS2Coop::Sync::SetModSignPlacement(true);
        DS2Coop::Hooks::SetSignProbe(Probe);   // the message is built inside this call
        __try {
            Submit(Manager, &Type);
            LOG_INFO("[PLACE] returned cleanly");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("[PLACE] threw — wrong entry point or wrong arguments");
        }
        DS2Coop::Hooks::SetSignProbe(false);
        DS2Coop::Sync::SetModSignPlacement(false);
        if (Silenced) StubReturnsOne(0x2A1BF0, false);
        // A real sign replaces the manager's live one, a probe included, so only a
        // probe is taken down.
        g_probeTakeDownUntil = Probe ? GetTickCount64() + kProbeTakeDownMs : 0;
        // Where signs are not allowed the game would turn the summon down on
        // arrival; the mod's own sign is let through (summon_accept.cpp). Not for
        // a probe: nobody is meant to summon it.
        if (!Probe) DS2Coop::Sync::ArmSummonAccept();
        // An automatic placement is checked a few seconds on: a RequestCreateSign
        // must have gone out, or it is tried again (see g_autoPlaceUntil).
        if (Watch) {
            g_autoPlaceCreatesBefore = CreatesBefore;
            g_autoPlaceCheckAt = GetTickCount64() + 3000;
        }
    }

    reinterpret_cast<SignTickFn>(g_signTickOriginal)(SignId, Manager);
}

bool HookSignTick() {
    const uintptr_t ExeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    void* Target = reinterpret_cast<void*>(ExeBase + 0x2A16F0);
    if (DS2Coop::Hooks::HookManager::GetInstance().InstallHook(
            Target, reinterpret_cast<void*>(&SignTickDetour), &g_signTickOriginal)) {
        LOG_INFO("[PLACE] sign tick hooked at exe+0x2A16F0");
        return true;
    }
    LOG_WARNING("[PLACE] could not hook exe+0x2A16F0 — placing a sign by key will not work");
    return false;
}

// Stub any function to "return 1", remembering what was there.
//
// The sign predicates do not share a prologue, so the earlier fixed-byte check
// does not generalise. This keeps the original three bytes the first time it
// patches an address and puts exactly those back on the way out, which is what
// makes it safe to point at a function whose start has not been read first.
struct StubRecord { uint32_t Rva; uint8_t Original[3]; bool Saved; bool Active; };
StubRecord g_stubs[4] = {};

bool StubReturnsOne(uint32_t Rva, bool Enable) {
    StubRecord* Slot = nullptr;
    for (StubRecord& R : g_stubs) {
        if (R.Rva == Rva) { Slot = &R; break; }
        if (!Slot && R.Rva == 0) Slot = &R;
    }
    if (!Slot) return false;

    const uintptr_t Addr = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr)) + Rva;
    if (!Slot->Saved) {
        Slot->Rva = Rva;
        memcpy(Slot->Original, reinterpret_cast<void*>(Addr), 3);
        Slot->Saved = true;
    }
    if (Slot->Active == Enable) return true;

    const uint8_t Stub[3] = { 0xB0, 0x01, 0xC3 };   // MOV AL,1 ; RET
    DWORD OldProtect = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(Addr), 3, PAGE_EXECUTE_READWRITE, &OldProtect)) {
        LOG_ERROR("[SIGNGATE] VirtualProtect failed at exe+0x%X (%lu)", Rva, GetLastError());
        return false;
    }
    memcpy(reinterpret_cast<void*>(Addr), Enable ? Stub : Slot->Original, 3);
    VirtualProtect(reinterpret_cast<void*>(Addr), 3, OldProtect, &OldProtect);
    Slot->Active = Enable;
    if (Rva != 0x2A1BF0) LOG_INFO("[SIGNGATE] exe+0x%X %s", Rva, Enable ? "returns 1" : "restored");
    return true;
}

// Placing a sign is gated separately from asking for the list — stubbing
// exe+0x2A1F30 revived the poll in Majula and left the soapstone grey. Both
// exe+0x2A1F30 and exe+0x2A1FA0 ask exe+0x275E72 whether a sign type is usable,
// and that in turn asks exe+0x2919D0, so one of those two is where the item
// takes its answer from. The wrapper has eight callers and the inner one is
// unknown territory, so they are tried separately rather than together.
std::atomic<int> g_itemGateMode{ 0 };   // 0 off, 1 exe+0x275E72, 2 exe+0x2919D0

void SetSoapstoneGateMode(int Mode) {
    g_itemGateMode.store(Mode);
    StubReturnsOne(0x275E72, Mode == 1);
    StubReturnsOne(0x2919D0, Mode == 2);
}

void SetSignGateMode(int Mode) {
    g_signGateMode.store(Mode);
    StubSignPredicate(0x2A1F30, (Mode & 1) != 0);
    StubSignPredicate(0x2A1FA0, (Mode & 2) != 0);
}

void ApplyRegionForce() { }   // the region-object experiment is over

// ---------------------------------------------------------------------------
// Compare the region object either side of the boundary.
//
// The byte at playerdata+0x5E1 turned out to be a consequence: forcing it to
// the permissive value changed nothing, and it was later seen holding 0x00,
// so it is not the two-state flag the sampling made it look like.
//
// The other survivor is more useful. playerctrl+0x468 holds a pointer that
// moves by 208 bytes when the boundary is crossed — an object per region, not a
// switch. Which region the player is in is exactly what the summon rules are
// keyed on, so the field that separates a summon-friendly region from Majula is
// inside that object.
//
// Two presses: once where signs work, once where they do not. What differs
// between the two objects is the region's own description, and a read-watch on
// that field afterwards will name the code that consults it.
// ---------------------------------------------------------------------------
constexpr size_t kRegionDumpSize = 0x180;

std::vector<uint8_t> g_regionSideA;
uintptr_t            g_regionSideAPtr = 0;

bool ReadCurrentRegion(uintptr_t& OutPtr, std::vector<uint8_t>& OutBytes) {
    auto& Resolver = DS2Coop::AddressResolver::GetInstance();
    const uintptr_t GmImp = Resolver.GetGameManagerImp();
    if (!GmImp) return false;

    uintptr_t PlayerCtrl = 0;
    if (!Memory::Read<uintptr_t>(GmImp + 0xD0, &PlayerCtrl) || !PlayerCtrl) return false;
    if (!Memory::Read<uintptr_t>(PlayerCtrl + 0x468, &OutPtr) || !OutPtr) return false;

    OutBytes.assign(kRegionDumpSize, 0);
    for (size_t i = 0; i < kRegionDumpSize; i++) {
        if (!Memory::Read<uint8_t>(OutPtr + i, &OutBytes[i])) return false;
    }
    return true;
}

void RegionCompareStep() {
    uintptr_t Ptr = 0;
    std::vector<uint8_t> Bytes;
    if (!ReadCurrentRegion(Ptr, Bytes)) {
        LOG_WARNING("[REGION] cannot read the current region object");
        return;
    }

    if (g_regionSideA.empty()) {
        g_regionSideAPtr = Ptr;
        g_regionSideA = std::move(Bytes);
        LOG_INFO("[REGION] side A recorded at 0x%llX. Cross the boundary and press again.",
                 (unsigned long long)Ptr);
        return;
    }

    LOG_INFO("[REGION] side A 0x%llX vs side B 0x%llX (%s):",
             (unsigned long long)g_regionSideAPtr, (unsigned long long)Ptr,
             (Ptr == g_regionSideAPtr) ? "SAME OBJECT — did the boundary get crossed?" : "different objects");

    char line[200];
    int shown = 0;
    for (size_t i = 0; i < kRegionDumpSize; i++) {
        if (g_regionSideA[i] == Bytes[i]) continue;
        if (shown++ >= 48) { LOG_INFO("[REGION]   ...and more"); break; }
        snprintf(line, sizeof(line), "  +0x%02zX : %02X -> %02X", i, g_regionSideA[i], Bytes[i]);
        LOG_INFO("[REGION] %s", line);
    }
    if (shown == 0) LOG_INFO("[REGION]   the two objects are byte-for-byte identical");

    g_regionSideA.clear();   // next press starts a fresh pair
}

// A flag this player just wrote that the partner must not be told about: what an NPC's talk records
// about itself, and what its own follow-up event sets (21.09, point 8: "let each of us have our own
// lines -- just make the items go to whoever talks, not only to the first one"). The Emerald Herald
// gave the guest the flask, that flag reached the host through the diff, and she would not give the
// host one. Folded into the baseline, it looks like nothing changed here.
//
// It is noted under a lock of its own and folded in at the start of the next pass, before the table is
// captured: the flag setter this is called from runs while the pass can be holding g_flagSyncMutex --
// every write the game accepts notifies the world's listeners -- and taking that lock here could be
// taking it twice on one thread.
void KeepFlagLocal(uint32_t Id, bool Value) {
    {
        std::lock_guard<std::mutex> Lock(g_localFlagsMutex);
        if (g_localFlags.size() < 512) g_localFlags.emplace_back(Id, Value);
    }
    std::lock_guard<std::mutex> Mine(g_myTalkMutex);
    if (g_myTalkFlags.size() < 4096 || g_myTalkFlags.count(Id)) g_myTalkFlags[Id] = Value;
}

// The talk progress of this player's own, put back into the table it is standing in.
void PutMyTalkFlagsBack(const char* When) {
    std::map<uint32_t, bool> Mine;
    {
        std::lock_guard<std::mutex> Lock(g_myTalkMutex);
        Mine = g_myTalkFlags;
    }
    if (Mine.empty() || !GetFlagManager()) return;
    int Set = 0;
    for (const auto& Pair : Mine) {
        if (!Pair.second || ReadFlag(Pair.first)) continue;
        if (!WriteFlagQuiet(Pair.first, true)) continue;
        ++Set;
        std::lock_guard<std::mutex> Lock(g_localFlagsMutex);
        if (g_localFlags.size() < 512) g_localFlags.emplace_back(Pair.first, true);
    }
    if (Set) {
        LOG_INFO("[FLAGSYNC] %d flag(s) of my own talks put back (%s) -- the partner is not told about them",
                 Set, When);
    }
}

void ReapplyMyTalkFlagsOnArrival() {
    PutMyTalkFlagsBack("in the partner's world");
}

// Apply a flag that arrived from another player.
//
// Writes it into this client's flag table and folds it into the diff baseline
// in the same lock, so the change is not mistaken for a local one and sent
// straight back. Silently does nothing unless flag_sync=on, so a peer running
// with the feature enabled cannot alter a save whose owner left it off.
bool ApplyRemoteEventFlag(uint32_t Id, bool Value) {
    if (static_cast<FlagSyncMode>(g_flagSyncMode.load()) != FlagSyncMode::On) {
        LOG_DEBUG("[FLAGSYNC] ignoring remote flag %u=%d (flag_sync is not on)", Id, Value ? 1 : 0);
        return false;
    }

    // Only ever set. Accepting a clear would let one client's transient undo a
    // door, an item or a boss in the other's save, and flags do not legitimately
    // go back to 0 during play.
    if (!Value) {
        LOG_DEBUG("[FLAGSYNC] ignoring remote clear of flag %u", Id);
        return false;
    }

    // Queued, not written: this runs on the network thread. The tick writes it.
    std::lock_guard<std::mutex> Lock(g_flagSyncMutex);
    AbsorbIntoBaseline(Id, Value);   // so the diff does not send it straight back
    g_pendingRemoteFlags.emplace_back(Id, Value);
    LOG_INFO("[FLAGSYNC] remote flag %u=%d queued", Id, Value ? 1 : 0);
    return true;
}

// Everything this player already has set, group by group, for someone who has
// just joined. The diff above only reports what changes while both are
// connected, so without this the guest never learns about the bonfires, fog
// gates and bosses the host cleared long before.
// One group, in pieces of 640 bytes. Before 0.2.2 a group went out as one packet cut at
// 640 bytes, and groups 10 and 20 are 1250: flags 105120-109999 and 205120-209999 -- NPC
// talk progress among them -- never reached a joining guest.
size_t SendFlagGroup(uint32_t Group, const std::vector<uint8_t>& Bits) {
    size_t Set = 0;
    DS2Coop::Network::FlagBulkPacket Packet{};
    for (size_t Offset = 0; Offset < Bits.size(); Offset += sizeof(Packet.bits)) {
        Packet = DS2Coop::Network::FlagBulkPacket{};
        Packet.header.magic = 0x44533243;
        Packet.header.type = DS2Coop::Network::PacketType::FlagBulk;
        Packet.header.size = sizeof(Packet);
        Packet.header.timestamp = GetTickCount64();
        Packet.group = Group;
        Packet.offset = static_cast<uint32_t>(Offset);
        const size_t Left = Bits.size() - Offset;
        Packet.bytes = static_cast<uint32_t>(Left < sizeof(Packet.bits) ? Left : sizeof(Packet.bits));
        memcpy(Packet.bits, Bits.data() + Offset, Packet.bytes);
        for (uint32_t I = 0; I < Packet.bytes; I++) {
            for (int Bit = 0; Bit < 8; Bit++) {
                if (Packet.bits[I] & (1 << Bit)) ++Set;
            }
        }
        DS2Coop::Network::PeerManager::GetInstance().BroadcastPacket(&Packet.header);
    }
    return Set;
}

// The groups a joined guest has been handed, so a group that turns up later -- a map the
// host loads after the join -- is handed over once both stand in that map (0.2.2, second
// report point 3: a boss killed long ago stood behind its fog again for the guest, whose
// copy of that map's flags had never been told). Game thread only (the flag tick).
std::set<uint32_t> g_groupsHandedOver;

void SendFlagCatchUp() {
    if (static_cast<FlagSyncMode>(g_flagSyncMode.load()) != FlagSyncMode::On) return;
    auto Flags = CaptureFlags();
    if (Flags.empty()) {
        LOG_INFO("[FLAGSYNC] nothing to hand over yet (the flag table is not up)");
        return;
    }
    int Groups = 0;
    size_t Set = 0;
    g_groupsHandedOver.clear();
    for (const auto& G : Flags) {
        Set += SendFlagGroup(G.first, G.second);
        g_groupsHandedOver.insert(G.first);
        ++Groups;
    }
    LOG_INFO("[FLAGSYNC] handed over what is already done: %d group(s), %zu flag(s) set", Groups, Set);
}

// Host: a group loaded after the guest was handed everything, sent once both players share
// the map it belongs to -- so the guest has that map loaded too and the flags are not
// dropped as "a group this save does not have".
void HandOverNewGroups(const std::map<uint32_t, std::vector<uint8_t>>& Current) {
    if (static_cast<FlagSyncMode>(g_flagSyncMode.load()) != FlagSyncMode::On) return;
    auto& Lobby = DS2Coop::Session::SessionManager::GetInstance();
    if (!Lobby.IsActive() || !Lobby.IsHost() || g_groupsHandedOver.empty()) return;
    if (DS2Coop::Network::PeerManager::GetInstance().GetPeers().empty()) {
        g_groupsHandedOver.clear();
        return;
    }
    if (!DS2Coop::Sync::PlayersShareMap()) return;
    for (const auto& G : Current) {
        if (g_groupsHandedOver.count(G.first)) continue;
        const size_t Set = SendFlagGroup(G.first, G.second);
        g_groupsHandedOver.insert(G.first);
        LOG_INFO("[FLAGSYNC] group %u was loaded after the guest joined -- handed over now that we share a map "
                 "(%zu flag(s) set)", G.first, Set);
    }
}

bool IsProgressSharingOn() {
    return static_cast<FlagSyncMode>(g_flagSyncMode.load()) == FlagSyncMode::On;
}

void NoteRemoteFlagBulk(uint32_t group, const uint8_t* bits, uint32_t bytes, uint32_t offset) {
    if (!bits || !bytes) return;
    if (static_cast<FlagSyncMode>(g_flagSyncMode.load()) != FlagSyncMode::On) {
        LOG_DEBUG("[FLAGSYNC] ignoring a group of %u flags (flag_sync is not on)", bytes * 8);
        return;
    }
    size_t Queued = 0;
    {
        std::lock_guard<std::mutex> Lock(g_flagSyncMutex);
        for (uint32_t I = 0; I < bytes; I++) {
            if (!bits[I]) continue;
            for (int Bit = 0; Bit < 8; Bit++) {
                if (!(bits[I] & (1 << Bit))) continue;
                const uint32_t Id = group * 10000 + (offset + I) * 8 + static_cast<uint32_t>(7 - Bit);
                AbsorbIntoBaseline(Id, true);
                g_pendingRemoteFlags.emplace_back(Id, true);
                ++Queued;
            }
        }
    }
    LOG_INFO("[FLAGSYNC] group %u from the other player: %zu flag(s) queued to be set here", group, Queued);
}

// off / on, straight from the ini.
//
// "log" used to mean "watch and report, write nothing", and it was the default.
// Restez asked for progress sharing on 12.09 knowing it writes into the other
// player's save, so "log" now means on as well: leaving it as a separate mode
// would have meant both players editing their ini by hand for the feature they
// asked for. Only "off" turns it off.
void SetFlagSyncMode(const std::string& Mode) {
    FlagSyncMode Parsed = FlagSyncMode::On;
    if (Mode == "off" || Mode == "false" || Mode == "0") Parsed = FlagSyncMode::Off;
    g_flagSyncMode.store(static_cast<int>(Parsed));
    LOG_INFO("[FLAGSYNC] mode = %s%s", Mode.c_str(),
             Parsed == FlagSyncMode::On
                 ? " -- progress from the other player is written into this save (and backed up first)"
                 : " (nothing is written into this save)");
}

} // namespace DS2Coop::Sync


PlayerSync& PlayerSync::GetInstance() {
    static PlayerSync instance;
    return instance;
}

static void PatchPhantomDismissalLoops() {
    uintptr_t exeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    const uint32_t Sites[] = { 0x18E5FB, 0x18E689 };

    for (uint32_t Rva : Sites) {
        uintptr_t addr = exeBase + Rva;
        uint8_t actual[5] = {};
        __try {
            memcpy(actual, reinterpret_cast<void*>(addr), sizeof(actual));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("PatchDismissal: cannot read exe+0x%X", Rva);
            continue;
        }
        const uint8_t Nops[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
        if (memcmp(actual, Nops, sizeof(Nops)) == 0) continue;
        if (actual[0] != 0xE8) {
            LOG_WARNING("PatchDismissal: exe+0x%X expected CALL, got %02X", Rva, actual[0]);
            continue;
        }
        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(addr), sizeof(Nops), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            LOG_ERROR("PatchDismissal: VirtualProtect failed at exe+0x%X (%lu)", Rva, GetLastError());
            continue;
        }
        memcpy(reinterpret_cast<void*>(addr), Nops, sizeof(Nops));
        VirtualProtect(reinterpret_cast<void*>(addr), sizeof(Nops), oldProtect, &oldProtect);
        LOG_INFO("PatchDismissal: exe+0x%X patched", Rva);
    }
}

static void PatchPlayerCap() {
    uintptr_t exeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    struct Site { uint32_t Rva; uint8_t Expect[7]; uint8_t Replace[7]; };
    const Site Sites[] = {
        { 0x6A3B56, { 0xC7, 0x45, 0xC3, 0x03, 0x00, 0x00, 0x00 }, { 0xC7, 0x45, 0xC3, 0x06, 0x00, 0x00, 0x00 } },
        { 0x6A3BFB, { 0xC7, 0x43, 0x1C, 0x03, 0x00, 0x00, 0x00 }, { 0xC7, 0x43, 0x1C, 0x06, 0x00, 0x00, 0x00 } },
    };
    for (const Site& S : Sites) {
        uintptr_t addr = exeBase + S.Rva;
        uint8_t actual[7] = {};
        __try {
            memcpy(actual, reinterpret_cast<void*>(addr), sizeof(actual));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("PatchPlayerCap: cannot read exe+0x%X", S.Rva);
            continue;
        }
        if (memcmp(actual, S.Replace, sizeof(actual)) == 0) continue;
        if (memcmp(actual, S.Expect, sizeof(actual)) != 0) {
            LOG_WARNING("PatchPlayerCap: exe+0x%X bytes mismatch", S.Rva);
            continue;
        }
        DWORD oldProtect = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(addr), sizeof(actual), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            LOG_ERROR("PatchPlayerCap: VirtualProtect failed at exe+0x%X (%lu)", S.Rva, GetLastError());
            continue;
        }
        memcpy(reinterpret_cast<void*>(addr), S.Replace, sizeof(actual));
        VirtualProtect(reinterpret_cast<void*>(addr), sizeof(actual), oldProtect, &oldProtect);
        LOG_INFO("PatchPlayerCap: exe+0x%X patched", S.Rva);
    }
}

static bool g_debugHotkeys = false;

static bool HotkeyDown(int vk) {
    if (!g_debugHotkeys) return false;
    if (vk == DS2Coop::UI::GetMenuKey()) return false;
    // A debug key is the bare key: Alt+F4 closing the game is not F4 (19.09, it switched the world
    // items off on the way out).
    if ((GetAsyncKeyState(VK_MENU) | GetAsyncKeyState(VK_CONTROL)) & 0x8000) return false;
    return (GetAsyncKeyState(vk) & 0x8000) != 0;
}

bool PlayerSync::Initialize() {
    if (m_initialized) return true;

    LOG_INFO("Initializing player sync...");
    // Every hook below goes live in one stop of the game's threads, at the end of this function.
    DS2Coop::Hooks::HookBatch Batch;

    g_debugHotkeys = SeamlessCoopMod::GetInstance().GetConfig().debug_hotkeys;
    LOG_INFO("Debug hotkeys (F2-F11, Home, End) %s",
             g_debugHotkeys ? "ON (debug_hotkeys=true)" : "off -- set debug_hotkeys=true to use them");

    // Flag syncing is what turns two worlds into one, and it writes into this
    // player's save, so the ini decides — default "log", which only watches.
    SetFlagSyncMode(SeamlessCoopMod::GetInstance().GetConfig().flag_sync);

    // Sign relocation follows the ini too, so both players get it without one
    // of them having to remember a key.
    DS2Coop::Hooks::SetSignUnderFeet(SeamlessCoopMod::GetInstance().GetConfig().sign_under_feet);

    // Let the sign subsystem run in regions the game switches it off in.
    SetSignGateMode(1);
    HookSignTick();
    g_autoSummonEnabled.store(SeamlessCoopMod::GetInstance().GetConfig().auto_summon);

    // One player's rest resets everyone's world (world_sync.cpp).
    DS2Coop::Sync::InstallWorldSync();
    DS2Coop::Sync::SetWorldSyncEnabled(SeamlessCoopMod::GetInstance().GetConfig().rest_sync);

    // World items follow each player's own save, in any world (loot_sync.cpp).
    DS2Coop::Sync::InstallLootSync();
    DS2Coop::Sync::SetLootSyncEnabled(SeamlessCoopMod::GetInstance().GetConfig().loot_sync);

    // A sign the mod put down can be summoned even where the game takes no
    // signs (summon_accept.cpp).
    DS2Coop::Sync::InstallSummonAccept();

    DS2Coop::Sync::InstallFreeTravel(SeamlessCoopMod::GetInstance().GetConfig().free_travel);
    DS2Coop::Sync::SetBossFogWait(SeamlessCoopMod::GetInstance().GetConfig().boss_fog_wait);

    // A death no longer ends the co-op: the guest comes straight back to the
    // partner's world, and boss fights wait for both (death_sync.cpp).
    DS2Coop::Sync::InstallDeathSync(SeamlessCoopMod::GetInstance().GetConfig().death_respawn);
    DS2Coop::Sync::SetBossSyncEnabled(SeamlessCoopMod::GetInstance().GetConfig().boss_sync);
    // Damage between the players, as this player last chose it as a host
    // (pvp_modes.cpp). A guest plays by whatever its host sends.
    DS2Coop::Sync::InstallPvpModes();
    DS2Coop::Sync::InstallEstusGrant();
    DS2Coop::Sync::InstallNpcProgress(SeamlessCoopMod::GetInstance().GetConfig().npc_progress);
    DS2Coop::Sync::InstallBonfireLit();
    DS2Coop::Sync::SetDamageMode(SeamlessCoopMod::GetInstance().GetDamageModeSetting());
    // A guest's world: NPC talk, NPCs run here, characters after the host's world
    // has arrived (guest_world.cpp); travelling in a session (travel_sync.cpp);
    // covenant and summon gates for a host with a guest (mp_gates.cpp).
    {
        const auto& Cfg = SeamlessCoopMod::GetInstance().GetConfig();
        DS2Coop::Sync::InstallGuestWorld(Cfg.guest_npc_talk_scripts, Cfg.guest_npc_local, Cfg.guest_wait_for_snapshot,
                                         Cfg.enemy_states_at_join);
        DS2Coop::Sync::InstallTravelSync(Cfg.travel_resync, Cfg.enemy_detach_when_apart);
        DS2Coop::Sync::InstallDeathResultType(Cfg.guest_result_type_fix);
        DS2Coop::Sync::InstallEnemyReconcile(Cfg.enemy_dead_reconcile, Cfg.kill_counts_reconcile);
        DS2Coop::Sync::InstallBossDown(Cfg.boss_while_down);
        DS2Coop::Sync::SetJoinSlotConfirm(Cfg.join_slot_confirm);
        DS2Coop::Sync::SetGuestLiftFix(Cfg.guest_lift_fix);
        DS2Coop::Sync::SetArrivalFollowHost(Cfg.arrival_follow_host);
        DS2Coop::Sync::SetTravelPoseFix(Cfg.travel_pose_fix);
        DS2Coop::Sync::SetRestReplayFull(Cfg.rest_replay_full);
        DS2Coop::Sync::SetFlagsCarryHome(Cfg.flags_carry_home);
        DS2Coop::Sync::SetGuestNpcHitsIgnored(Cfg.guest_npc_hits_ignored);
        DS2Coop::Sync::SetNpcEventsAfterTalk(Cfg.npc_events_after_talk);
        DS2Coop::Sync::SetNpcGiftShare(Cfg.npc_gift_share);
        DS2Coop::Sync::SetMapObjectStates(Cfg.map_object_states);
        DS2Coop::Sync::SetPartnerLookRefresh(Cfg.partner_look_refresh);
        DS2Coop::Sync::SetChestLidsReconcile(Cfg.chest_lids_reconcile);
        DS2Coop::Sync::InstallBossArena(Cfg.boss_guest_starts);
        DS2Coop::Sync::InstallFarDeathCamera(Cfg.far_death_camera);
        DS2Coop::Sync::InstallMpGates(Cfg.mp_gates);
        DS2Coop::Sync::SetEffigySummon(Cfg.effigy_summon);
        DS2Coop::Sync::SetTransferEventsSolo(Cfg.transfer_events_solo);
        DS2Coop::Sync::InstallGuestDrops(true);
    }

    // A guest can talk to NPCs in the host's world (npc_talk.cpp)...
    DS2Coop::Sync::InstallNpcTalk();
    DS2Coop::Sync::SetNpcTalkEnabled(SeamlessCoopMod::GetInstance().GetConfig().npc_talk);
    // ... and sees them solid rather than as ghosts, which is the same field
    // (docs §3.24). This also makes the partner solid on a host's screen.
    DS2Coop::Sync::SetNpcSolidEnabled(SeamlessCoopMod::GetInstance().GetConfig().npc_solid);

    // What a join actually needs, captured from a normal summon: the groundwork
    // for entering a world without a sign at all (join_direct.cpp, docs §3.27).
    DS2Coop::Sync::InstallJoinProbe();

    // Map objects a session keeps local, and the probe that watches the Majula gate (map_state_act.cpp).
    DS2Coop::Sync::InstallMapStateAct(SeamlessCoopMod::GetInstance().GetConfig().map_objects_local);

    // Verify we have the GameManagerImp address
    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    if (!resolver.GetGameManagerImp()) {
        LOG_WARNING("GameManagerImp not resolved - player sync will use session data only");
    } else {
        LOG_INFO("Player sync will read from GameManagerImp at 0x%p",
                 reinterpret_cast<void*>(resolver.GetGameManagerImp()));
    }

    PatchPhantomDismissalLoops();    PatchPhantomDismissalLoops();

    // Increase player cap from 3 to 6
    PatchPlayerCap();

    // Open the bonfire interaction gate (see PatchBonfireGate).
    PatchBonfireGate();

    // Stop boss/fog scripts from treating a guest as someone to send home.
    SetScriptHostCondition(true);

    // Log every call to the predicate so its caller chain can be traced.
    HookBonfireGate();

    // Everything above is installed now -- let the world-sync detour call in.
    DS2Coop::Sync::SetWorldGameTicksReady(true);
    m_initialized = true;
    LOG_INFO("Player sync initialized");
    return true;
}

void PlayerSync::Shutdown() {
    if (!m_initialized) return;
    DS2Coop::Sync::SetWorldGameTicksReady(false);
    LOG_INFO("Shutting down player sync...");
    m_initialized = false;
}

// ============================================================================
// Read player data directly from game memory
// ============================================================================

static bool ReadPlayerDataBase(uintptr_t& outPlayerData) {
    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    uintptr_t gmImp = resolver.GetGameManagerImp();
    if (!gmImp) return false;

    // GameManagerImp -> +0x38 -> PlayerData pointer
    uintptr_t playerDataPtr = 0;
    if (!Memory::Read<uintptr_t>(gmImp + Offsets::GameManager::PlayerData, &playerDataPtr)) {
        return false;
    }

    if (!playerDataPtr) return false;
    outPlayerData = playerDataPtr;
    return true;
}

static bool ReadCharacterNameRaw(uintptr_t playerData, wchar_t* nameBuf, int maxChars) {
    __try {
        for (int i = 0; i < maxChars; i++) {
            wchar_t ch = 0;
            if (!Memory::Read<wchar_t>(playerData + Offsets::GameManager::CharacterName + i * 2, &ch))
                break;
            if (ch == 0) break;
            nameBuf[i] = ch;
        }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Try reading a wchar name from an address, convert to UTF-8. Returns "" on failure.
static std::string WcharToUtf8(const wchar_t* buf) {
    if (!buf || buf[0] == 0) return "";
    if (buf[0] < 0x20) return ""; // not printable — likely a pointer, not a name
    int len = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, &result[0], len, nullptr, nullptr);
    return result;
}

// SEH helper: read name wchars into a plain array, no C++ objects
static bool TryReadNameBuffer(uintptr_t addr, wchar_t* buf, int maxChars) {
    __try {
        for (int i = 0; i < maxChars; i++) {
            wchar_t ch = 0;
            if (!Memory::Read<wchar_t>(addr + i * 2, &ch) || ch == 0) break;
            if (ch < 0x20 || ch > 0x9FFF) return false;
            buf[i] = ch;
        }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static std::string TryReadNameFrom(uintptr_t addr, const char* source) {
    wchar_t nameBuf[32] = {};
    if (!TryReadNameBuffer(addr, nameBuf, 31)) return "";
    if (nameBuf[0] == 0) return "";
    std::string result = WcharToUtf8(nameBuf);
    if (!result.empty())
        LOG_INFO("[NAME] Character name from %s: %s", source, result.c_str());
    return result;
}

static std::string ReadCharacterName() {
    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    uintptr_t gmImp = resolver.GetGameManagerImp();
    uintptr_t netSession = resolver.GetNetSessionManager();

    // PATH 1: the name the game itself uses (exe+0x2D8400): [[GMImp+0xA8]+0xC0]+0x24, wchar_t -- YOUR
    // character's own data. The cheat tables' "GameDataManager+0x114" lies past that 0xE0-byte object and
    // only met the name because the next allocation happened to be this data.
    if (gmImp) {
        uintptr_t gdm = 0, data = 0;
        if (Memory::Read<uintptr_t>(gmImp + 0xA8, &gdm) && gdm && Memory::Read<uintptr_t>(gdm + 0xC0, &data) && data) {
            std::string name = TryReadNameFrom(data + 0x24, "PlayerGameData+0x24");
            if (!name.empty()) return name;
        }
    }

    // PATH 2: NSM → [+0x20] → +0x234 (host/opponent name — fallback only)
    if (netSession) {
        uintptr_t pp = 0;
        if (Memory::Read<uintptr_t>(netSession + 0x20, &pp) && pp) {
            std::string name = TryReadNameFrom(pp + 0x234, "NetSession+0x234");
            if (!name.empty()) return name;
        }
    }

    // PATH 3: GMImp → [+0x38] → +0x24 (PlayerData path — legacy fallback)
    if (gmImp) {
        uintptr_t pd = 0;
        if (Memory::Read<uintptr_t>(gmImp + 0x38, &pd) && pd) {
            std::string name = TryReadNameFrom(pd + 0x24, "PlayerData+0x24");
            if (!name.empty()) return name;
        }
    }

    return "";
}

static bool ReadPlayerPosition(float& x, float& y, float& z, float& rotY) {
    // PlayerCtrl+0x90, not PlayerData+0x30.
    //
    // The inherited offsets read as zeros — caught when a sign creation logged
    // "player x=0.00 y=0.00 z=0.00 rot=-nan" while the character was plainly
    // somewhere. The IDENT dump of PlayerCtrl shows the real vector:
    //
    //   +0x90:  A3 5A A9 40  FE 21 94 C1  32 14 50 43  00 00 80 3F
    //           x=5.29       y=-18.52     z=208.08     w=1.0
    //
    // and the w=1.0 tail marks it as a position rather than four loose floats.
    //
    // This is not only the sign's problem: every position this mod sends to the
    // other player came through here, so peers were being told about a character
    // at the origin, or worse — the relocation logged an owner at x=-31853,
    // which is what an untouched SessionPlayer holds.
    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    const uintptr_t gmImp = resolver.GetGameManagerImp();
    if (!gmImp) return false;

    uintptr_t playerCtrl = 0;
    if (!Memory::Read<uintptr_t>(gmImp + 0xD0, &playerCtrl) || !playerCtrl) return false;

    bool ok = true;
    ok &= Memory::Read<float>(playerCtrl + 0x90, &x);
    ok &= Memory::Read<float>(playerCtrl + 0x94, &y);
    ok &= Memory::Read<float>(playerCtrl + 0x98, &z);
    if (!Memory::Read<float>(playerCtrl + 0x88, &rotY)) rotY = 0.0f;
    return ok;
}

namespace DS2Coop::Sync {

// The first map of this player's own world after the host's: the carried flags go in while the map is
// being made, before its event scripts look at them (19.09: carried at 21:24:33, eight seconds after
// Things Betwixt had loaded at home -- the crones' making (event 16000) had already read "not made"
// (102000015) and offered the name, class and gift again at 21:25:04, and the gift was given twice).
// Nothing is marked done here: the regular pass after the tables settle finishes the job.
void CarryHostWorldFlagsHomeNow(const char* Why) {
    if (!g_carryHomeOn.load() || !g_carryHomePending || ReadJoinCtrlState() == 7) return;
    std::lock_guard<std::mutex> Lock(g_flagSyncMutex);
    if (!g_carryHomePending || g_hostWorldFlags.empty()) return;
    auto Current = CaptureFlags();
    if (Current.empty()) return;
    size_t Missing = 0, Groups = 0;
    const size_t Written = CarryHomeLocked(&Current, 4000, &Missing, &Groups);
    if (Written) {
        LOG_INFO("[FLAGSYNC] %s: %zu flag(s) of the host's world written into my own before its scripts start "
                 "(%zu groups compared)", Why, Written, Groups);
    }
}

void SetFlagsCarryHome(bool On) {
    g_carryHomeOn.store(On);
}

// The local player's world position, for code outside this file.
//
// Used when dumping a sign creation: the message carries no coordinates, so the
// only way to tell which bytes of player_struct hold the position is to compare
// them against where the player actually stood when the sign went out.
void RequestImmediateSignPoll() {
    g_signPollWanted.store(true);
}

// Joiner: the host accepted us -- put a sign down for it to summon. Goes through
// the same pending flag as F11, so the placement itself happens inside the
// sign-manager tick on the game's thread, and it is aimed under the host's feet
// by the usual rewrite on the way out.
std::atomic<ULONGLONG> g_autoPlaceLast{ 0 };

bool RequestAutoSignPlacement() {
    if (!g_autoSummonEnabled.load()) return false;
    if (DS2Coop::Session::SessionManager::GetInstance().IsHost()) return false;
    const ULONGLONG Now = GetTickCount64();
    if (Now - g_autoPlaceLast.load() < 30000) {   // one sign per handshake, not a flood
        LOG_INFO("[AUTO] joined again within 30 s of the last sign -- no new sign");
        return false;
    }
    g_autoPlaceLast.store(Now);
    // Checked a few seconds on, and tried again for two minutes if the game
    // submitted nothing (Majula takes no signs).
    g_autoPlaceUntil.store(Now + 120000);
    g_autoPlaceWarned.store(false);
    g_autoPlaceWatch.store(true);
    g_placeSignPending.store(true);
    LOG_INFO("[AUTO] joined the host -- putting a sign down for it to summon");
    return true;
}

// Leaving the lobby ends the one-sign-per-handshake wait: the next join places a sign.
void ForgetAutoSignPlacement() {
    g_autoPlaceLast.store(0);
}

// Joiner, back home after a death (or after the host's): put a sign down again
// for the host to summon -- the automatic join without its once-per-handshake
// limit. The placement and its retries are the automatic join's own.
void RequestRejoinSignPlacement() {
    if (!g_autoSummonEnabled.load()) return;
    if (DS2Coop::Session::SessionManager::GetInstance().IsHost()) return;
    g_autoPlaceUntil.store(GetTickCount64() + 120000);
    g_autoPlaceWarned.store(false);
    g_autoPlaceWatch.store(true);
    g_placeSignPending.store(true);
    LOG_INFO("[AUTO] home again -- putting a sign down to be summoned back");
}

// Host: the other player put a sign down. Keep watching for it for a minute.
void ArmAutoSummon() {
    if (!g_autoSummonEnabled.load()) return;
    if (!DS2Coop::Session::SessionManager::GetInstance().IsHost()) return;
    g_autoSnapshotPending.store(true);   // note the signs known before the joiner's
    g_autoSummonUntil.store(GetTickCount64() + 60000);
    g_autoPollNextTry.store(GetTickCount64() + 1500);   // the ping's own poll goes first
    LOG_INFO("[AUTO] the other player put a sign down -- summoning it as soon as it arrives");
}

// Leave the other player's world. Carried out in the sign tick on the game's
// thread and retried for a while in case the join has not settled yet. Any
// automatic summon is called off too: nothing should be summoned on the way out.
void RequestLeaveWorld() {
    g_autoSummonUntil.store(0);
    g_autoPlaceUntil.store(0);   // and no more sign retries
    CancelDeathRejoin();         // leaving on purpose: no automatic way back
    g_leaveLastState.store(-1);
    g_leaveWorldNextTry.store(0);
    g_leaveWorldUntil.store(GetTickCount64() + 20000);
    LOG_INFO("[LEAVE] leaving the other player's world");
}

bool GetLocalPlayerPosition(float& X, float& Y, float& Z, float& RotY) {
    return ReadPlayerPosition(X, Y, Z, RotY);
}

} // namespace DS2Coop::Sync

static bool ReadPlayerHealth(int32_t& health, int32_t& maxHealth) {
    // HP is on PlayerCtrl (GMImp+0xD0), NOT PlayerData (GMImp+0x38).
    // PlayerCtrl + 0x168 = current HP, +0x170 = max HP (SotFS, from DS2S-META).
    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    uintptr_t gmImp = resolver.GetGameManagerImp();
    if (!gmImp) return false;

    uintptr_t playerCtrl = 0;
    if (!Memory::Read<uintptr_t>(gmImp + 0xD0, &playerCtrl) || !playerCtrl) return false;

    bool ok = true;
    ok &= Memory::Read<int32_t>(playerCtrl + 0x168, &health);
    ok &= Memory::Read<int32_t>(playerCtrl + 0x170, &maxHealth);
    return ok;
}

static bool ReadPlayerLevel(uint32_t& level) {
    uintptr_t playerData = 0;
    if (!ReadPlayerDataBase(playerData)) return false;

    return Memory::Read<uint32_t>(playerData + Offsets::GameManager::Level, &level);
}

static bool ReadPlayerStamina(float& stamina) {
    uintptr_t playerData = 0;
    if (!ReadPlayerDataBase(playerData)) return false;

    return Memory::Read<float>(playerData + Offsets::GameManager::Stamina, &stamina);
}

// ============================================================================
// Sync update loop
// ============================================================================

void PlayerSync::Update(float deltaTime) {
    if (!m_initialized) return;

    __try {
        m_positionSyncTimer += deltaTime;
        m_stateSyncTimer += deltaTime;

        if (m_positionSyncTimer >= POSITION_SYNC_INTERVAL) {
            SyncLocalPlayerPosition();
            m_positionSyncTimer = 0.0f;
        }

        if (m_stateSyncTimer >= STATE_SYNC_INTERVAL) {
            SyncLocalPlayerState();
            m_stateSyncTimer = 0.0f;
        }

        // The partner is told my character's name whenever it changes (report 8 of 21.09 evening).
        TellPartnerMyName();

        // Event flag diff. Rate-limits itself to once a second and does nothing
        // at all unless the ini turned it on.
        FlagSyncTick();

        // Hold the region byte permissive if asked, since the game rewrites it
        // as the player moves.
        ApplyRegionForce();

        // The "phantom timer" of the old code is gone (19.09, the host's crash at exe+0x2C6DA9): it wrote
        // 99999.0f to [[net root]+0x18]+0x17C every 5 s, but [net root+0x18] is the multiplayer manager,
        // 0x100 bytes (exe+0x513BE0 allocates it for exe+0x2C5810), so the float landed 0x7C bytes past
        // it -- in the host's run on the high half of the manager pointer itself (0x47C34F80'2AA60FE0),
        // and the next read of that pointer crashed. A phantom's time is counted elsewhere
        // (exe+0x25F830 -> exe+0x51C540, per player slot); the write never reached it.

        // Keep permission patches active every 1s — bonfire bits are checked
        // every frame by the game, so 5s gaps cause intermittent blocking.
        static float s_summoningTimer = 0.0f;
        s_summoningTimer += deltaTime;
        if (s_summoningTimer >= 1.0f) {
            EnableSummoning();
            s_summoningTimer = 0.0f;
        }

        // F4: world items from your own save, on and off (loot_sync.cpp). In
        // someone else's world, on shows every item your save has not picked up
        // and off takes them away again -- the inversion that proves the fix.
        // (It used to snapshot the event flags; flag sync logs on its own now.)
        static bool s_f4WasDown = false;
        const bool f4Down = HotkeyDown(VK_F4);
        if (f4Down && !s_f4WasDown) DS2Coop::Sync::ToggleLootSyncNow();
        s_f4WasDown = f4Down;

        static bool s_f5WasDown = false, s_lastFlagValue = false;
        const bool f5Down = HotkeyDown(VK_F5);
        if (f5Down && !s_f5WasDown && g_lastFlagId) {
            s_lastFlagValue = !s_lastFlagValue;
            WriteFlag(g_lastFlagId, s_lastFlagValue);
        }
        s_f5WasDown = f5Down;

        static bool s_f6WasDown = false, s_scriptStub = true;
        const bool f6Down = HotkeyDown(VK_F6);
        if (f6Down && !s_f6WasDown) {
            s_scriptStub = !s_scriptStub;
            SetScriptHostCondition(s_scriptStub);
        }
        s_f6WasDown = f6Down;

        static bool s_f2WasDown = false;
        const bool f2Down = HotkeyDown(VK_F2);
        if (f2Down && !s_f2WasDown) {
            g_summonPending.store(true);
            LOG_INFO("[SUMMON] queued");
        }
        s_f2WasDown = f2Down;

        // F3: put an incoming summon sign under my feet instead of where it
        // was placed. Off at startup — a wrong rewrite would break summoning,
        // so it is switched on deliberately and can be switched straight back.
        // No local copy of the state: a function-local static with a dynamic
        // initialiser cannot live in a function that uses __try, and the hook
        // already owns the flag anyway.
        static bool s_f3WasDown = false;
        const bool f3Down = HotkeyDown(VK_F3);
        if (f3Down && !s_f3WasDown) {
            DS2Coop::Hooks::SetSignUnderFeet(!DS2Coop::Hooks::GetSignUnderFeet());
        }
        s_f3WasDown = f3Down;

        // F11 used to fake being in a session at the bonfire registration gate,
        // which is long settled. It now compares the region object either side
        // of the boundary: press where signs work, then where they do not.
        // F11 cycles the two candidates for the soapstone's own gate.
        // F11 asks for a sign to be placed here, soapstone or not. The request
        // is only a flag: the call itself happens inside the sign-manager tick,
        // on the game's own thread.
        static bool s_f11WasDown = false;
        const bool f11Down = HotkeyDown(VK_F11);
        if (f11Down && !s_f11WasDown) {
            if (!g_signManager.load()) {
                LOG_WARNING("[PLACE] sign manager not seen yet — is the game in a world?");
            } else {
                g_placeSignPending.store(true);
                LOG_INFO("[PLACE] queued");
            }
        }
        s_f11WasDown = f11Down;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("PlayerSync::Update CRASHED (exception 0x%08X) — disabling sync",
                  GetExceptionCode());
        m_initialized = false;
    }
}

// ============================================================================
// Position sync - reads ACTUAL game memory
// ============================================================================
void PlayerSync::SyncLocalPlayerPosition() {
    auto& sessionMgr = Session::SessionManager::GetInstance();
    if (!sessionMgr.IsActive()) return;

    // Copy local player data under lock to avoid racing with network thread
    auto players = sessionMgr.GetPlayers();
    Session::SessionPlayer* localPlayer = nullptr;
    uint64_t localId = Network::PeerManager::GetInstance().GetLocalPlayerId();
    for (auto& p : players) {
        if (p.playerId == localId) { localPlayer = &p; break; }
    }
    if (!localPlayer) return;

    float x = 0, y = 0, z = 0, rotY = 0;

    // Try reading from actual game memory first
    if (ReadPlayerPosition(x, y, z, rotY)) {
        // Store back to session manager (the copy is discarded, so write directly)
        sessionMgr.UpdatePlayerPosition(localId, x, y, z);
    } else {
        x = localPlayer->x;
        y = localPlayer->y;
        z = localPlayer->z;
        //LOG_DEBUG("Could not read player position from game memory, using cached");
    }

    // Build and broadcast position packet
    static uint32_t posSequence = 0;
    Network::PlayerPositionPacket packet{};
    packet.header.magic = 0x44533243;
    packet.header.type = Network::PacketType::PlayerPosition;
    packet.header.size = sizeof(Network::PlayerPositionPacket);
    packet.header.sequence = ++posSequence;
    packet.header.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    packet.playerId = localPlayer->playerId;
    // Which map I am in, so the other side can aim a summon sign at me even
    // when we are not in the same one.
    packet.onlineAreaId = DS2Coop::Hooks::GetLocalAreaId();
    packet.x = x;
    packet.y = y;
    packet.z = z;
    packet.rotX = 0.0f;
    packet.rotY = rotY;
    packet.rotZ = 0.0f;
    packet.animation = 0;

    auto& peerMgr = Network::PeerManager::GetInstance();
    peerMgr.BroadcastPacket(&packet.header);

    //LOG_DEBUG("Synced position: (%.2f, %.2f, %.2f)", x, y, z);
}

// ============================================================================
// State sync - reads ACTUAL game memory
// ============================================================================
void PlayerSync::SyncLocalPlayerState() {
    auto& sessionMgr = Session::SessionManager::GetInstance();
    if (!sessionMgr.IsActive()) return;

    auto players = sessionMgr.GetPlayers();
    Session::SessionPlayer* localPlayer = nullptr;
    uint64_t localId = Network::PeerManager::GetInstance().GetLocalPlayerId();
    for (auto& p : players) {
        if (p.playerId == localId) { localPlayer = &p; break; }
    }
    if (!localPlayer) return;

    int32_t health = 0, maxHealth = 0;
    float stamina = 0;
    uint32_t soulLevel = 0;

    // Read actual values from game memory
    bool gotHealth = ReadPlayerHealth(health, maxHealth);
    bool gotLevel = ReadPlayerLevel(soulLevel);
    ReadPlayerStamina(stamina);

    if (gotHealth) {
        sessionMgr.UpdatePlayerHealth(localId, health, maxHealth);
    } else {
        health = localPlayer->health;
        maxHealth = localPlayer->maxHealth;
    }

    if (gotLevel) {
        sessionMgr.UpdatePlayerLevel(localId, soulLevel);
    } else {
        soulLevel = localPlayer->soulLevel;
    }

    // Build and broadcast state packet
    Network::PlayerStatePacket packet{};
    packet.header.magic = 0x44533243;
    packet.header.type = Network::PacketType::PlayerState;
    packet.header.size = sizeof(Network::PlayerStatePacket);
    packet.header.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    packet.playerId = localPlayer->playerId;
    packet.health = health;
    packet.maxHealth = maxHealth;
    packet.stamina = static_cast<int32_t>(stamina);
    packet.maxStamina = 100;
    packet.souls = 0;
    packet.soulLevel = soulLevel;

    auto& peerMgr = Network::PeerManager::GetInstance();
    peerMgr.BroadcastPacket(&packet.header);

    //LOG_DEBUG("Synced state: HP %d/%d, SL %u", health, maxHealth, soulLevel);
}

// ============================================================================
// Remote player updates (from network)
// ============================================================================

void PlayerSync::ApplyRemotePlayerPosition(uint64_t playerId, float x, float y, float z,
                                           float rotX, float rotY, float rotZ) {
    //LOG_DEBUG("Remote player position: (%.2f, %.2f, %.2f)", playerId, x, y, z);
    auto& sessionMgr = Session::SessionManager::GetInstance();
    sessionMgr.UpdatePlayerPosition(playerId, x, y, z);
}

void PlayerSync::ApplyRemotePlayerState(uint64_t playerId, int32_t health, int32_t maxHealth,
                                        int32_t stamina, int32_t maxStamina) {
    //LOG_DEBUG("Remote player state: HP %d/%d", playerId, health, maxHealth);
    auto& sessionMgr = Session::SessionManager::GetInstance();
    sessionMgr.UpdatePlayerHealth(playerId, health, maxHealth);
}

void PlayerSync::SyncAnimation(uint64_t playerId, uint32_t animationId) {
    LOG_DEBUG("Animation sync for player %llu: %u", playerId, animationId);
}

void PlayerSync::SyncEquipment(uint64_t playerId) {
    LOG_DEBUG("Equipment sync for player %llu", playerId);
}

// ============================================================================
// Item struct for the game's internal ItemGive function (16 bytes)
// ============================================================================
#pragma pack(push, 1)
struct DS2ItemStruct {
    int32_t  type;       // 3 = consumable
    int32_t  itemId;     // e.g. 0x03B280B0
    float    durability; // FLT_MAX
    int16_t  quantity;   // count
    uint8_t  upgrade;    // 0-10
    uint8_t  infusion;   // 0 = none
};
#pragma pack(pop)

// x64 fastcall: void ItemGive(void* bag, DS2ItemStruct* items, int count, int mode)
typedef void (__fastcall *ItemGiveFunc)(void* bag, DS2ItemStruct* items, int count, int mode);
static ItemGiveFunc g_itemGiveFunc = nullptr;
static bool g_itemGiveScanned = false;

// ============================================================================
// Resolve the ItemGive function and AvailableItemBag pointer
// ============================================================================
static bool ResolveItemGive(uintptr_t& outBag) {
    // Find ItemGive function via AOB (only scan once)
    if (!g_itemGiveScanned) {
        g_itemGiveScanned = true;
        uintptr_t addr = DS2Coop::Utils::PatternScanner::FindPattern(
            ItemGib::ITEM_GIVE_PATTERN,
            ItemGib::ITEM_GIVE_MASK,
            nullptr);
        if (addr) {
            g_itemGiveFunc = reinterpret_cast<ItemGiveFunc>(addr);
            LOG_INFO("ItemGive function found at %p", reinterpret_cast<void*>(addr));
        } else {
            LOG_WARNING("ItemGive function not found — soapstone grant unavailable");
        }
    }

    if (!g_itemGiveFunc) return false;

    // Resolve AvailableItemBag: [BaseA] -> +0xA8 -> +0x10 -> +0x10
    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    uintptr_t baseA = resolver.GetGameManagerImp();
    if (!baseA) { LOG_WARNING("ResolveItemGive: BaseA is null"); return false; }

    uintptr_t ptr1 = 0, ptr2 = 0, bag = 0;
    if (!Memory::Read<uintptr_t>(baseA + ItemGib::AvailItemBag_Off1, &ptr1) || !ptr1) {
        LOG_WARNING("ResolveItemGive: ptr1 failed (BaseA=%p +0x%X)", (void*)baseA, ItemGib::AvailItemBag_Off1);
        return false;
    }
    if (!Memory::Read<uintptr_t>(ptr1 + ItemGib::AvailItemBag_Off2, &ptr2) || !ptr2) {
        LOG_WARNING("ResolveItemGive: ptr2 failed (ptr1=%p +0x%X)", (void*)ptr1, ItemGib::AvailItemBag_Off2);
        return false;
    }
    if (!Memory::Read<uintptr_t>(ptr2 + ItemGib::AvailItemBag_Off3, &bag) || !bag) {
        LOG_WARNING("ResolveItemGive: bag failed (ptr2=%p +0x%X)", (void*)ptr2, ItemGib::AvailItemBag_Off3);
        return false;
    }

    LOG_INFO("ResolveItemGive: BaseA=%p -> ptr1=%p -> ptr2=%p -> bag=%p",
             (void*)baseA, (void*)ptr1, (void*)ptr2, (void*)bag);
    outBag = bag;
    return true;
}

// ============================================================================
// Grant White Sign Soapstone + Small White Sign Soapstone
// Calls the game's internal ItemGive function
// ============================================================================
bool PlayerSync::GrantSoapstones() {
    uintptr_t bag = 0;
    if (!ResolveItemGive(bag)) {
        LOG_WARNING("GrantSoapstones: could not resolve ItemGive or AvailableItemBag");
        return false;
    }

    DS2ItemStruct items[2] = {};

    // White Sign Soapstone
    items[0].type       = ItemCategory::Consumable;
    items[0].itemId     = ItemIDs::WhiteSignSoapstone;
    items[0].durability = FLT_MAX;
    items[0].quantity   = 1;
    items[0].upgrade    = 0;
    items[0].infusion   = 0;

    // Small White Sign Soapstone
    items[1].type       = ItemCategory::Consumable;
    items[1].itemId     = ItemIDs::SmallWhiteSignSoapstone;
    items[1].durability = FLT_MAX;
    items[1].quantity   = 1;
    items[1].upgrade    = 0;
    items[1].infusion   = 0;

    LOG_INFO("GrantSoapstones: calling ItemGive at %p with bag=%p, 2 items",
             reinterpret_cast<void*>(g_itemGiveFunc), reinterpret_cast<void*>(bag));

    __try {
        // Give items one at a time to isolate which one crashes (if any)
        g_itemGiveFunc(reinterpret_cast<void*>(bag), &items[0], 1, 0);
        LOG_INFO("GrantSoapstones: White Sign Soapstone given");

        g_itemGiveFunc(reinterpret_cast<void*>(bag), &items[1], 1, 0);
        LOG_INFO("GrantSoapstones: Small White Sign Soapstone given");

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("GrantSoapstones: ItemGive crashed (exception 0x%08X)",
                  GetExceptionCode());
        // Disable further attempts
        g_itemGiveFunc = nullptr;
        return false;
    }
}

// ============================================================================
// Enable summoning regardless of hollow state, and force host-equivalent
// permissions for all players (bonfire, NPC, chest, fog wall access).
// Runs every 5 seconds while seamless is active.
// ============================================================================
void PlayerSync::EnableSummoning() {
    // Throttled diagnostics: this function runs once per second, so every
    // branch below logs at most once per 10s. Without this the function
    // returns silently and the log gives no clue why permissions never
    // got patched (chests/bonfire still blocked for the guest).
    static ULONGLONG s_lastDiag = 0;
    ULONGLONG nowTick = GetTickCount64();
    const bool diag = (nowTick - s_lastDiag) >= 10000;
    if (diag) s_lastDiag = nowTick;

    if (!DS2Coop::Hooks::ProtobufHooks::IsSeamlessActive()) {
        if (diag) LOG_INFO("[PERM] SKIP: seamless not active (no mod session established)");
        return;
    }

    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    uintptr_t gmImp = resolver.GetGameManagerImp();
    if (!gmImp) {
        if (diag) LOG_INFO("[PERM] SKIP: GameManagerImp not resolved");
        return;
    }

    if (diag) LOG_INFO("[PERM] running (GMImp=0x%llX)", (unsigned long long)gmImp);

    // ==========================================================================
    // 1. The old "TeamType" poke, narrowed to the one field it always hit.
    //
    // The inherited code scanned 64 KB of three objects for the first uint16
    // equal to 513 and kept zeroing it. It was retired as a blind write -- and
    // in the very next session the host's automatic summon stalled (the job
    // started, RequestSummonSign never went out). In every earlier session, on
    // both machines, the scan had landed on the same field: +0x1374 of the first
    // object it searches, value 513, even on a host in his own world -- so it is
    // not TeamType. Until an on/off test says whether it matters, that exact
    // field is zeroed again, and only while it holds 513-516; nothing else is
    // scanned or written.
    // ==========================================================================
    __try {
        static uintptr_t s_legacyField = 0;
        if (!s_legacyField) {
            uintptr_t Bases[3] = {};
            Memory::Read<uintptr_t>(gmImp + 0x38, &Bases[0]);
            uintptr_t Npm = 0;
            if (Memory::Read<uintptr_t>(gmImp + 0x10, &Npm) && Npm) {
                Bases[1] = Npm;
                Memory::Read<uintptr_t>(Npm + 0x18, &Bases[2]);
            }
            for (int B = 0; B < 3 && !s_legacyField; B++) {
                uint16_t Val = 0;
                if (Bases[B] && Memory::Read<uint16_t>(Bases[B] + 0x1374, &Val) && Val >= 513 && Val <= 516) {
                    s_legacyField = Bases[B] + 0x1374;
                    LOG_INFO("[PERM] legacy field at 0x%llX (object %d +0x1374) holds %u -- zeroing it as the old code did",
                             (unsigned long long)s_legacyField, B, (unsigned)Val);
                }
            }
        }
        if (s_legacyField) {
            uint16_t Val = 0;
            if (!Memory::Read<uint16_t>(s_legacyField, &Val)) {
                s_legacyField = 0;
            } else if (Val >= 513 && Val <= 516) {
                Memory::Write<uint16_t>(s_legacyField, (uint16_t)0);
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}

    // ==========================================================================
    // 2. Hollowing → human form, so summon signs work without effigies.
    //
    // The earlier attempt wrote a uint32 to PlayerCtrl+0x1AC and crashed the
    // game. That address is SP (stamina) — hence the bogus 244 that was read.
    // Verified against DS2S-META (Nordgaren/DS2S-META, Util/DS2SOffsets.cs +
    // DS2SHook.cs) the real chain is:
    //
    //   BaseA (= GameManagerImp) -> [+0xD0] PlayerCtrl
    //                            -> [+0x490] PlayerParam
    //                            -> +0x1AC HollowLevel  (ONE BYTE)
    //
    //   PlayerCtrl  = CreateChildPointer(BaseA,      PlayerCtrlOffset  = 0xD0)
    //   PlayerParam = CreateChildPointer(PlayerCtrl, PlayerParamOffset = 0x490)
    //   HollowLevel = PlayerParam.ReadByte(0x1AC)
    //
    // HollowLevel 0 == human form, which is the state the game requires before
    // it will let you place or use a summon sign.
    // ==========================================================================
    __try {
        uintptr_t playerCtrl = 0, playerParam = 0;
        if (!Memory::Read<uintptr_t>(gmImp + 0xD0, &playerCtrl) || !playerCtrl) {
            if (diag) LOG_INFO("[PERM] hollow: PlayerCtrl ([GMImp+0xD0]) is null");
        } else if (!Memory::Read<uintptr_t>(playerCtrl + 0x490, &playerParam) || !playerParam) {
            if (diag) LOG_INFO("[PERM] hollow: PlayerParam ([PlayerCtrl+0x490]) is null");
        } else {
            uint8_t hollow = 0;
            if (!Memory::Read<uint8_t>(playerParam + 0x1AC, &hollow)) {
                if (diag) LOG_INFO("[PERM] hollow: read failed at [[GMImp+0xD0]+0x490]+0x1AC");
            } else if (hollow != 0) {
                Memory::Write<uint8_t>(playerParam + 0x1AC, (uint8_t)0);
                LOG_INFO("EnableSummoning: HollowLevel %u -> 0 (human form) — summoning no longer needs an effigy",
                         (unsigned)hollow);
            } else if (diag) {
                LOG_INFO("[PERM] hollow level already 0 — human form, summoning allowed");
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        if (diag) LOG_INFO("[PERM] hollow: exception while patching");
    }

    // ==========================================================================
    // 3. Phantom field — Bob Edition CT: NetSessionManager → [+0x20] → +0x1F4
    //
    // This is the field the game checks to determine if the local player is a
    // phantom. Zeroing it makes the game treat the local player as the host
    // for permission checks (bonfire, NPC, chest, fog wall).
    // ==========================================================================
    uintptr_t netSession = resolver.GetNetSessionManager();
    if (!netSession) {
        if (diag) LOG_INFO("[PERM] phantom field: NetSessionManager not resolved");
    } else {
        __try {
            uintptr_t playerPtr = 0;
            if (Memory::Read<uintptr_t>(netSession + Offsets::NetSession::PlayerPointer, &playerPtr) && playerPtr) {
                uint32_t phantomField = 0;
                if (Memory::Read<uint32_t>(playerPtr + 0x1F4, &phantomField)) {
                    if (phantomField != 0) {
                        Memory::Write<uint32_t>(playerPtr + 0x1F4, (uint32_t)0);
                        LOG_INFO("EnableSummoning: Phantom field zeroed (was %u) via [NSM+0x20]+0x1F4", phantomField);
                    } else if (diag) {
                        LOG_INFO("[PERM] phantom field already 0 — host-equivalent permissions active");
                    }
                } else if (diag) {
                    LOG_INFO("[PERM] phantom field: read failed at [NSM+0x20]+0x1F4");
                }
            } else if (diag) {
                LOG_INFO("[PERM] phantom field: [NSM+0x20] (player pointer) is null — not in a session yet");
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            if (diag) LOG_INFO("[PERM] phantom field: exception while patching");
        }
    }

    // ==========================================================================
    // 4. Session-slot TeamType — DISABLED: value 127 at [NSM+0x20][+0x1E8][slot*8][+0xB0]+0x4D
    // is not TeamType — wrong pointer chain. Zeroing it corrupted game state → crash.
    // Needs CE re-verification before re-enabling.
    // ==========================================================================

    // ==========================================================================
    // 5. Bonfire access bits — Bob Edition CT:
    //    GameManagerImp → [+0xD0] → [+0xB8] → +0x4C8, bits 4+5
    //
    // bit 4 = isBonfireStart, bit 5 = isBonfireLoop.
    // The host bonfire restriction checks phantom count > 0. Separately,
    // the phantom-side restriction checks these bits. Setting both forces
    // the game to allow bonfire interaction regardless of session state.
    // ==========================================================================
    __try {
        uintptr_t ptr_d0 = 0, ptr_b8 = 0;
        if (Memory::Read<uintptr_t>(gmImp + 0xD0, &ptr_d0) && ptr_d0) {
            // What actions is the game currently offering, and are any disabled?
            //
            // exe+0x456430 picks the offered action by walking the list at
            // owner+0x23C (count at +0x2BC) and taking the first id whose slot
            // (owner+0x34 + (id & 0x1F)*0x10) is live and whose byte at +0xE is
            // zero — that byte disables an entry. Printing the list plus those
            // bytes says whether a guest's bonfire action is disabled or simply
            // never registered, which are two very different fixes.
            {
                const uintptr_t exeB = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
                uintptr_t g = 0, s70 = 0, owner = 0;
                if (Memory::Read<uintptr_t>(exeB + 0x16148F0, &g) && g &&
                    Memory::Read<uintptr_t>(g + 0x70, &s70) && s70 &&
                    Memory::Read<uintptr_t>(s70 + 0x18, &owner) && owner) {
                    uint32_t count = 0, chosen = 0;
                    Memory::Read<uint32_t>(owner + 0x2BC, &count);
                    Memory::Read<uint32_t>(owner + 0x234, &chosen);

                    char line[512];
                    int used = snprintf(line, sizeof(line), "chosen=0x%X count=%u |", chosen, count);
                    if (count > 32) count = 32;
                    for (uint32_t i = 0; i < count && used > 0 && used < (int)sizeof(line) - 40; i++) {
                        uint32_t id = 0;
                        if (!Memory::Read<uint32_t>(owner + 0x23C + i * 4, &id)) break;

                        uintptr_t slot = owner + 0x34 + (id & 0x1F) * 0x10;
                        uint32_t slotId = 0;
                        uint8_t type = 0, disabled = 0;
                        Memory::Read<uint32_t>(slot, &slotId);
                        Memory::Read<uint8_t>(slot + 0xD, &type);
                        Memory::Read<uint8_t>(slot + 0xE, &disabled);

                        used += snprintf(line + used, sizeof(line) - used,
                                         " id=0x%X%s(type=%u off=%u)", id,
                                         slotId == id ? "" : "!", type, disabled);
                    }
                    // Only when the list changes: once a second it was 6500-8800 lines a session.
                    static char s_lastActions[512] = {};
                    if (strcmp(s_lastActions, line) != 0) {
                        strncpy_s(s_lastActions, sizeof(s_lastActions), line, _TRUNCATE);
                        LOG_INFO("[ACTIONS] %s", line);
                    }
                }
            }

            // Which object is the player looking at? The interaction manager
            // (exe+0x32A200, case 0) takes it from [[PlayerCtrl+0xE8]+0x18] and
            // asks it, via vftable slot +0x98, which action it offers. For a
            // guest a bonfire answers "light torch" instead of "rest" — so the
            // phantom check lives inside that method. Logging the object's
            // vftable tells us its class, and thereby which method to read.
            if (diag) {
                uintptr_t targeting = 0, target = 0, vtable = 0;
                const uintptr_t exeBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
                if (Memory::Read<uintptr_t>(ptr_d0 + 0xE8, &targeting) && targeting &&
                    Memory::Read<uintptr_t>(targeting + 0x18, &target) && target &&
                    Memory::Read<uintptr_t>(target, &vtable) && vtable > exeBase) {
                    LOG_INFO("[TARGET] object 0x%llX vftable exe+0x%llX",
                             (unsigned long long)target, (unsigned long long)(vtable - exeBase));
                } else {
                    LOG_INFO("[TARGET] no interactable in focus");
                }
            }
            if (Memory::Read<uintptr_t>(ptr_d0 + 0xB8, &ptr_b8) && ptr_b8) {
                uint32_t flags = 0;
                if (Memory::Read<uint32_t>(ptr_b8 + 0x4C8, &flags)) {
                    uint32_t newFlags = flags | (1u << 4) | (1u << 5);
                    if (newFlags != flags) {
                        Memory::Write<uint32_t>(ptr_b8 + 0x4C8, newFlags);
                        LOG_INFO("EnableSummoning: isBonfireStart/Loop bits set (0x%X -> 0x%X)", flags, newFlags);
                    } else if (diag) {
                        LOG_INFO("[PERM] bonfire bits already set (0x%X) — bonfire access should be open", flags);
                    }
                } else if (diag) {
                    LOG_INFO("[PERM] bonfire bits: read failed at [GMImp+0xD0][+0xB8]+0x4C8");
                }
            } else if (diag) {
                LOG_INFO("[PERM] bonfire bits: [GMImp+0xD0]+0xB8 is null");
            }

            // ==========================================================================
            // 4. ChrNetworkPhantomId — Bob Edition CT:
            //    GameManagerImp → [+0xD0] → [+0xB0] → +0x3C (byte)
            //
            // This byte controls phantom rendering (ghostly white appearance).
            // 0 = normal player rendering, non-zero = phantom appearance.
            // Zeroing it makes all players appear as solid/normal.
            // ==========================================================================

            // These identity fields are the phantom's own view of itself.
            // Rewriting them while the join is still settling -- the join
            // controller below state 7 -- is the likeliest reason the game gave
            // up on a summon right after arrival ("summon cancelled"): on the
            // failed attempt they flipped the same second the world loaded, and
            // the join never reached RequestNotifyJoinSession. So they wait.
            int JoinState = -1;
            {
                const uintptr_t ExeB = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
                uintptr_t Net = 0, Mp = 0, Ctrl = 0, Vtbl = 0;
                if (Memory::Read<uintptr_t>(ExeB + 0x1616CF8, &Net) && Net &&
                    Memory::Read<uintptr_t>(Net + 0x18, &Mp) && Mp &&
                    Memory::Read<uintptr_t>(Mp + 0x40, &Ctrl) && Ctrl &&
                    Memory::Read<uintptr_t>(Ctrl, &Vtbl) && Vtbl == ExeB + 0x10D7BD8) {
                    Memory::Read<int>(Ctrl + 0xF8, &JoinState);
                }
            }
            const bool JoinSettling = JoinState >= 0 && JoinState < 7;
            static int s_joinLogged = -2;
            if (JoinSettling && s_joinLogged != JoinState) {
                LOG_INFO("[PERM] joining (join controller state %d) -- phantom identity left alone until it settles",
                         JoinState);
            }
            s_joinLogged = JoinSettling ? JoinState : -2;

            // Nor during a load, or in the first 2 s after one. The death result a map
            // load builds reads the phantom id once (exe+0x191BB0 -> exe+0x18F2E0, kept
            // at +0xE0) and picks the death branch by it: 0 is the host's, which waits
            // for as long as any session exists. A guest's own travel keeps join state 7,
            // so the zeroing below could land between the game setting the id and that
            // read -- on 17.09 at 14:44:02 it did ("zeroed (was 1)" in the second of the
            // arrival), and the guest's next death at 14:45:49 left it watching the
            // partner's camera until it left the lobby (0.2.2 point 3).
            static ULONGLONG s_standingSince = 0;
            {
                int32_t GameState = 0;
                uint8_t WarpFlags = 0;
                const bool StandingNow = Memory::Read<int32_t>(gmImp + 0x24AC, &GameState) && GameState == 0x1E &&
                                         Memory::Read<uint8_t>(gmImp + 0x24B1, &WarpFlags) && !(WarpFlags & 0x02);
                if (!StandingNow) s_standingSince = 0;
                else if (!s_standingSince) s_standingSince = nowTick;
            }
            const bool LoadSettled = s_standingSince && nowTick - s_standingSince >= 2000;

            uintptr_t ptr_b0 = 0;
            if (!JoinSettling && LoadSettled && Memory::Read<uintptr_t>(ptr_d0 + 0xB0, &ptr_b0) && ptr_b0) {
                uint8_t phantomId = 0;
                if (Memory::Read<uint8_t>(ptr_b0 + 0x3C, &phantomId) && phantomId != 0) {
                    Memory::Write<uint8_t>(ptr_b0 + 0x3C, (uint8_t)0);
                    LOG_INFO("EnableSummoning: ChrNetworkPhantomId zeroed (was %u) — solid appearance", phantomId);
                }

                // ==============================================================
                // Identity struct hunt.
                //
                // The documented "permission" pokes (phantom field at
                // [NSM+0x20]+0x1F4, bonfire bits at [[GMImp+0xD0]+0xB8]+0x4C8)
                // demonstrably do nothing: the phantom field reads 0 even on a
                // summoned phantom, and the bonfire "flags" change value between
                // reads, so that chain does not point at a stable field.
                //
                // So dump PlayerType ([[GMImp+0xD0]+0xB0], the struct holding
                // ChrNetworkPhantomId/TeamType/CharType per DS2S-META) on both
                // machines. Whatever byte differs between the host and the
                // summoned guest is the real marker the game tests before it
                // allows bonfires, chests and pickups.
                // ==============================================================
                // Once per join state rather than every ten seconds: the identity hunt this served is
                // long over (docs §3.24), and its eight lines were 5600-7900 lines a session.
                static int s_identJoin = -100;
                const bool IdentDue = diag && s_identJoin != JoinState;
                if (IdentDue) s_identJoin = JoinState;
                if (IdentDue) {
                    // Comparing two different players is too noisy — position,
                    // stamina and timers differ constantly. What actually
                    // identifies the marker is watching ONE client across the
                    // moment it gets summoned: the byte that flips from "my own
                    // world" to "guest in someone else's world" is the flag the
                    // game tests for bonfires/chests/pickups.
                    //
                    // So dump the three structs that could plausibly hold it and
                    // diff the same log before vs after the summon.
                    struct DumpRegion { const char* Name; uintptr_t Base; uint32_t Start; uint32_t Size; };

                    uintptr_t nsmPlayer = 0;
                    uintptr_t nsm = resolver.GetNetSessionManager();
                    if (nsm) {
                        Memory::Read<uintptr_t>(nsm + Offsets::NetSession::PlayerPointer, &nsmPlayer);
                    }

                    // Wider sweep: the marker that gates bonfires/pickups is not
                    // in PlayerType (that one only drives team + appearance) and
                    // not in the NetSession fields (zeroing those kills the
                    // session outright). So dump much more of PlayerCtrl and the
                    // sibling structs hanging off BaseA, and diff the same client
                    // before vs after a summon again.
                    uintptr_t playerName = 0, baseMisc = 0;
                    Memory::Read<uintptr_t>(gmImp + 0xA8, &playerName);   // PlayerName  (DS2S-META)
                    Memory::Read<uintptr_t>(gmImp + 0xC0, &baseMisc);     // PlayerBaseMisc

                    DumpRegion regions[] = {
                        { "PlayerType",  ptr_b0,     0x00,  0x60 },
                        { "PlayerCtrlA", ptr_d0,     0x00,  0x80 },
                        { "PlayerCtrlB", ptr_d0,     0x80,  0x80 },
                        { "PlayerCtrlC", ptr_d0,     0x100, 0x80 },
                        { "PlayerCtrlD", ptr_d0,     0x180, 0x80 },
                        { "NSMPlayer",   nsmPlayer,  0x1C0, 0x80 },
                        { "PlayerName",  playerName, 0x00,  0x80 },
                        { "BaseMisc",    baseMisc,   0x00,  0x80 },
                    };

                    for (const DumpRegion& r : regions) {
                        if (!r.Base) {
                            LOG_INFO("[IDENT] %s: base null", r.Name);
                            continue;
                        }

                        // Plain char buffer, not std::string: this whole function
                        // sits inside __try, and MSVC refuses SEH in a scope that
                        // needs object unwinding (C2712).
                        char hex[0x80 * 3 + 1];
                        hex[0] = '\0';
                        bool ok = true;
                        for (uint32_t i = 0; i < r.Size && ok; i++) {
                            uint8_t b = 0;
                            ok = Memory::Read<uint8_t>(r.Base + r.Start + i, &b);
                            if (ok) {
                                snprintf(hex + i * 3, 4, "%02X ", b);
                            }
                        }

                        if (ok) {
                            LOG_INFO("[IDENT] %s@0x%llX +0x%02X..0x%02X: %s",
                                     r.Name, (unsigned long long)r.Base,
                                     r.Start, r.Start + r.Size - 1, hex);
                        } else {
                            LOG_INFO("[IDENT] %s@0x%llX unreadable", r.Name, (unsigned long long)r.Base);
                        }
                    }
                }

                // ==============================================================
                // The real phantom marker, found by diffing this client's own
                // dumps either side of a summon (2026-09-07 01:13):
                //
                //   PlayerType +0x38 (uint32)  0 -> 2
                //   PlayerType +0x3D (byte)    0 -> 2   <- TeamType per DS2S-META
                //
                // Both are 0 while you are in your own world and flip to 2 the
                // moment the host summons you. Nothing else in the struct moves
                // except position floats. Note that +0x1F4 in the NetSession
                // player struct — the "phantom field" this mod used to zero
                // every second — does NOT change across a summon at all.
                //
                // The existing TeamType code scans the heap for the value 513
                // and pokes whatever it finds; that address is unrelated to this
                // one, which is why it never had any effect.
                // ==============================================================
                uint32_t typeWord = 0;
                if (Memory::Read<uint32_t>(ptr_b0 + 0x38, &typeWord) && typeWord != 0) {
                    Memory::Write<uint32_t>(ptr_b0 + 0x38, (uint32_t)0);
                    LOG_INFO("EnableSummoning: PlayerType+0x38 %u -> 0 (host-equivalent)", typeWord);
                }

                uint8_t teamType = 0;
                if (Memory::Read<uint8_t>(ptr_b0 + 0x3D, &teamType)) {
                    // 0 like the host -- unless the host picked friendly fire or
                    // PvP, which give the guest a team of its own (pvp_modes.cpp).
                    const uint8_t wantTeam = DS2Coop::Sync::GuestOwnTeam();
                    if (teamType != wantTeam) {
                        Memory::Write<uint8_t>(ptr_b0 + 0x3D, wantTeam);
                        LOG_INFO("EnableSummoning: TeamType(PlayerType+0x3D) %u -> %u (%s)", (unsigned)teamType,
                                 (unsigned)wantTeam, wantTeam == 0 ? "host" : "the host's damage mode");
                    } else if (diag) {
                        LOG_INFO("[IDENT] TeamType(+0x3D) already %u", (unsigned)wantTeam);
                    }
                }

                uint8_t charType = 0;
                if (Memory::Read<uint8_t>(ptr_b0 + 0x48, &charType) && charType != 0) {
                    Memory::Write<uint8_t>(ptr_b0 + 0x48, (uint8_t)0);
                    LOG_INFO("EnableSummoning: CharType %u -> 0 (host) at [PlayerType+0x48]",
                             (unsigned)charType);
                }

                // ==============================================================
                // Zeroing PlayerType+0x38/+0x3D stopped the game rendering the
                // guest as a white phantom, but bonfires and item pickups are
                // still blocked — so those two only drive team/appearance, and
                // the interaction check reads session state instead.
                //
                // The same before/after diff flagged four more fields inside the
                // NetSession player struct that flip on summon:
                //
                //   +0x1F0 (uint32) 0 -> 2
                //   +0x1F8 (uint32) 0 -> 2
                //   +0x1FC (byte)   0 -> 1
                //   +0x210 (byte)   0 -> 1
                //
                // (+0x1E8 also fills in, but that is the phantom slot array
                // pointer — leave it alone or the session loses its players.)
                // ==============================================================
                // REVERTED 2026-09-07 01:30: zeroing the NetSession player fields
                // (+0x1F0, +0x1F8, +0x1FC, +0x210) is destructive. Tested live:
                // the host stopped seeing the guest entirely and the guest was
                // dropped from the session mid-play, while bonfires stayed
                // blocked. Those fields are load-bearing session state, not the
                // interaction gate. Left as dump-only above.
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
}

// The name the partner knows me by. The handshake carries it once, and a lobby joined before the
// character existed carries "Player"; this goes out whenever the name changes (21.09 evening,
// report 8: "I lit a bonfire and it told him Player lit it").
void PlayerSync::TellPartnerMyName() {
    if (!Session::SessionManager::GetInstance().IsActive()) return;
    const std::string Name = GetLocalCharacterName();
    if (Name.empty()) return;
    static std::string s_sent;
    static ULONGLONG s_at = 0;
    const ULONGLONG Now = GetTickCount64();
    if (Name == s_sent && Now - s_at < 30000) return;   // and a reminder now and then, for a late join
    const bool New = Name != s_sent;
    s_sent = Name;
    s_at = Now;
    Network::PlayerNamePacket Packet{};
    Packet.header.magic = 0x44533243;
    Packet.header.type = Network::PacketType::PlayerName;
    Packet.header.size = sizeof(Packet);
    Packet.header.timestamp = Now;
    strncpy_s(Packet.name, Name.c_str(), sizeof(Packet.name) - 1);
    Network::PeerManager::GetInstance().BroadcastPacket(&Packet.header);
    if (New) LOG_INFO("[NAME] my character is %s -- telling the other player", Name.c_str());
}

std::string PlayerSync::GetLocalCharacterName() {
    return ReadCharacterName();
}

// The name the game itself uses for this player (exe+0x2D8400: [[GMImp+0xA8]+0xC0]+0x24, the character's
// own data). The old "+0x114 of GameDataManager" read lay past that 0xE0-byte object and only met the name
// because the next allocation happened to be that data.
std::string PlayerSync::GetOwnCharacterName() {
    uintptr_t Gm = 0, Gdm = 0, Data = 0;
    if (!Memory::Read<uintptr_t>(reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr)) + 0x16148F0, &Gm) || !Gm ||
        !Memory::Read<uintptr_t>(Gm + 0xA8, &Gdm) || !Gdm || !Memory::Read<uintptr_t>(Gdm + 0xC0, &Data) || !Data) {
        return "";
    }
    wchar_t Name[32] = {};
    if (!TryReadNameBuffer(Data + 0x24, Name, 31) || Name[0] == 0) return "";
    return WcharToUtf8(Name);
}

// The save slot of the character being played: the load-menu records ([[GMImp+0xA8]+0xD8], ten of 0x1F0
// bytes) keep the current one's index at +0x1368 -- the record the game writes on each save (exe+0x19C190).
std::string PlayerSync::GetOwnCharacterKey() {
    const std::string Name = GetOwnCharacterName();
    if (Name.empty()) return "";
    uintptr_t Gm = 0, Gdm = 0, Info = 0;
    int32_t Slot = -1;
    if (Memory::Read<uintptr_t>(reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr)) + 0x16148F0, &Gm) && Gm &&
        Memory::Read<uintptr_t>(Gm + 0xA8, &Gdm) && Gdm && Memory::Read<uintptr_t>(Gdm + 0xD8, &Info) && Info &&
        Memory::Read<int32_t>(Info + 0x1368, &Slot) && Slot >= 0 && Slot < 10) {
        return Name + "#" + std::to_string(Slot);
    }
    return Name;
}

bool DS2Coop::Sync::IsLocalCharacterLoaded() {
    auto& Sync = PlayerSync::GetInstance();

    // The direct GMImp+0xA8 name read is the fast path.
    if (!Sync.GetOwnCharacterKey().empty()) return true;

    // Fallback: ReadCharacterName() uses the AOB-resolved GameManagerImp and
    // several alternate paths. Re-check it at most twice a second so the menu
    // can show the lobby buttons without reading game memory every frame.
    static ULONGLONG NextCheck = 0;
    static bool Cached = false;
    static std::atomic<bool> LoggedOk{ false };
    static std::atomic<bool> LoggedNone{ false };
    const ULONGLONG Now = GetTickCount64();
    if (Now >= NextCheck) {
        NextCheck = Now + 500;
        const std::string Local = Sync.GetLocalCharacterName();
        Cached = !Local.empty();
        if (Cached && !LoggedOk.exchange(true)) {
            LOG_INFO("[GATE] character loaded via local name: %s", Local.c_str());
        } else if (!Cached && !LoggedNone.exchange(true)) {
            LOG_WARNING("[GATE] no character detected: local name empty");
        }
    }
    return Cached;
}
