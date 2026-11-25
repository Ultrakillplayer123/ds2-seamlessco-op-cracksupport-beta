// Palette helpers, fonts and the base ImGui style for the overlay.
//
// The menu deliberately uses the small, square Tahoma/MS Sans Serif look of a
// Windows 98 dialog. Those fonts also carry Cyrillic, so the Russian menu keeps
// working. They are loaded from the Windows font folder, sized for the screen,
// with the next font in each list as a fallback.
//
// The size is not settled once: the game often shows its first frames at
// 1280x720 and only then switches to the real resolution, which left the menu
// drawn for 720p on a 1440p screen. The renderer calls Setup again whenever the
// back buffer settles at a size that wants another scale, or the player picks
// another menu size.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "../../include/ui_kit.h"
#include "../../include/ui_settings.h"
#include "../../include/utils.h"

#include <Windows.h>
#include <algorithm>
#include <cmath>
#include <initializer_list>
#include <string>

using namespace DS2Coop::Utils;

namespace DS2Coop::UI::Kit {

namespace {

float   g_scale  = 1.0f;
ImFont* g_body   = nullptr;
ImFont* g_small  = nullptr;
ImFont* g_strong = nullptr;
ImFont* g_title  = nullptr;

// Latin, Latin-1, Cyrillic, and the punctuation the texts use (— … • ‹ › №).
const ImWchar kRanges[] = {
    0x0020, 0x00FF,
    0x0400, 0x052F,
    0x2010, 0x2027,
    0x2039, 0x203A,
    0x2116, 0x2116,
    0x2190, 0x2193,
    0,
};

std::string FontPath(const char* file) {
    char Dir[MAX_PATH] = {};
    GetWindowsDirectoryA(Dir, MAX_PATH);
    return std::string(Dir) + "\\Fonts\\" + file;
}

ImFont* LoadFirst(std::initializer_list<const char*> files, float size, float multiply) {
    ImGuiIO& io = ImGui::GetIO();
    for (const char* File : files) {
        const std::string Path = FontPath(File);
        if (GetFileAttributesA(Path.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        ImFontConfig Cfg;
        Cfg.OversampleH = 2;
        Cfg.OversampleV = 1;
        Cfg.RasterizerMultiply = multiply;
        if (ImFont* Font = io.Fonts->AddFontFromFileTTF(Path.c_str(), size, &Cfg, kRanges)) {
            LOG_INFO("[UI] font %s at %.0f px", File, size);
            return Font;
        }
    }
    return nullptr;
}

ImVec4 V(ImU32 c) { return ImGui::ColorConvertU32ToFloat4(c); }

void ApplyStyle() {
    // No custom theme: stock ImGui, plain light grey, nothing decorative. Only
    // the size is scaled so the controls stay usable at the chosen menu size.
    ImGuiStyle& S = ImGui::GetStyle();
    S = ImGuiStyle();
    ImGui::StyleColorsLight(&S);
    S.ScaleAllSizes(g_scale);
}

} // namespace

ImU32 Fade(ImU32 color, float alpha) {
    const float A = static_cast<float>((color >> IM_COL32_A_SHIFT) & 0xFF) * std::clamp(alpha, 0.0f, 1.0f);
    return (color & ~IM_COL32_A_MASK) | (static_cast<ImU32>(A + 0.5f) << IM_COL32_A_SHIFT);
}

ImU32 Mix(ImU32 a, ImU32 b, float t) {
    t = std::clamp(t, 0.0f, 1.0f);
    ImU32 Out = 0;
    for (int Shift = 0; Shift < 32; Shift += 8) {
        const float Ca = static_cast<float>((a >> Shift) & 0xFF);
        const float Cb = static_cast<float>((b >> Shift) & 0xFF);
        Out |= static_cast<ImU32>(Ca + (Cb - Ca) * t + 0.5f) << Shift;
    }
    return Out;
}

float EaseOut(float t) {
    t = std::clamp(t, 0.0f, 1.0f);
    const float U = 1.0f - t;
    return 1.0f - U * U * U;
}

float Approach(float value, float target, float perSecond) {
    const float Step = perSecond * ImGui::GetIO().DeltaTime;
    return value < target ? std::min(value + Step, target) : std::max(value - Step, target);
}

float TargetScale(float displayWidth, float displayHeight) {
    if (displayWidth < 1.0f || displayHeight < 1.0f) return g_scale;
    const float Screen = std::clamp(displayHeight / 1080.0f, 0.85f, 3.0f);
    float Wanted = Screen * static_cast<float>(GetMenuSize()) / 100.0f;
    Wanted = std::min(Wanted, displayWidth * 0.92f / kMenuWidth);
    if (kMenuTallest > 0.0f) Wanted = std::min(Wanted, displayHeight * 0.94f / kMenuTallest);
    Wanted = std::clamp(Wanted, 0.6f, 4.0f);
    return std::round(Wanted * 20.0f) / 20.0f;
}

void Setup(float displayWidth, float displayHeight) {
    g_scale = TargetScale(displayWidth, displayHeight);
    const float S = g_scale;

    // Fonts built for the previous scale go; ImFont pointers are only ever
    // asked for through the accessors below, never kept across frames.
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();
    g_body = g_small = g_strong = g_title = nullptr;

    g_body   = LoadFirst({ "tahoma.ttf", "msans.ttf", "arial.ttf" }, 12.0f * S, 1.0f);
    g_small  = LoadFirst({ "tahoma.ttf", "msans.ttf", "arial.ttf" }, 11.0f * S, 1.0f);
    g_strong = LoadFirst({ "tahomabd.ttf", "msansb.ttf", "arialbd.ttf" }, 12.0f * S, 1.0f);
    g_title  = LoadFirst({ "tahomabd.ttf", "msansb.ttf", "arialbd.ttf" }, 14.0f * S, 1.0f);

    if (!g_body) {
        LOG_WARNING("[UI] no system font found; Cyrillic will not display");
        g_body = io.Fonts->AddFontDefault();
    }
    if (!g_small)  g_small  = g_body;
    if (!g_strong) g_strong = g_body;
    if (!g_title)  g_title  = g_strong;
    io.FontDefault = g_body;

    ApplyStyle();
}

float   Scale()      { return g_scale; }
ImFont* FontBody()   { return g_body   ? g_body   : ImGui::GetFont(); }
ImFont* FontSmall()  { return g_small  ? g_small  : ImGui::GetFont(); }
ImFont* FontStrong() { return g_strong ? g_strong : ImGui::GetFont(); }
ImFont* FontTitle()  { return g_title  ? g_title  : ImGui::GetFont(); }

} // namespace DS2Coop::UI::Kit
