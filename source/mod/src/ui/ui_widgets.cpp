// Custom widgets for the overlay menu.
//
// Each one reserves its space with an InvisibleButton and draws itself with the
// window's draw list. Raw draw-list colours ignore ImGui's style alpha, so every
// colour goes through A(), which applies the menu's fade and the disabled dim.

#include "../../include/ui_kit.h"

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstring>

namespace DS2Coop::UI::Kit {

namespace {

float Anim(ImGuiID, float target, float) {
    // No animations: hover and selection states are instant.
    return target;
}

ImU32 A(ImU32 color, float extra = 1.0f) {
    return Fade(color, ImGui::GetStyle().Alpha * extra);
}

// The cheap raised-edge look every Win98 control had. Two light edges, two dark
// edges, no antialiasing and no apologies.
void Bevel(ImDrawList*, ImVec2, ImVec2, float = 1.0f) {
    // No bevels in the plain UI: the caller's rectangle is all there is.
}

const char* VisibleEnd(const char* label) {
    const char* Hash = strstr(label, "##");
    return Hash ? Hash : label + strlen(label);
}

ImVec2 Measure(ImFont* font, const char* text, const char* end = nullptr) {
    return font->CalcTextSizeA(font->FontSize, FLT_MAX, 0.0f, text, end);
}

void CenterText(ImDrawList* list, ImFont* font, ImVec2 min, ImVec2 max, ImU32 color,
                const char* text, const char* end = nullptr) {
    const ImVec2 Size = Measure(font, text, end);
    const ImVec2 Pos(std::floor((min.x + max.x - Size.x) * 0.5f),
                     std::floor((min.y + max.y - Size.y) * 0.5f));
    list->AddText(font, font->FontSize, Pos, color, text, end);
}

} // namespace

bool Button(const char* label, ButtonKind kind, float width, bool enabled) {
    const float S = Scale();
    ImFont* Font = kind == ButtonKind::Ghost ? FontBody() : FontStrong();
    const char* End = VisibleEnd(label);
    const ImVec2 Text = Measure(Font, label, End);

    // A ghost button with no width is a text link: sized to its text, left-aligned.
    const bool Link = kind == ButtonKind::Ghost && width == 0.0f;
    const float W = width < 0.0f ? ImGui::GetContentRegionAvail().x
                  : width == 0.0f ? Text.x + (Link ? 8.0f : 36.0f) * S : width;
    const float H = kind == ButtonKind::Ghost ? Text.y + 8.0f * S : 44.0f * S;

    if (!enabled) ImGui::BeginDisabled();
    const bool Pressed = ImGui::InvisibleButton(label, ImVec2(W, H));
    const bool Held = ImGui::IsItemActive();
    const float T = Anim(ImGui::GetItemID(), ImGui::IsItemHovered() ? 1.0f : 0.0f, 8.0f);
    const ImVec2 Min = ImGui::GetItemRectMin(), Max = ImGui::GetItemRectMax();
    ImDrawList* L = ImGui::GetWindowDrawList();
    const float R = 0.0f;  // square corners, like the control panel meant it

    switch (kind) {
    case ButtonKind::Primary: {
        if (!enabled) {
            L->AddRectFilled(Min, Max, A(Col::Surface), R);
            L->AddRect(Min, Max, A(Col::Line), R, 0, 1.0f);
            CenterText(L, Font, Min, Max, A(Col::TextFaint), label, End);
            break;
        }
        const ImU32 Fill = Held ? Col::EmberHi : Col::Ember;
        L->AddRectFilled(Min, Max, A(Fill), R);
        L->AddRect(Min, Max, A(Col::Line), R, 0, 1.0f);
        Bevel(L, Min, Max, 1.0f);
        CenterText(L, Font, Min, Max, A(Col::OnEmber), label, End);
        break;
    }
    case ButtonKind::Secondary:
        L->AddRectFilled(Min, Max, A(Mix(Col::Surface, Col::Surface2, T)), R);
        L->AddRect(Min, Max, A(Col::Line), R, 0, 1.0f);
        Bevel(L, Min, Max, 1.0f);
        CenterText(L, Font, Min, Max, A(Col::Text), label, End);
        break;
    case ButtonKind::Danger:
        L->AddRectFilled(Min, Max, A(Col::Surface), R);
        L->AddRect(Min, Max, A(Fade(Col::Red, 0.7f + 0.3f * T)), R, 0, 1.0f);
        Bevel(L, Min, Max, 1.0f);
        CenterText(L, Font, Min, Max, A(Col::Red), label, End);
        break;
    case ButtonKind::Ghost:
        CenterText(L, Font, Min, Max, A(Mix(Col::TextMuted, Col::Ember, T)), label, End);
        break;
    }
    if (!enabled) ImGui::EndDisabled();
    return Pressed && enabled;
}

bool ActionCard(const char* id, int icon, const char* title, const char* subtitle) {
    const float S = Scale();
    const float W = ImGui::GetContentRegionAvail().x, H = 72.0f * S;
    const bool Pressed = ImGui::InvisibleButton(id, ImVec2(W, H));
    const float T = Anim(ImGui::GetItemID(), ImGui::IsItemHovered() ? 1.0f : 0.0f, 7.0f);
    const ImVec2 Min = ImGui::GetItemRectMin(), Max = ImGui::GetItemRectMax();
    ImDrawList* L = ImGui::GetWindowDrawList();
    const float R = 0.0f;

    L->AddRectFilled(Min, Max, A(Mix(Col::Surface, Col::Surface2, T)), R);
    L->AddRect(Min, Max, A(Col::Line), R, 0, 1.0f);
    Bevel(L, Min, Max, 1.0f);

    // Icon box: a square, because circles are a luxury this UI cannot afford.
    const ImVec2 C(Min.x + 36.0f * S, (Min.y + Max.y) * 0.5f);
    const float Rad = 18.0f * S, Th = 2.0f * S, K = 6.0f * S;
    L->AddRectFilled(ImVec2(C.x - Rad, C.y - Rad), ImVec2(C.x + Rad, C.y + Rad), A(Col::Surface2), 0.0f);
    L->AddRect(ImVec2(C.x - Rad, C.y - Rad), ImVec2(C.x + Rad, C.y + Rad), A(Col::Ember), 0.0f, 0, 1.0f);
    const ImU32 Glyph = A(Col::Ember);
    if (icon == IconHost) {
        L->AddLine(ImVec2(C.x - K, C.y), ImVec2(C.x + K, C.y), Glyph, Th);
        L->AddLine(ImVec2(C.x, C.y - K), ImVec2(C.x, C.y + K), Glyph, Th);
    } else {
        L->AddLine(ImVec2(C.x - K, C.y), ImVec2(C.x + K, C.y), Glyph, Th);
        L->AddLine(ImVec2(C.x + K, C.y), ImVec2(C.x + 1.0f * S, C.y - 5.0f * S), Glyph, Th);
        L->AddLine(ImVec2(C.x + K, C.y), ImVec2(C.x + 1.0f * S, C.y + 5.0f * S), Glyph, Th);
    }

    // Title and one line of explanation.
    ImFont* TitleFont = FontStrong();
    ImFont* SubFont = FontSmall();
    const float TextX = Min.x + 70.0f * S;
    const float TitleH = TitleFont->FontSize, SubH = SubFont->FontSize;
    const float Top = C.y - (TitleH + 2.0f * S + SubH) * 0.5f;
    L->AddText(TitleFont, TitleH, ImVec2(TextX, Top), A(Col::Text), title);
    L->AddText(SubFont, SubH, ImVec2(TextX, Top + TitleH + 2.0f * S), A(Col::TextMuted), subtitle);

    // Chevron that leans forward on hover.
    const float X = Max.x - 26.0f * S + 3.0f * S * T;
    const ImU32 Chev = A(Mix(Col::TextFaint, Col::Ember, T));
    L->AddLine(ImVec2(X, C.y - 5.0f * S), ImVec2(X + 5.0f * S, C.y), Chev, 1.8f * S);
    L->AddLine(ImVec2(X + 5.0f * S, C.y), ImVec2(X, C.y + 5.0f * S), Chev, 1.8f * S);
    return Pressed;
}

bool Tabs(const char* id, const char* const* labels, int count, int& current) {
    const float S = Scale();
    const float W = ImGui::GetContentRegionAvail().x, H = 38.0f * S;
    const float Seg = W / static_cast<float>(count);
    ImGui::PushID(id);
    const ImVec2 P = ImGui::GetCursorScreenPos();
    ImDrawList* L = ImGui::GetWindowDrawList();

    L->AddRectFilled(P, ImVec2(P.x + W, P.y + H), A(Col::Surface), 0.0f);
    L->AddRect(P, ImVec2(P.x + W, P.y + H), A(Col::Line), 0.0f, 0, 1.0f);
    Bevel(L, P, ImVec2(P.x + W, P.y + H), 1.0f);

    // Tabs snap instantly. Transitions are a modern luxury.
    const float Slide = static_cast<float>(current);
    const ImVec2 K0(P.x + 3.0f * S + Slide * Seg, P.y + 3.0f * S);
    const ImVec2 K1(K0.x + Seg - 6.0f * S, P.y + H - 3.0f * S);
    L->AddRectFilled(K0, K1, A(Col::Surface2), 0.0f);
    L->AddRect(K0, K1, A(Col::Line), 0.0f, 0, 1.0f);
    Bevel(L, K0, K1, 1.0f);
    const float Mid = (K0.x + K1.x) * 0.5f;
    L->AddRectFilled(ImVec2(Mid - 14.0f * S, K1.y - 3.0f * S), ImVec2(Mid + 14.0f * S, K1.y - 1.0f * S),
                     A(Col::Ember), 0.0f);

    bool Changed = false;
    for (int i = 0; i < count; i++) {
        ImGui::SetCursorScreenPos(ImVec2(P.x + Seg * static_cast<float>(i), P.y));
        ImGui::PushID(i);
        if (ImGui::InvisibleButton("seg", ImVec2(Seg, H)) && current != i) {
            current = i;
            Changed = true;
        }
        const bool Hovered = ImGui::IsItemHovered();
        ImGui::PopID();
        const ImVec2 Min(P.x + Seg * static_cast<float>(i), P.y);
        const ImU32 Color = i == current ? Col::Text : Mix(Col::TextMuted, Col::Text, Hovered ? 0.6f : 0.0f);
        CenterText(L, FontStrong(), Min, ImVec2(Min.x + Seg, Min.y + H), A(Color), labels[i]);
    }
    ImGui::PopID();
    return Changed;
}

bool LanguageSwitch(const char* id, bool& russian) {
    const float S = Scale();
    const float W = 108.0f * S, H = 34.0f * S;
    const bool Pressed = ImGui::InvisibleButton(id, ImVec2(W, H));
    if (Pressed) russian = !russian;
    const bool Hovered = ImGui::IsItemHovered();
    const float T = Anim(ImGui::GetItemID(), russian ? 1.0f : 0.0f, 7.0f);
    const ImVec2 Min = ImGui::GetItemRectMin(), Max = ImGui::GetItemRectMax();
    ImDrawList* L = ImGui::GetWindowDrawList();

    L->AddRectFilled(Min, Max, A(Col::Surface), 0.0f);
    L->AddRect(Min, Max, A(Col::Line), 0.0f, 0, 1.0f);
    Bevel(L, Min, Max, 1.0f);

    const float Half = (W - 6.0f * S) * 0.5f;
    const float E = EaseOut(T);
    const ImVec2 K0(Min.x + 3.0f * S + E * Half, Min.y + 3.0f * S);
    const ImVec2 K1(K0.x + Half, Max.y - 3.0f * S);
    L->AddRectFilled(K0, K1, A(Hovered ? Col::EmberHi : Col::Ember), 0.0f);
    L->AddRect(K0, K1, A(Col::Line), 0.0f, 0, 1.0f);

    const ImVec2 LeftMax(Min.x + 3.0f * S + Half, Max.y), RightMin(Min.x + 3.0f * S + Half, Min.y);
    CenterText(L, FontStrong(), ImVec2(Min.x + 3.0f * S, Min.y), LeftMax,
               A(Mix(Col::OnEmber, Col::TextMuted, T)), "EN");
    CenterText(L, FontStrong(), RightMin, ImVec2(Max.x - 3.0f * S, Max.y),
               A(Mix(Col::TextMuted, Col::OnEmber, T)), "RU");
    return Pressed;
}

bool KeyBindButton(const char* id, const char* keyName, bool capturing) {
    const float S = Scale();
    ImFont* Font = FontStrong();
    const ImVec2 Text = Measure(Font, keyName);
    const float W = std::max(Text.x + 32.0f * S, 88.0f * S), H = 38.0f * S, Depth = 3.0f * S;

    const bool Pressed = ImGui::InvisibleButton(id, ImVec2(W, H));
    const float T = Anim(ImGui::GetItemID(), ImGui::IsItemHovered() ? 1.0f : 0.0f, 8.0f);
    const ImVec2 Min = ImGui::GetItemRectMin(), Max = ImGui::GetItemRectMax();
    ImDrawList* L = ImGui::GetWindowDrawList();
    const float R = 0.0f;
    const float Pulse = capturing ? 0.5f + 0.5f * std::sin(static_cast<float>(ImGui::GetTime()) * 5.0f) : 0.0f;

    L->AddRectFilled(ImVec2(Min.x, Min.y + Depth), Max, A(Col::TextFaint), R);
    const ImVec2 TopMax(Max.x, Max.y - Depth);
    L->AddRectFilled(Min, TopMax, A(Mix(Col::Surface, Col::Surface2, T)), R);
    L->AddRect(Min, TopMax, A(capturing ? Fade(Col::Red, 0.45f + 0.55f * Pulse) : Col::Line),
               R, 0, capturing ? 1.6f * S : 1.0f);
    Bevel(L, Min, TopMax, 1.0f);
    CenterText(L, Font, Min, TopMax, A(capturing ? Col::Red : Col::Text), keyName);
    return Pressed;
}

bool CloseButton(const char* id) {
    const float S = Scale();
    const float Size = 30.0f * S;
    const bool Pressed = ImGui::InvisibleButton(id, ImVec2(Size, Size));
    const float T = Anim(ImGui::GetItemID(), ImGui::IsItemHovered() ? 1.0f : 0.0f, 8.0f);
    const ImVec2 Min = ImGui::GetItemRectMin(), Max = ImGui::GetItemRectMax();
    const ImVec2 C((Min.x + Max.x) * 0.5f, (Min.y + Max.y) * 0.5f);
    ImDrawList* L = ImGui::GetWindowDrawList();
    L->AddRectFilled(Min, Max, A(Mix(Col::Surface, Col::Surface2, T)), 0.0f);
    L->AddRect(Min, Max, A(Col::Line), 0.0f, 0, 1.0f);
    Bevel(L, Min, Max, 1.0f);
    const float K = 5.0f * S;
    const ImU32 Color = A(Mix(Col::TextMuted, Col::Red, T));
    L->AddLine(ImVec2(C.x - K, C.y - K), ImVec2(C.x + K, C.y + K), Color, 1.6f * S);
    L->AddLine(ImVec2(C.x - K, C.y + K), ImVec2(C.x + K, C.y - K), Color, 1.6f * S);
    return Pressed;
}

bool InputField(const char* label, const char* id, char* buffer, size_t size,
                const char* hint, bool focus) {
    const float S = Scale();
    ImGui::PushFont(FontSmall());
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Col::TextMuted));
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    ImGui::PopFont();
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 4.0f * S);

    ImGui::SetNextItemWidth(-FLT_MIN);
    if (focus) ImGui::SetKeyboardFocusHere();
    ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(Col::Line));
    const bool Changed = ImGui::InputTextWithHint(id, hint, buffer, size);
    ImGui::PopStyleColor();

    const float R = ImGui::GetStyle().FrameRounding;
    ImDrawList* L = ImGui::GetWindowDrawList();
    if (ImGui::IsItemActive()) {
        L->AddRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax(), A(Fade(Col::Ember, 0.85f)), R, 0, 1.5f * S);
    } else if (ImGui::IsItemHovered()) {
        L->AddRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax(), A(Fade(Col::Gold, 0.5f)), R, 0, 1.0f);
    }
    return Changed;
}

void SectionLabel(const char* text) {
    const float S = Scale();
    ImGui::PushFont(FontSmall());
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(Col::Ember));
    ImGui::TextUnformatted(text);
    ImGui::PopStyleColor();
    ImGui::PopFont();
    const ImVec2 Max = ImGui::GetItemRectMax(), Min = ImGui::GetItemRectMin();
    const float Y = std::floor((Min.y + Max.y) * 0.5f) + 0.5f;
    const float Right = ImGui::GetWindowPos().x + ImGui::GetWindowContentRegionMax().x;
    ImGui::GetWindowDrawList()->AddLine(ImVec2(Max.x + 10.0f * S, Y), ImVec2(Right, Y), A(Col::Line), 1.0f);
}

void Paragraph(const char* text, ImU32 color) {
    ImGui::PushFont(FontBody());
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(color));
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextUnformatted(text);
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();
    ImGui::PopFont();
}

void Divider() {
    const ImVec2 P = ImGui::GetCursorScreenPos();
    const float W = ImGui::GetContentRegionAvail().x;
    ImDrawList* L = ImGui::GetWindowDrawList();
    const ImU32 Line = A(Col::Line);
    L->AddLine(ImVec2(P.x, P.y + 0.5f), ImVec2(P.x + W, P.y + 0.5f), Line, 1.0f);
    ImGui::Dummy(ImVec2(W, 1.0f));
}

void StatusDot(ImDrawList* list, ImVec2 center, ImU32 color, bool pulse) {
    const float S = Scale();
    if (pulse) {
        const float Phase = std::fmod(static_cast<float>(ImGui::GetTime()) * 0.8f, 1.0f);
        list->AddCircleFilled(center, 4.0f * S + 6.0f * S * Phase, A(Fade(color, 0.35f * (1.0f - Phase))));
    }
    list->AddCircleFilled(center, 4.0f * S, A(color));
}

void Chip(const char* text, ImU32 color) {
    const float S = Scale();
    ImFont* Font = FontSmall();
    const ImVec2 Text = Measure(Font, text);
    const ImVec2 Size(Text.x + 16.0f * S, Text.y + 6.0f * S);
    ImGui::Dummy(Size);
    const ImVec2 Min = ImGui::GetItemRectMin(), Max = ImGui::GetItemRectMax();
    ImDrawList* L = ImGui::GetWindowDrawList();
    L->AddRectFilled(Min, Max, A(Fade(color, 0.14f)), 0.0f);
    L->AddRect(Min, Max, A(Col::Line), 0.0f, 0, 1.0f);
    Bevel(L, Min, Max, 1.0f);
    CenterText(L, Font, Min, Max, A(color), text);
}

ImVec2 KeycapSize(const char* label) {
    const float S = Scale();
    const ImVec2 Text = Measure(FontSmall(), label);
    return ImVec2(std::max(Text.x + 14.0f * S, 26.0f * S), Text.y + 8.0f * S);
}

void Keycap(ImDrawList* list, ImVec2 pos, const char* label, float alpha) {
    const float S = Scale();
    const ImVec2 Size = KeycapSize(label);
    const float Depth = 2.0f * S, R = 0.0f;
    const ImVec2 Max(pos.x + Size.x, pos.y + Size.y);
    const ImVec2 TopMax(Max.x, Max.y - Depth);
    list->AddRectFilled(ImVec2(pos.x, pos.y + Depth), Max, Fade(Col::TextFaint, alpha), R);
    list->AddRectFilled(pos, TopMax, Fade(Col::Surface, alpha), R);
    list->AddRect(pos, TopMax, Fade(Col::Line, alpha), R, 0, 1.0f);
    CenterText(list, FontSmall(), pos, TopMax, Fade(Col::Text, alpha), label);
}

} // namespace DS2Coop::UI::Kit
