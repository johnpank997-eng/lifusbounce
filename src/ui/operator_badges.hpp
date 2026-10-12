#pragma once
#include "ui/gfx.hpp"
#include "ui/image_resources.hpp"
#include <array>
#include <cstdint>
#include <string_view>

namespace base {
struct OperatorBadges {
    struct Asset {
        std::string_view name;
        unsigned resource;
    };

    inline static constexpr std::array<Asset, 78> assets{{
        {"ace", 200},
        {"amaru", 201},
        {"ash", 202},
        {"blackbeard", 203},
        {"blitz", 204},
        {"brava", 205},
        {"buck", 206},
        {"capitao", 207},
        {"deimos", 208},
        {"denari", 209},
        {"dokkaebi", 210},
        {"finka", 211},
        {"flores", 212},
        {"fuze", 213},
        {"glaz", 214},
        {"gridlock", 215},
        {"grim", 216},
        {"hibana", 217},
        {"iana", 218},
        {"iq", 219},
        {"jackal", 220},
        {"kali", 221},
        {"lion", 222},
        {"maverick", 223},
        {"montagne", 224},
        {"nokk", 225},
        {"nomad", 226},
        {"osa", 227},
        {"ram", 228},
        {"rauora", 229},
        {"sens", 230},
        {"sledge", 231},
        {"solidsnake", 232},
        {"striker", 233},
        {"thatcher", 234},
        {"thermite", 235},
        {"twitch", 236},
        {"ying", 237},
        {"zero", 238},
        {"zofia", 239},
        {"alibi", 240},
        {"aruni", 241},
        {"azami", 242},
        {"bandit", 243},
        {"castle", 244},
        {"caveira", 245},
        {"clash", 246},
        {"doc", 247},
        {"echo", 248},
        {"ela", 249},
        {"fenrir", 250},
        {"frost", 251},
        {"goyo", 252},
        {"jager", 253},
        {"kaid", 254},
        {"kapkan", 255},
        {"lesion", 256},
        {"maestro", 257},
        {"melusi", 258},
        {"mira", 259},
        {"mozzie", 260},
        {"mute", 261},
        {"oryx", 262},
        {"pulse", 263},
        {"rook", 264},
        {"sentry", 265},
        {"skopos", 266},
        {"smoke", 267},
        {"solis", 268},
        {"tachanka", 269},
        {"thorn", 270},
        {"thunderbird", 271},
        {"tubarao", 272},
        {"valkyrie", 273},
        {"vigil", 274},
        {"wamai", 275},
        {"warden", 276},
        {"noor", 277},
    }};
    std::array<ComPtr<ID3D11ShaderResourceView>, assets.size()> textures;
    bool Init(HINSTANCE instance, ID3D11Device* device, const ImageResources& images);
    ID3D11ShaderResourceView* Get(std::uint32_t id) const noexcept;
};
}
