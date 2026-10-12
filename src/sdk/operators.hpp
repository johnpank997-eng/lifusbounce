#pragma once
#include <array>
#include <cstdint>
#include <string_view>

namespace base::sdk::operators {
inline constexpr std::uint32_t decode_mask = 0x9a23fd15u;

struct Entry {
    std::uint32_t id;
    std::string_view name, badge;
};

inline constexpr std::array<Entry, 81> entries{{
    {0x3c7e14b7u, "Sentry", "sentry"},
    {0x8601294bu, "Striker", "striker"},
    {0x3ae9c970u, "Smoke", "smoke"},
    {0x9c469283u, "Mute", "mute"},
    {0xc95d2c83u, "Castle", "castle"},
    {0x90b64022u, "Pulse", "pulse"},
    {0x58d64e14u, "Doc", "doc"},
    {0xcc6828a5u, "Rook", "rook"},
    {0x3057e380u, "Kapkan", "kapkan"},
    {0xfe433863u, "Tachanka", "tachanka"},
    {0x654e99f8u, "Jager", "jager"},
    {0xade0a497u, "Bandit", "bandit"},
    {0xb007aed3u, "Frost", "frost"},
    {0xb7836f44u, "Valkyrie", "valkyrie"},
    {0x3adbfa6bu, "Caveira", "caveira"},
    {0x37c9987au, "Echo", "echo"},
    {0xf5105430u, "Mira", "mira"},
    {0x0e33e133u, "Lesion", "lesion"},
    {0x5832143au, "Ela", "ela"},
    {0xa24a251au, "Vigil", "vigil"},
    {0x3c48ec09u, "Maestro", "maestro"},
    {0x71aa1729u, "Alibi", "alibi"},
    {0x3c640269u, "Clash", "clash"},
    {0xc05555d6u, "Kaid", "kaid"},
    {0xa1e25671u, "Mozzie", "mozzie"},
    {0x4290edf4u, "Warden", "warden"},
    {0x2ee7f4ecu, "Goyo", "goyo"},
    {0x585416d5u, "Wamai", "wamai"},
    {0x5e81e122u, "Oryx", "oryx"},
    {0x57d4a882u, "Melusi", "melusi"},
    {0x702d7af2u, "Aruni", "aruni"},
    {0x829649b5u, "Thunderbird", "thunderbird"},
    {0xbae63ed7u, "Thorn", "thorn"},
    {0x438adda4u, "Azami", "azami"},
    {0x71c046dbu, "Solis", "solis"},
    {0xce419731u, "Fenrir", "fenrir"},
    {0x016bfa1bu, "Tubarao", "tubarao"},
    {0x60f4c606u, "Denari", "denari"},
    {0x8c63fca7u, "Skopos", "skopos"},
    {0xc49a2f1eu, "Noor", "noor"},
    {0x215d5e05u, "Sledge", "sledge"},
    {0xa39ebe6bu, "Thatcher", "thatcher"},
    {0x991bef66u, "Ash", "ash"},
    {0x4b7c2915u, "Thermite", "thermite"},
    {0xa5729261u, "Thermite", "thermite"},
    {0xef373f88u, "Twitch", "twitch"},
    {0xfedcde1du, "Montagne", "montagne"},
    {0x07d3781bu, "Glaz", "glaz"},
    {0x866822e2u, "Fuze", "fuze"},
    {0x4910b4cbu, "Blitz", "blitz"},
    {0x0ae5c56au, "IQ", "iq"},
    {0x6ee8c682u, "IQ", "iq"},
    {0xe1ff9b66u, "Buck", "buck"},
    {0x47531307u, "Blackbeard", "blackbeard"},
    {0x1f469dc5u, "Capitao", "capitao"},
    {0x4f758195u, "Hibana", "hibana"},
    {0x2ac8c77eu, "Jackal", "jackal"},
    {0xed615291u, "Ying", "ying"},
    {0xbb570c69u, "Zofia", "zofia"},
    {0xb6018854u, "Dokkaebi", "dokkaebi"},
    {0xcece6c60u, "Lion", "lion"},
    {0x6635ffb2u, "Finka", "finka"},
    {0xafc61105u, "Maverick", "maverick"},
    {0xf7ba2bd7u, "Nomad", "nomad"},
    {0x888d1c32u, "Gridlock", "gridlock"},
    {0x596fe59au, "Nokk", "nokk"},
    {0x500514bfu, "Amaru", "amaru"},
    {0xc28aacceu, "Kali", "kali"},
    {0x082c6ca4u, "Iana", "iana"},
    {0x4e5570bau, "Ace", "ace"},
    {0x9f00bf21u, "Zero", "zero"},
    {0xd69bbfbcu, "Flores", "flores"},
    {0xa4cf0af7u, "Osa", "osa"},
    {0x3356ed0eu, "Nomad", "nomad"},
    {0x2e341133u, "Sens", "sens"},
    {0xe8f7c002u, "Grim", "grim"},
    {0x0c4945ebu, "Brava", "brava"},
    {0x2b53ecf7u, "Ram", "ram"},
    {0xd5a3b13bu, "Deimos", "deimos"},
    {0xe80b2e23u, "Rauora", "rauora"},
    {0xd31cd095u, "Solid Snake", "solidsnake"},
}};

inline constexpr const Entry* Find(std::uint32_t id) noexcept {
    for (const auto& value : entries)
        if (value.id == id)
            return &value;
    return nullptr;
}
}
