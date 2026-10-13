#include "sdk/locator.hpp"
#include <algorithm>
#include <bit>
#include <vector>
#include <map>
#include <set>
#include <cstring>
#include <limits>
#include <tuple>
#include <string>
#ifdef LIFUS_EQUIPMENT_TRACE
#include <cstdio>
#endif

namespace base::sdk::locators {
namespace {
std::uint32_t Dependency(ZydisRegister reg) {
    if (reg == ZYDIS_REGISTER_RFLAGS || reg == ZYDIS_REGISTER_EFLAGS)
        return 0;
    const auto enclosing = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
    if (ZydisRegisterGetClass(enclosing) != ZYDIS_REGCLASS_GPR64)
        return 0;
    const auto id = ZydisRegisterGetId(enclosing);
    return id >= 0 && id < 16 ? 1u << id : 0;
}

bool LocalSlot(const ZydisDecodedOperand& o) {
    return o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.base == ZYDIS_REGISTER_RSP &&
        o.mem.index == ZYDIS_REGISTER_NONE;
}

struct Word {
    std::uint64_t constant{};
    std::map<std::size_t, std::uint64_t> terms;
    bool operator==(const Word&) const = default;
};

struct Algebra {
    struct Node {
        ZydisMnemonic operation{};
        Word left, right;
    };

    std::vector<Node> nodes{{}};
    std::map<std::tuple<ZydisMnemonic, std::string, std::string>, std::size_t> interned;

    static std::string Key(const Word& value) {
        auto result = std::to_string(value.constant);
        for (const auto& [id, coefficient] : value.terms)
            result += ":" + std::to_string(id) + "=" + std::to_string(coefficient);
        return result;
    }

    Word Unknown() {
        nodes.push_back({});
        return {0, {{nodes.size() - 1, 1}}};
    }

    static void Add(Word& a, const Word& b, std::uint64_t coefficient = 1) {
        a.constant += b.constant * coefficient;
        for (const auto& [id, value] : b.terms) {
            auto& destination = a.terms[id];
            destination += value * coefficient;
            if (!destination)
                a.terms.erase(id);
        }
    }

    Word Reduce(Word value) {
        for (unsigned round = 0; round < 32; ++round) {
            bool changed = false;
            for (const auto& [id, coefficient] : value.terms) {
                const auto& a = nodes[id];
                if (a.operation != ZYDIS_MNEMONIC_XOR && a.operation != ZYDIS_MNEMONIC_OR)
                    continue;
                for (const auto& [other, multiple] : value.terms) {
                    const auto& b = nodes[other];

                    const bool same_mask = a.right == b.right ||
                        (a.right.terms.empty() && b.right.terms.empty() &&
                            (a.right.constant ^ b.right.constant) * multiple == 0);
                    if (b.operation != ZYDIS_MNEMONIC_AND || a.left != b.left || !same_mask ||
                        multiple != coefficient * (a.operation == ZYDIS_MNEMONIC_XOR ? 2 : 1))
                        continue;
                    const auto left = a.left, right = a.right;
                    const auto amount = coefficient;
                    value.terms.erase(id);
                    value.terms.erase(other);
                    Add(value, left, amount);
                    Add(value, right, amount);
                    changed = true;
                    break;
                }
                if (changed)
                    break;
            }
            if (!changed)
                break;
        }
        return value;
    }

    Word Sum(Word a, const Word& b, std::uint64_t coefficient = 1) {
        Add(a, b, coefficient);
        return Reduce(std::move(a));
    }

    Word Scale(Word value, std::uint64_t coefficient) {
        Word result;
        Add(result, value, coefficient);
        return Reduce(std::move(result));
    }

    std::uint64_t Bits(const Word& value) const {
        if (value.terms.empty())
            return value.constant;
        if (value.constant || value.terms.size() != 1 || value.terms.begin()->second != 1)
            return ~0ull;
        const auto& node = nodes[value.terms.begin()->first];
        if (node.operation == ZYDIS_MNEMONIC_AND)
            return Bits(node.left) & Bits(node.right);
        if (node.operation == ZYDIS_MNEMONIC_OR || node.operation == ZYDIS_MNEMONIC_XOR)
            return Bits(node.left) | Bits(node.right);
        return ~0ull;
    }

    Word Bitwise(ZydisMnemonic operation, Word a, Word b) {
        if (a == b)
            return operation == ZYDIS_MNEMONIC_XOR ? Word{} : a;
        if (a.terms.empty() && b.terms.empty()) {
            if (operation == ZYDIS_MNEMONIC_XOR)
                return {a.constant ^ b.constant};
            if (operation == ZYDIS_MNEMONIC_AND)
                return {a.constant & b.constant};
            return {a.constant | b.constant};
        }
        if (a.terms.empty())
            std::swap(a, b);
        if (b.terms.empty()) {

            if (operation == ZYDIS_MNEMONIC_AND && !a.constant && a.terms.size() == 1 &&
                a.terms.begin()->second == 1) {
                const auto node = nodes[a.terms.begin()->first];
                if (node.operation == ZYDIS_MNEMONIC_AND) {
                    if (node.left.terms.empty())
                        return Bitwise(operation, node.right, Word{node.left.constant & b.constant});
                    if (node.right.terms.empty())
                        return Bitwise(operation, node.left, Word{node.right.constant & b.constant});
                }
            }
            const auto mask = Bits(a);
            if (operation == ZYDIS_MNEMONIC_AND) {
                b.constant &= mask;
                if (b.constant == mask)
                    return a;
            }
            if (operation == ZYDIS_MNEMONIC_XOR && (b.constant & ~mask)) {
                const auto outside = b.constant & ~mask;
                return Sum(Bitwise(operation, std::move(a), Word{b.constant & mask}), Word{outside});
            }
        }
        if (a.terms.empty()) {
            if (!a.constant)
                return operation == ZYDIS_MNEMONIC_AND ? Word{} : b;
            if (a.constant == ~0ull && operation == ZYDIS_MNEMONIC_AND)
                return b;
        }
        if (b.terms.empty()) {
            if (!b.constant)
                return operation == ZYDIS_MNEMONIC_AND ? Word{} : a;
            if (b.constant == ~0ull && operation == ZYDIS_MNEMONIC_AND)
                return a;
        }
        auto ka = Key(a), kb = Key(b);
        if (kb < ka) {
            std::swap(ka, kb);
            std::swap(a, b);
        }
        const auto [at, inserted] = interned.try_emplace({operation, ka, kb}, nodes.size());
        if (inserted)
            nodes.push_back({operation, std::move(a), std::move(b)});
        return {0, {{at->second, 1}}};
    }
};

Emulator::Program Simplify(const Emulator::Program& source) {
    auto result = source;
    Algebra math;
    std::array<Word, 16> registers;
    const auto reset = [&] {
        for (auto& reg : registers)
            reg = math.Unknown();
    };
    reset();
    std::vector<std::uint64_t> targets;
    for (const auto& d : source.instructions)
        if ((d.instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                d.instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR) &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.operands[0].imm.is_relative)
            targets.push_back(d.address + d.instruction.length + d.operands[0].imm.value.s);
    std::sort(targets.begin(), targets.end());
    ZydisDecoder decoder{};
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    for (auto& d : result.instructions) {
        if (std::binary_search(targets.begin(), targets.end(), d.address))
            reset();
        const auto value = [&](const ZydisDecodedOperand& o) {
            if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                return Word{o.imm.value.u};
            if (o.type != ZYDIS_OPERAND_TYPE_REGISTER)
                return math.Unknown();
            if (o.reg.value == ZYDIS_REGISTER_RIP)
                return Word{d.address + d.instruction.length};
            if (!Dependency(o.reg.value))
                return math.Unknown();
            auto result = registers[ZydisRegisterGetId(
                ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, o.reg.value))];
            if (o.size < 64)
                result = math.Bitwise(ZYDIS_MNEMONIC_AND, std::move(result), Word{(1ull << o.size) - 1});
            return result;
        };
        const auto& x = d.operands[0];
        const auto& y = d.operands[1];
        if (x.type == ZYDIS_OPERAND_TYPE_REGISTER && Dependency(x.reg.value) &&
            (x.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) {
            Word computed = math.Unknown();
            const auto op = d.instruction.mnemonic;
            if (op == ZYDIS_MNEMONIC_MOV)
                computed = value(y);
            if (op == ZYDIS_MNEMONIC_LEA && y.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                const auto reg = [&](ZydisRegister r) {
                    ZydisDecodedOperand o{};
                    o.type = ZYDIS_OPERAND_TYPE_REGISTER;
                    o.reg.value = r;
                    o.size = 64;
                    return r == ZYDIS_REGISTER_NONE ? Word{} : value(o);
                };
                computed = math.Sum(math.Sum(reg(y.mem.base), math.Scale(reg(y.mem.index), y.mem.scale)),
                    Word{static_cast<std::uint64_t>(y.mem.disp.value)});
                if (d.instruction.address_width == 32)
                    computed = math.Bitwise(ZYDIS_MNEMONIC_AND, std::move(computed), Word{0xffffffffu});
            }
            if (op == ZYDIS_MNEMONIC_ADD || op == ZYDIS_MNEMONIC_SUB)
                computed = math.Sum(value(x), value(y), op == ZYDIS_MNEMONIC_ADD ? 1 : ~0ull);
            if (op == ZYDIS_MNEMONIC_NOT || op == ZYDIS_MNEMONIC_NEG)
                computed = math.Sum(math.Scale(value(x), ~0ull), Word{op == ZYDIS_MNEMONIC_NOT ? ~0ull : 0});
            if (op == ZYDIS_MNEMONIC_XOR || op == ZYDIS_MNEMONIC_AND || op == ZYDIS_MNEMONIC_OR)
                computed = math.Bitwise(op, value(x), value(y));
            if (op == ZYDIS_MNEMONIC_SHL && y.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                computed = math.Scale(value(x), 1ull << (y.imm.value.u & (x.size == 64 ? 63 : 31)));
            if (x.size < 64)
                computed = math.Bitwise(ZYDIS_MNEMONIC_AND, std::move(computed), Word{(1ull << x.size) - 1});
            const auto id =
                ZydisRegisterGetId(ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, x.reg.value));
            registers[id] = x.size >= 32 ? computed : math.Unknown();
            bool flags_dead = false;
            if (x.size == 64 && computed.terms.empty() && d.instruction.cpu_flags) {
                auto remaining = d.instruction.cpu_flags->modified | d.instruction.cpu_flags->set_0 |
                    d.instruction.cpu_flags->set_1 | d.instruction.cpu_flags->undefined;
                for (std::size_t next = static_cast<std::size_t>(&d - result.instructions.data()) + 1;
                    next < result.instructions.size() && remaining; ++next) {
                    const auto& after = result.instructions[next];
                    const auto* flags = after.instruction.cpu_flags;
                    if (flags && (flags->tested & remaining))
                        break;
                    if (flags)
                        remaining &= ~(flags->modified | flags->set_0 | flags->set_1 | flags->undefined);
                    if (!remaining) {
                        flags_dead = true;
                        break;
                    }
                    const auto category = after.instruction.meta.category;
                    if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_RET ||
                        category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR)
                        break;
                }
            }
            if (x.size == 64 && computed.terms.empty() &&
                (op == ZYDIS_MNEMONIC_MOV || op == ZYDIS_MNEMONIC_LEA || op == ZYDIS_MNEMONIC_NOT ||
                    flags_dead)) {
                std::array<std::byte, 10> bytes{std::byte(id < 8 ? 0x48 : 0x49), std::byte(0xb8 + (id & 7))};
                std::memcpy(bytes.data() + 2, &computed.constant, 8);
                Emulator::Decoded replacement{};
                replacement.address = d.address;
                if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes.data(), bytes.size(),
                        &replacement.instruction, replacement.operands.data()))) {
                    replacement.instruction.length = d.instruction.length;
                    d = std::move(replacement);
                }
            }
        }
        for (unsigned j = 1; j < d.instruction.operand_count; ++j) {
            const auto& operand = d.operands[j];
            if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                (operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) && Dependency(operand.reg.value))
                registers[ZydisRegisterGetId(ZydisRegisterGetLargestEnclosing(
                    ZYDIS_MACHINE_MODE_LONG_64, operand.reg.value))] = math.Unknown();
        }
        if (d.instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
            d.instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
            d.instruction.meta.category == ZYDIS_CATEGORY_CALL ||
            d.instruction.meta.category == ZYDIS_CATEGORY_RET)
            reset();
    }
    return result;
}

std::optional<Expression> Alias(const Emulator::Program& code, std::size_t before, ZydisRegister output) {
    if (!Dependency(output) || before >= code.instructions.size())
        return std::nullopt;
    constexpr auto unknown = std::numeric_limits<std::int64_t>::max();
    using Values = std::array<std::int64_t, 16>;
    std::vector<std::optional<Values>> states(code.instructions.size());
    Values entry;
    entry.fill(unknown);
    entry[4] = 0;
    states[0] = entry;
    std::vector<std::size_t> pending{0};
    while (!pending.empty()) {
        const auto index = pending.back();
        pending.pop_back();
        const auto& d = code.instructions[index];
        const auto& i = d.instruction;
        auto next = *states[index];
        const auto read = [&](ZydisRegister r) {
            return Dependency(r)
                ? next[ZydisRegisterGetId(ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r))]
                : unknown;
        };
        for (unsigned j = 0; j < i.operand_count; ++j) {
            const auto& o = d.operands[j];
            if (o.type != ZYDIS_OPERAND_TYPE_REGISTER || !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) ||
                !Dependency(o.reg.value))
                continue;
            const auto id =
                ZydisRegisterGetId(ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, o.reg.value));
            if (id == 4)
                continue;
            auto result = unknown;
            if (j == 0 && o.size == 64 && !(o.actions & ZYDIS_OPERAND_ACTION_CONDWRITE)) {
                const auto& source = d.operands[1];
                if (i.mnemonic == ZYDIS_MNEMONIC_MOV && source.type == ZYDIS_OPERAND_TYPE_REGISTER)
                    result = read(source.reg.value);
                if (i.mnemonic == ZYDIS_MNEMONIC_LEA && source.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    source.mem.index == ZYDIS_REGISTER_NONE && read(source.mem.base) != unknown)
                    result = read(source.mem.base) + source.mem.disp.value;
                if ((i.mnemonic == ZYDIS_MNEMONIC_ADD || i.mnemonic == ZYDIS_MNEMONIC_SUB) &&
                    source.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && read(o.reg.value) != unknown)
                    result = read(o.reg.value) +
                        (i.mnemonic == ZYDIS_MNEMONIC_ADD ? source.imm.value.s : -source.imm.value.s);
            }
            next[id] = result;
        }
        if (i.meta.category == ZYDIS_CATEGORY_CALL)
            for (unsigned j = 0; j < 16; ++j)
                if (0xf07u & (1u << j))
                    next[j] = unknown;
        const auto push = [&](std::size_t target) {
            if (target >= states.size())
                return;
            bool changed = false;
            if (!states[target]) {
                states[target] = next;
                changed = true;
            } else
                for (unsigned j = 0; j < 16; ++j)
                    if ((*states[target])[j] != next[j] && (*states[target])[j] != unknown) {
                        (*states[target])[j] = unknown;
                        changed = true;
                    }
            if (changed)
                pending.push_back(target);
        };
        if (i.meta.category != ZYDIS_CATEGORY_RET && i.meta.category != ZYDIS_CATEGORY_UNCOND_BR)
            push(index + 1);
        if ((i.meta.category == ZYDIS_CATEGORY_COND_BR || i.meta.category == ZYDIS_CATEGORY_UNCOND_BR) &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.operands[0].imm.is_relative) {
            const auto target = d.address + i.length + d.operands[0].imm.value.s;
            const auto found = std::lower_bound(code.instructions.begin(), code.instructions.end(), target,
                [](const auto& value, std::uint64_t at) { return value.address < at; });
            if (found != code.instructions.end() && found->address == target)
                push(static_cast<std::size_t>(found - code.instructions.begin()));
        }
    }
    const auto id = ZydisRegisterGetId(ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, output));
    if (!states[before] || (*states[before])[id] == unknown)
        return std::nullopt;
    const auto offset = (*states[before])[id];
    for (auto d : code.instructions)
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_LEA && d.operands[0].size == 64 &&
            d.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && d.operands[1].mem.base == ZYDIS_REGISTER_RSP &&
            d.operands[1].mem.index == ZYDIS_REGISTER_NONE && d.operands[1].mem.disp.value == offset) {
            d.operands[0].reg.value = output;
            return Expression{{d.address, d.address + d.instruction.length, {d}, true}, output, 0};
        }
    return std::nullopt;
}
}

static std::optional<Expression> Trace(const Emulator::Program& code, std::size_t before, Location output,
    std::optional<Location> input = std::nullopt) {
    if (before > code.instructions.size() || (!output.stack && !Dependency(output.reg)))
        return std::nullopt;
    Expression result{{0, 0, {}, true}, output.reg, 0};
    auto needed = output.stack ? 0 : Dependency(output.reg);
    std::uint32_t bound{};
    ZydisAccessedFlagsMask flags{};
    std::map<std::int64_t, unsigned> slots;
    if (output.stack)
        slots.emplace(output.slot, 64);
    std::vector<std::size_t> definitions;
    std::vector<std::vector<std::size_t>> predecessors(before + 1);
    const auto boundary = code.instructions.begin() + std::min(before + 1, code.instructions.size());
    for (std::size_t at = 0; at < before; ++at) {
        const auto& d = code.instructions[at];
        const auto category = d.instruction.meta.category;
        if (category != ZYDIS_CATEGORY_RET && category != ZYDIS_CATEGORY_UNCOND_BR)
            predecessors[at + 1].push_back(at);
        if ((category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.operands[0].imm.is_relative) {
            const auto address = d.address + d.instruction.length + d.operands[0].imm.value.s;
            const auto target = std::lower_bound(code.instructions.begin(), boundary, address,
                [](const auto& value, std::uint64_t at) { return value.address < at; });
            if (target != boundary && target->address == address)
                predecessors[target - code.instructions.begin()].push_back(at);
        }
    }
    std::vector<bool> reaches(before + 1);
    std::vector<std::size_t> ancestors{before};
    while (!ancestors.empty()) {
        const auto at = ancestors.back();
        ancestors.pop_back();
        if (reaches[at])
            continue;
        reaches[at] = true;
        ancestors.insert(ancestors.end(), predecessors[at].begin(), predecessors[at].end());
    }
    for (std::size_t index = before; index > 0; --index) {
        if (!reaches[index - 1])
            continue;
        needed &= ~(1u << 4);
        if (input) {
            if (input->stack)
                slots.erase(input->slot);
            else {
                bound |= needed & Dependency(input->reg);
                needed &= ~Dependency(input->reg);
            }
        }
        const auto& d = code.instructions[index - 1];
        const auto& i = d.instruction;
        if (i.mnemonic == ZYDIS_MNEMONIC_CALL && ((needed & 0xf07u) || flags))
            return std::nullopt;
        const auto writes = i.cpu_flags
            ? (i.cpu_flags->modified | i.cpu_flags->set_0 | i.cpu_flags->set_1 | i.cpu_flags->undefined)
            : 0;
        bool selected = (flags & writes) != 0;
        for (unsigned j = 0; j < i.operand_count; ++j) {
            const auto& o = d.operands[j];
            if (!(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                continue;
            if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && (needed & Dependency(o.reg.value)))
                selected = true;
            if (LocalSlot(o) && slots.contains(o.mem.disp.value))
                selected = true;
        }
        if (!selected)
            continue;
        if (i.meta.category == ZYDIS_CATEGORY_CALL || i.meta.category == ZYDIS_CATEGORY_RET ||
            i.meta.category == ZYDIS_CATEGORY_COND_BR || i.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
            i.mnemonic == ZYDIS_MNEMONIC_PUSH || i.mnemonic == ZYDIS_MNEMONIC_POP)
            return std::nullopt;
        if (i.cpu_flags) {
            if (flags & i.cpu_flags->undefined)
                return std::nullopt;
            flags = (flags & ~writes) | i.cpu_flags->tested;
        }
        for (unsigned j = 0; j < i.operand_count; ++j) {
            const auto& o = d.operands[j];
            if (!(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                continue;
            if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && o.size >= 32 &&
                !(o.actions & ZYDIS_OPERAND_ACTION_CONDWRITE))
                needed &= ~Dependency(o.reg.value);
            if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (!LocalSlot(o))
                    return std::nullopt;
                const auto found = slots.find(o.mem.disp.value);
                if (found != slots.end()) {
                    if (o.size < found->second)
                        return std::nullopt;
                    slots.erase(found);
                }
            }
        }
        bool zero = false;
        if (i.mnemonic == ZYDIS_MNEMONIC_XOR && i.operand_count_visible == 2 &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            d.operands[0].reg.value == d.operands[1].reg.value)
            zero = true;
        for (unsigned j = 0; j < i.operand_count; ++j) {
            const auto& o = d.operands[j];
            if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                needed |= Dependency(o.mem.base) | Dependency(o.mem.index);
                if (LocalSlot(o) && (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) &&
                    i.mnemonic != ZYDIS_MNEMONIC_LEA)
                    slots[o.mem.disp.value] =
                        std::max(slots[o.mem.disp.value], static_cast<unsigned>(o.size));
            }
            if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) &&
                !zero)
                needed |= Dependency(o.reg.value);
        }
        result.code.instructions.push_back(d);
        definitions.push_back(index - 1);
    }
    needed &= ~(1u << 4);
    if (input) {
        if (input->stack)
            slots.erase(input->slot);
        else {
            bound |= needed & Dependency(input->reg);
            needed &= ~Dependency(input->reg);
        }
    }
    if (flags || !slots.empty() || result.code.instructions.empty())
        return std::nullopt;
    for (const auto definition : definitions) {
        std::vector<bool> seen(before + 1);
        std::vector<std::size_t> pending{0};
        while (!pending.empty()) {
            const auto at = pending.back();
            pending.pop_back();
            if (at == definition || at > before || seen[at])
                continue;
            if (at == before)
                return std::nullopt;
            seen[at] = true;
            const auto& d = code.instructions[at];
            const auto category = d.instruction.meta.category;
            if (category == ZYDIS_CATEGORY_RET)
                continue;
            if (category != ZYDIS_CATEGORY_UNCOND_BR)
                pending.push_back(at + 1);
            if (category == ZYDIS_CATEGORY_UNCOND_BR || category == ZYDIS_CATEGORY_COND_BR) {
                const auto& o = d.operands[0];
                if (o.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !o.imm.is_relative)
                    return std::nullopt;
                const auto target = d.address + d.instruction.length + o.imm.value.s;
                const auto found = std::lower_bound(code.instructions.begin(), code.instructions.end(),
                    target, [](const auto& v, std::uint64_t address) { return v.address < address; });
                if (found != code.instructions.end() && found->address == target)
                    pending.push_back(static_cast<std::size_t>(found - code.instructions.begin()));
            }
        }
    }
    std::reverse(result.code.instructions.begin(), result.code.instructions.end());
    result.code.begin = result.code.instructions.front().address;
    const auto& last = result.code.instructions.back();
    result.code.end = last.address + last.instruction.length;
    result.inputs = needed | bound;
    return result;
}

std::optional<Expression> Slice(const Emulator::Program& code, std::size_t before, ZydisRegister output) {
    return Trace(code, before, {output});
}

std::optional<equipment::ResourcePath> WeaponResource(const Emulator::Program& native) {
    if (auto simple = equipment::WeaponResource(native))
        return simple;
    const auto& ins = native.instructions;
    ZydisRegister source = ZYDIS_REGISTER_NONE;
    std::size_t first_copy = ins.size();
    unsigned copies{};
    std::optional<equipment::ResourcePath> accepted;
    for (std::size_t i = 0; i + 1 < ins.size(); ++i) {
        const auto& d = ins[i];
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_RET)
            break;
        if (!source && d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[0].size == 64 &&
            d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            d.operands[1].reg.value == ZYDIS_REGISTER_RCX)
            source = d.operands[0].reg.value;
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV && d.instruction.mnemonic != ZYDIS_MNEMONIC_MOVZX)
            continue;
        if (d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            d.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || d.operands[1].mem.base != source ||
            d.operands[1].mem.index != ZYDIS_REGISTER_NONE)
            continue;
        const auto field = d.operands[1].mem.disp.value;
        const auto& next = ins[i + 1];
        if (field >= 0x98 && field <= 0xae && (d.operands[1].size == 8 || d.operands[1].size == 32) &&
            next.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            next.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && next.operands[0].mem.base != source &&
            next.operands[0].mem.disp.value == field &&
            Dependency(next.operands[1].reg.value) == Dependency(d.operands[0].reg.value)) {
            if (!copies)
                first_copy = i;
            ++copies;
        }
        if (copies < 4 || d.operands[1].size != 64 || field < 0x40 || field >= 0x98)
            continue;
        const auto output = d.operands[0].reg.value;
        std::size_t end = i + 1;
        bool rotation{};
        for (; end < ins.size(); ++end) {
            const auto& at = ins[end];
            if (at.instruction.meta.category == ZYDIS_CATEGORY_CALL ||
                at.instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                at.instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                at.instruction.mnemonic == ZYDIS_MNEMONIC_RET)
                break;
            bool reads{}, writes{};
            for (unsigned op = 0; op < at.instruction.operand_count; ++op) {
                const auto& o = at.operands[op];
                if (o.type != ZYDIS_OPERAND_TYPE_REGISTER || Dependency(o.reg.value) != Dependency(output))
                    continue;
                reads |= (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
                writes |= (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
            }
            if (reads && !writes)
                break;
            rotation |= writes &&
                (at.instruction.mnemonic == ZYDIS_MNEMONIC_ROL ||
                    at.instruction.mnemonic == ZYDIS_MNEMONIC_ROR);
        }
        if (!rotation || end == ins.size())
            continue;
        Emulator::Program region;

        for (std::size_t seed = 0; seed < first_copy; ++seed) {
            const auto& at = ins[seed];
            if (at.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                at.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                at.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                (Dependency(at.operands[0].reg.value) & 0xf0e8u))
                region.instructions.push_back(at);
        }
        bool unsupported_branch{};
        for (std::size_t k = first_copy; k < end; ++k) {
            const auto& at = ins[k];
            if (at.instruction.meta.category == ZYDIS_CATEGORY_COND_BR) {

                const auto target = at.address + at.instruction.length + at.operands[0].imm.value.s;
                const auto side = std::lower_bound(ins.begin(), ins.end(), target,
                    [](const auto& v, std::uint64_t address) { return v.address < address; });
                if (side == ins.end() || side + 1 == ins.end() || side->address != target ||
                    side->instruction.mnemonic != ZYDIS_MNEMONIC_ADD ||
                    !(side->instruction.attributes & ZYDIS_ATTRIB_HAS_LOCK) ||
                    side->operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                    side->operands[0].mem.disp.value != 8 ||
                    (side + 1)->instruction.meta.category != ZYDIS_CATEGORY_UNCOND_BR ||
                    (side + 1)->operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                    (side + 1)->address + (side + 1)->instruction.length +
                            (side + 1)->operands[0].imm.value.s !=
                        at.address + at.instruction.length) {
                    unsupported_branch = true;
                    break;
                }
                continue;
            }
            region.instructions.push_back(at);
        }
        if (unsupported_branch)
            continue;
        region.begin = region.instructions.front().address;
        region.end = ins[end - 1].address + ins[end - 1].instruction.length;
        region.linear = true;
        auto normalized = Simplify(region);
        const auto value = Slice(normalized, normalized.instructions.size(), output);
#ifdef LIFUS_EQUIPMENT_TRACE
        std::fprintf(stderr, "weapon candidate field %llx copies %u end %zu slice %d inputs %x source %x\n",
            static_cast<unsigned long long>(field), copies, end, bool(value), value ? value->inputs : 0,
            dependency(source));
        if (value) {
            ZydisFormatter debug_formatter{};
            ZydisFormatterInit(&debug_formatter, ZYDIS_FORMATTER_STYLE_INTEL);
            for (const auto& at : value->code.instructions) {
                char debug_text[256]{};
                ZydisFormatterFormatInstruction(&debug_formatter, &at.instruction, at.operands.data(),
                    at.instruction.operand_count_visible, debug_text, sizeof(debug_text), at.address,
                    nullptr);
                std::fprintf(stderr, "%llx: %s\n", static_cast<unsigned long long>(at.address), debug_text);
            }
        }
#endif
        if (!value || value->inputs != Dependency(source))
            continue;
        equipment::ResourcePath result{value->code, source, output, static_cast<std::uint32_t>(field)};
        if (accepted)
            return std::nullopt;
        accepted = std::move(result);
    }
    return accepted;
}

std::vector<SerializedMember> SerializedMembers(const Emulator::Program& native) {
    std::vector<SerializedMember> result;
    const auto& ins = native.instructions;
    for (std::size_t i = 1; i < ins.size(); ++i) {
        const auto& d = ins[i];
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_RET)
            break;
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !d.operands[0].imm.is_relative)
            continue;

        bool descriptor_load{};
        for (std::size_t j = i; j && i - j < 8; --j) {
            const auto& at = ins[j - 1];
            descriptor_load |= at.instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
                at.operands[0].reg.value == ZYDIS_REGISTER_RDX &&
                at.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                at.operands[1].mem.base == ZYDIS_REGISTER_RIP;
        }
        if (!descriptor_load)
            continue;
        auto descriptor = Slice(native, i, ZYDIS_REGISTER_RDX);
        if (!descriptor || descriptor->inputs)
            continue;
        auto data = Slice(native, i, ZYDIS_REGISTER_R8);
        if (!data || data->inputs != Dependency(ZYDIS_REGISTER_RCX))
            continue;
        result.push_back({std::move(*data), std::move(*descriptor),
            d.address + d.instruction.length + d.operands[0].imm.value.s});
    }
    return result;
}

std::optional<std::uint32_t> SerializationCodecField(const Emulator::Program& native) {
    const auto& ins = native.instructions;
    std::optional<std::uint32_t> accepted;
    for (std::size_t i = 0; i < ins.size(); ++i) {
        const auto& d = ins[i];
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
            continue;
        const auto callback = Slice(native, i, d.operands[0].reg.value);
        const auto receiver = Slice(native, i, ZYDIS_REGISTER_RCX);
        if (!callback || callback->inputs != Dependency(ZYDIS_REGISTER_RDX) || !receiver ||
            receiver->inputs != Dependency(ZYDIS_REGISTER_R8))
            continue;
        for (const auto& at : callback->code.instructions) {
            const auto& memory = at.operands[1];
            if (at.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || memory.type != ZYDIS_OPERAND_TYPE_MEMORY ||
                memory.mem.index != ZYDIS_REGISTER_NONE || memory.mem.disp.value <= 0 ||
                memory.mem.disp.value >= 0x200)
                continue;
            const auto field = static_cast<std::uint32_t>(memory.mem.disp.value);
            if (accepted && *accepted != field)
                return std::nullopt;
            accepted = field;
        }
    }
    return accepted;
}

std::optional<std::uint64_t> InlineNameCodec(const Emulator::Program& native) {
    bool hash{}, flag{};
    std::optional<std::uint64_t> characters;
    const auto& ins = native.instructions;
    for (std::size_t i = 0; i < ins.size(); ++i) {
        const auto& d = ins[i];
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && d.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            d.operands[0].mem.index == ZYDIS_REGISTER_NONE && d.operands[0].mem.base != ZYDIS_REGISTER_RSP) {
            const auto owner = Slice(native, i, d.operands[0].mem.base);
            if (owner && owner->inputs == Dependency(ZYDIS_REGISTER_RCX)) {
                hash |= d.operands[0].mem.disp.value == 0x10 && d.operands[0].size == 64;
                flag |= d.operands[0].mem.disp.value == 0x18 && d.operands[0].size == 8;
            }
        }
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !d.operands[0].imm.is_relative)
            continue;
        const auto receiver = Slice(native, i, ZYDIS_REGISTER_RDX);
        const auto stream = Slice(native, i, ZYDIS_REGISTER_RCX);
        if (!receiver || receiver->inputs != Dependency(ZYDIS_REGISTER_RCX) || !stream ||
            stream->inputs != Dependency(ZYDIS_REGISTER_RDX))
            continue;
        const auto target = d.address + d.instruction.length + d.operands[0].imm.value.s;
        if (characters && *characters != target)
            return std::nullopt;
        characters = target;
    }
    return hash && flag ? characters : std::nullopt;
}

bool InlineStringCodec(const Emulator::Program& native) {
    bool tag{}, mode{}, capacity{}, allocation{};
    const auto& ins = native.instructions;
    constexpr auto unknown = std::numeric_limits<std::int64_t>::max();
    using Aliases = std::array<std::int64_t, 16>;
    std::vector<std::optional<Aliases>> incoming(ins.size());
    if (ins.empty())
        return false;
    Aliases entry;
    entry.fill(unknown);
    entry[2] = 0;
    incoming[0] = entry;
    std::vector<std::size_t> pending{0};

    while (!pending.empty()) {
        const auto i = pending.back();
        pending.pop_back();
        const auto& d = ins[i];
        auto next = *incoming[i];
        for (unsigned operand = 0; operand < d.instruction.operand_count; ++operand) {
            const auto& o = d.operands[operand];
            if (o.type != ZYDIS_OPERAND_TYPE_REGISTER || !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) ||
                !Dependency(o.reg.value))
                continue;
            const auto id =
                ZydisRegisterGetId(ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, o.reg.value));
            auto value = unknown;
            if (operand == 0 && o.size == 64 && !(o.actions & ZYDIS_OPERAND_ACTION_CONDWRITE) &&
                d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && Dependency(d.operands[1].reg.value))
                value = (*incoming[i])[ZydisRegisterGetId(
                    ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, d.operands[1].reg.value))];
            next[id] = value;
        }
        if (d.instruction.meta.category == ZYDIS_CATEGORY_CALL)
            for (unsigned reg = 0; reg < 16; ++reg)
                if (0xf07u & (1u << reg))
                    next[reg] = unknown;
        const auto push = [&](std::size_t target) {
            if (target >= ins.size())
                return;
            bool changed{};
            if (!incoming[target]) {
                incoming[target] = next;
                changed = true;
            } else
                for (unsigned reg = 0; reg < 16; ++reg)
                    if ((*incoming[target])[reg] != next[reg] && (*incoming[target])[reg] != unknown) {
                        (*incoming[target])[reg] = unknown;
                        changed = true;
                    }
            if (changed)
                pending.push_back(target);
        };
        const auto category = d.instruction.meta.category;
        if (category != ZYDIS_CATEGORY_RET && category != ZYDIS_CATEGORY_UNCOND_BR)
            push(i + 1);
        if ((category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.operands[0].imm.is_relative) {
            const auto target = d.address + d.instruction.length + d.operands[0].imm.value.s;
            const auto at = std::lower_bound(ins.begin(), ins.end(), target,
                [](const auto& value, std::uint64_t address) { return value.address < address; });
            if (at != ins.end() && at->address == target)
                push(static_cast<std::size_t>(at - ins.begin()));
        }
    }
    for (std::size_t i = 0; i < ins.size(); ++i) {
        const auto& d = ins[i];
        for (unsigned operand = 0; operand < d.instruction.operand_count_visible; ++operand) {
            const auto& o = d.operands[operand];
            if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                capacity |= o.imm.value.u == 15;
                allocation |= o.imm.value.u == 16;
            }
            if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.size != 8 || o.mem.index != ZYDIS_REGISTER_NONE ||
                (o.mem.disp.value != 0 && o.mem.disp.value != 1) ||
                !(o.actions & ZYDIS_OPERAND_ACTION_MASK_READ))
                continue;
            if (!incoming[i] || !Dependency(o.mem.base) ||
                (*incoming[i])[ZydisRegisterGetId(
                    ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, o.mem.base))] != 0)
                continue;
            tag |= o.mem.disp.value == 0;
            mode |= o.mem.disp.value == 1;
        }
    }
#ifdef LIFUS_EQUIPMENT_TRACE
    std::fprintf(
        stderr, "string codec tag %d mode %d capacity %d allocation %d\n", tag, mode, capacity, allocation);
#endif
    return tag && mode && capacity && allocation;
}

std::optional<PointerDescriptor> Flow(
    const Emulator::Program& source, std::size_t begin, std::size_t end, Location input, Location output) {
    const auto code = Simplify(source);
    if (begin >= code.instructions.size() || end >= code.instructions.size() || begin == end)
        return std::nullopt;
    const auto& instructions = code.instructions;

    struct State {
        std::uint32_t registers{};
        ZydisAccessedFlagsMask flags{};
        std::map<std::int64_t, unsigned> slots;
        bool operator==(const State&) const = default;
    };

    const auto merge = [](State& a, const State& b) {
        a.registers |= b.registers;
        a.flags |= b.flags;
        for (const auto& [slot, bits] : b.slots)
            a.slots[slot] = std::max(a.slots[slot], bits);
    };
    std::map<std::size_t, std::vector<std::size_t>> edges;
    std::vector<std::size_t> pending{begin};
    while (!pending.empty()) {
        const auto index = pending.back();
        pending.pop_back();
        if (index == end || edges.contains(index))
            continue;
        if (index >= instructions.size() || edges.size() >= 512)
            return std::nullopt;
        const auto& d = instructions[index];
        const auto category = d.instruction.meta.category;
        if (category == ZYDIS_CATEGORY_RET || category == ZYDIS_CATEGORY_CALL)
            return std::nullopt;
        auto& successors = edges[index];
        if (category != ZYDIS_CATEGORY_UNCOND_BR)
            successors.push_back(index + 1);
        if (category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) {
            const auto& o = d.operands[0];
            if (o.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !o.imm.is_relative)
                return std::nullopt;
            const auto target = d.address + d.instruction.length + o.imm.value.s;
            const auto found = std::lower_bound(instructions.begin(), instructions.end(), target,
                [](const auto& v, std::uint64_t address) { return v.address < address; });
            if (found == instructions.end() || found->address != target)
                return std::nullopt;
            successors.push_back(static_cast<std::size_t>(found - instructions.begin()));
        }
        pending.insert(pending.end(), successors.begin(), successors.end());
    }
    std::map<std::size_t, State> live;
    if (output.stack)
        live[end].slots.emplace(output.slot, 64);
    else
        live[end].registers = Dependency(output.reg);
    if (!live[end].registers && live[end].slots.empty())
        return std::nullopt;
    std::map<std::size_t, bool> selected;
    for (unsigned round = 0; round <= edges.size() + 1; ++round) {
        bool changed = false;
        for (auto at = edges.rbegin(); at != edges.rend(); ++at) {
            const auto index = at->first;
            const auto& d = instructions[index];
            const auto& i = d.instruction;
            State needed;
            for (const auto next : at->second)
                merge(needed, live[next]);
            const auto writes = i.cpu_flags
                ? (i.cpu_flags->modified | i.cpu_flags->set_0 | i.cpu_flags->set_1 | i.cpu_flags->undefined)
                : 0;
            const bool branch =
                i.meta.category == ZYDIS_CATEGORY_COND_BR || i.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
            bool keep = branch || (needed.flags & writes) != 0;
            for (unsigned j = 0; j < i.operand_count; ++j) {
                const auto& o = d.operands[j];
                if (!(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                    continue;
                keep |= o.type == ZYDIS_OPERAND_TYPE_REGISTER && (needed.registers & Dependency(o.reg.value));
                keep |= LocalSlot(o) && needed.slots.contains(o.mem.disp.value);
            }
            selected[index] = keep;
            if (keep) {
                if (i.cpu_flags) {
                    if (needed.flags & i.cpu_flags->undefined)
                        return std::nullopt;
                    needed.flags = (needed.flags & ~writes) | i.cpu_flags->tested;
                }
                for (unsigned j = 0; j < i.operand_count; ++j) {
                    const auto& o = d.operands[j];
                    if (!(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                        continue;
                    if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && o.size >= 32 &&
                        !(o.actions & ZYDIS_OPERAND_ACTION_CONDWRITE))
                        needed.registers &= ~Dependency(o.reg.value);
                    if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        if (!LocalSlot(o))
                            return std::nullopt;
                        if (const auto found = needed.slots.find(o.mem.disp.value);
                            found != needed.slots.end()) {
                            if (o.size < found->second)
                                return std::nullopt;
                            needed.slots.erase(found);
                        }
                    }
                }
                const bool zero = i.mnemonic == ZYDIS_MNEMONIC_XOR &&
                    d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    d.operands[0].reg.value == d.operands[1].reg.value;
                for (unsigned j = 0; j < i.operand_count; ++j) {
                    const auto& o = d.operands[j];
                    if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                        needed.registers |= Dependency(o.mem.base) | Dependency(o.mem.index);
                        if (LocalSlot(o) && (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) &&
                            i.mnemonic != ZYDIS_MNEMONIC_LEA)
                            needed.slots[o.mem.disp.value] =
                                std::max(needed.slots[o.mem.disp.value], static_cast<unsigned>(o.size));
                    }
                    if (o.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) && !zero)
                        needed.registers |= Dependency(o.reg.value);
                }
            }
            needed.registers &= ~(1u << 4);
            if (needed != live[index]) {
                live[index] = std::move(needed);
                changed = true;
            }
        }
        if (!changed)
            break;
        if (round == edges.size() + 1)
            return std::nullopt;
    }
    if (live[begin].flags)
        return std::nullopt;
    PointerDescriptor result{
        {instructions[begin].address, instructions[end].address, {}, false, true}, input, output, {}};
    for (const auto& [index, keep] : selected)
        if (keep)
            result.code.instructions.push_back(instructions[index]);
    result.code.instructions.push_back(instructions[end]);
    std::sort(result.code.instructions.begin(), result.code.instructions.end(),
        [](const auto& a, const auto& b) { return a.address < b.address; });
    const auto entry = std::lower_bound(result.code.instructions.begin(), result.code.instructions.end(),
        instructions[begin].address,
        [](const auto& value, std::uint64_t address) { return value.address < address; });
    if (entry == result.code.instructions.end())
        return std::nullopt;
    result.code.begin = entry->address;
    const auto add_seed = [&](Location target) {
        auto value = Trace(code, begin, target, input);
        if ((!value || (value->inputs & ~(input.stack ? 0u : Dependency(input.reg)))) && !target.stack)
            value = Alias(code, begin, target.reg);
        if (!value || (value->inputs & ~(input.stack ? 0u : Dependency(input.reg)))) {
            return false;
        }
        result.seeds.push_back({target, std::move(*value)});
        return true;
    };
    const auto registers = live[begin].registers & ~(input.stack ? 0u : Dependency(input.reg));
    for (unsigned j = 0; j < 16; ++j)
        if ((registers & (1u << j)) &&
            !add_seed({ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, static_cast<ZyanU8>(j))}))
            return std::nullopt;
    for (const auto& [slot, bits] : live[begin].slots)
        if ((!input.stack || slot != input.slot) && !add_seed({ZYDIS_REGISTER_NONE, slot, true}))
            return std::nullopt;
    return result;
}

std::optional<MetadataDescriptor> Metadata(const Emulator::Program& code) {
    for (std::size_t j = 0; j + 4 < code.instructions.size() && j < 12; ++j) {
        const auto& a = code.instructions[j];
        const auto& b = code.instructions[j + 1];
        if (a.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || b.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            a.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || a.operands[0].size != 64 ||
            a.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || a.operands[1].mem.base != ZYDIS_REGISTER_RCX ||
            a.operands[1].mem.index != ZYDIS_REGISTER_NONE || a.operands[1].mem.disp.value != 0 ||
            b.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || b.operands[0].size != 64 ||
            b.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
            b.operands[1].mem.base != a.operands[0].reg.value ||
            b.operands[1].mem.index != ZYDIS_REGISTER_NONE)
            continue;
        const auto info = b.operands[0].reg.value;
        ZydisRegister output = ZYDIS_REGISTER_NONE;
        std::int64_t field = -1;
        std::size_t end = j + 2;
        for (; end < code.instructions.size() && end < j + 14; ++end) {
            const auto& d = code.instructions[end];
            if (d.instruction.operand_count_visible < 2 ||
                d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || d.operands[0].size != 32 ||
                (output != ZYDIS_REGISTER_NONE && d.operands[0].reg.value != output))
                break;
            if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV &&
                d.instruction.mnemonic != ZYDIS_MNEMONIC_ADD &&
                d.instruction.mnemonic != ZYDIS_MNEMONIC_SUB &&
                d.instruction.mnemonic != ZYDIS_MNEMONIC_XOR &&
                d.instruction.mnemonic != ZYDIS_MNEMONIC_ROL && d.instruction.mnemonic != ZYDIS_MNEMONIC_ROR)
                break;
            output = d.operands[0].reg.value;
            if (d.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                if (field != -1 || d.operands[1].mem.base != info ||
                    d.operands[1].mem.index != ZYDIS_REGISTER_NONE)
                    break;
                field = d.operands[1].mem.disp.value;
            }
        }
        const auto table = b.operands[1].mem.disp.value;
        if (field < 0 || field > 0x1000 || table < 0 || table > 0x1000 || output == ZYDIS_REGISTER_NONE)
            continue;
        auto expression = Slice(code, end, output);
        if (!expression || expression->inputs != 2u)
            continue;
        return MetadataDescriptor{
            std::move(*expression), static_cast<std::uint32_t>(table), static_cast<std::uint32_t>(field)};
    }
    return std::nullopt;
}

std::optional<Expression> Root(const Emulator::Program& code, const ValidationObserver& validation) {
    bool ring = false, divide = false, stride = false;
    for (const auto& d : code.instructions)
        for (unsigned j = 0; j < d.instruction.operand_count_visible; ++j) {
            const auto& o = d.operands[j];
            if (o.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
                continue;
            ring |= o.imm.value.u == 0x14f8b589;
            divide |= o.imm.value.u == 0xc350;
            stride |= o.imm.value.u == 0x198;
        }
    if (!ring || !divide || !stride) {
        if (validation)
            validation(!ring  ? "root ring anchor missing"
                    : !divide ? "root divisor anchor missing"
                              : "root stride anchor missing",
                code.begin, (ring ? 1u : 0u) | (divide ? 2u : 0u) | (stride ? 4u : 0u));
        return std::nullopt;
    }
    for (std::size_t j = 0; j < code.instructions.size(); ++j) {
        const auto& d = code.instructions[j];
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || d.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
            d.operands[1].mem.index != ZYDIS_REGISTER_NONE || d.operands[1].mem.base == ZYDIS_REGISTER_RIP ||
            d.operands[1].mem.base == ZYDIS_REGISTER_RSP || d.operands[1].mem.disp.value <= 0)
            continue;
        auto result = Slice(code, j, d.operands[1].mem.base);
        if (!result || result->inputs || result->code.instructions.empty()) {
            if (validation)
                validation(
                    !result ? "root receiver dataflow unresolved" : "root receiver requires external inputs",
                    d.address, result ? result->inputs : 0);
            continue;
        }
        const auto& tail = result->code.instructions.back();
        const bool tls = tail.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            tail.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && tail.operands[1].mem.scale == 8 &&
            tail.operands[1].mem.index != ZYDIS_REGISTER_NONE &&
            std::any_of(
                result->code.instructions.begin(), result->code.instructions.end(), [&](const auto& load) {
                    return load.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                        load.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        load.operands[0].reg.value == tail.operands[1].mem.base &&
                        load.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        load.operands[1].mem.segment == ZYDIS_REGISTER_GS &&
                        load.operands[1].mem.disp.value == 0x58;
                });
        if (!tls)
            return result;
        if (validation)
            validation("root receiver is a tls container", d.address, 0);
    }
    if (validation)
        validation("root receiver not proven", code.begin, 0);
    return std::nullopt;
}

std::optional<Expression> Camera(const Emulator::Program& code) {
    for (std::size_t j = 0; j < code.instructions.size(); ++j) {
        const auto& d = code.instructions[j];
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || d.operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
            d.operands[0].mem.index != ZYDIS_REGISTER_NONE || d.operands[0].mem.base == ZYDIS_REGISTER_RSP ||
            d.operands[0].mem.base == ZYDIS_REGISTER_RIP || d.operands[0].mem.disp.value <= 0 ||
            d.operands[0].size != 64 || d.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
            continue;
        bool owned = false;
        for (std::size_t k = 0; k < j; ++k) {
            const auto& p = code.instructions[k];
            owned |= p.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                p.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                p.operands[1].mem.base == d.operands[0].mem.base && p.operands[1].mem.disp.value > 0;
        }
        if (!owned)
            continue;
        auto result = Slice(code, j, d.operands[0].mem.base);
        if (result && !result->inputs)
            return result;
    }
    return std::nullopt;
}

std::vector<RigDescriptor> RigLookups(const Emulator::Program& code) {
    std::vector<RigDescriptor> result;
    const auto& instructions = code.instructions;
    for (std::size_t j = 0; j + 2 < instructions.size(); ++j) {
        const auto& shift = instructions[j + 2];
        const bool reversed = instructions[j].operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            instructions[j].operands[0].reg.value == shift.operands[0].reg.value;
        const auto& table = instructions[j + (reversed ? 1 : 0)];
        const auto& count = instructions[j + (reversed ? 0 : 1)];
        const auto& a = table.operands[1];
        const auto& b = count.operands[1];
        if (table.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            count.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || a.type != ZYDIS_OPERAND_TYPE_MEMORY ||
            b.type != ZYDIS_OPERAND_TYPE_MEMORY || a.size != 64 || (b.size != 32 && b.size != 64) ||
            a.mem.base != b.mem.base || !Dependency(a.mem.base) || a.mem.base == ZYDIS_REGISTER_RSP ||
            a.mem.index != ZYDIS_REGISTER_NONE || b.mem.index != ZYDIS_REGISTER_NONE ||
            a.mem.disp.value <= 0 || a.mem.disp.value >= 0x10000 ||
            b.mem.disp.value != a.mem.disp.value + 8 || shift.instruction.mnemonic != ZYDIS_MNEMONIC_SHL ||
            shift.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            shift.operands[0].reg.value != count.operands[0].reg.value ||
            shift.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || shift.operands[1].imm.value.u != 3)
            continue;
        ZydisRegister indexed = ZYDIS_REGISTER_NONE, equality = ZYDIS_REGISTER_NONE;
        for (std::size_t k = j + 3;
            k < instructions.size() && instructions[k].address - table.address < 0x100; ++k) {
            const auto& d = instructions[k];
            if (d.instruction.mnemonic != ZYDIS_MNEMONIC_CMP ||
                d.operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY || d.operands[0].size != 32 ||
                d.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                static_cast<std::uint32_t>(d.operands[1].imm.value.u) != 0xa9cefd4a)
                continue;
            if (d.operands[0].mem.index != ZYDIS_REGISTER_NONE && d.operands[0].mem.scale == 8)
                indexed = d.operands[0].mem.base;
            if (d.operands[0].mem.index == ZYDIS_REGISTER_NONE)
                equality = d.operands[0].mem.base;
        }
        if (indexed == ZYDIS_REGISTER_NONE || indexed != equality)
            continue;
        bool iterator = false, index = false;
        for (std::size_t k = j + 3;
            k < instructions.size() && instructions[k].address - table.address < 0x100; ++k) {
            const auto& d = instructions[k];
            iterator |= d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[0].reg.value == indexed &&
                d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                d.operands[1].reg.value == table.operands[0].reg.value;
            index |= d.instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX &&
                d.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && d.operands[1].size == 16 &&
                d.operands[1].mem.base == indexed && d.operands[1].mem.index == ZYDIS_REGISTER_NONE &&
                d.operands[1].mem.disp.value == 4;
        }
        if (!iterator || !index)
            continue;

        std::vector<std::vector<std::size_t>> predecessors(instructions.size());
        for (std::size_t k = 0; k < instructions.size(); ++k) {
            const auto& d = instructions[k];
            const auto category = d.instruction.meta.category;
            if (category != ZYDIS_CATEGORY_RET && category != ZYDIS_CATEGORY_UNCOND_BR &&
                k + 1 < instructions.size())
                predecessors[k + 1].push_back(k);
            if ((category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) &&
                d.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.operands[0].imm.is_relative) {
                const auto address = d.address + d.instruction.length + d.operands[0].imm.value.s;
                const auto to = std::lower_bound(instructions.begin(), instructions.end(), address,
                    [](const auto& v, std::uint64_t at) { return v.address < at; });
                if (to != instructions.end() && to->address == address)
                    predecessors[to - instructions.begin()].push_back(k);
            }
        }
        std::vector<bool> seen(instructions.size());
        std::vector<std::size_t> pending = predecessors[j];
        std::optional<std::size_t> definition;
        bool valid = true;
        while (!pending.empty() && valid) {
            const auto k = pending.back();
            pending.pop_back();
            if (seen[k])
                continue;
            seen[k] = true;
            const auto& d = instructions[k];
            bool writes =
                d.instruction.meta.category == ZYDIS_CATEGORY_CALL && (Dependency(a.mem.base) & 0xf07u);
            for (unsigned operand = 0; operand < d.instruction.operand_count; ++operand) {
                const auto& o = d.operands[operand];
                writes |= o.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                    (Dependency(o.reg.value) & Dependency(a.mem.base));
            }
            if (writes) {
                if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || d.operands[0].size != 64 ||
                    d.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                    d.operands[1].mem.base == ZYDIS_REGISTER_RSP ||
                    d.operands[1].mem.base == ZYDIS_REGISTER_RIP ||
                    d.operands[1].mem.index != ZYDIS_REGISTER_NONE || d.operands[1].mem.disp.value <= 0 ||
                    (definition && *definition != k))
                    valid = false;
                else
                    definition = k;
            } else if (predecessors[k].empty())
                valid = false;
            else
                pending.insert(pending.end(), predecessors[k].begin(), predecessors[k].end());
        }
        if (valid && definition)
            if (auto value = Slice(code, *definition + 1, a.mem.base); value && value->inputs == 2u)
                result.push_back({std::move(*value), static_cast<std::uint32_t>(a.mem.disp.value),
                    static_cast<std::uint8_t>(b.size)});
    }
    return result;
}

std::vector<ArrayDescriptor> Arrays(const Emulator::Program& code) {
    std::vector<ArrayDescriptor> result;
    const auto& instructions = code.instructions;
    const auto field = [](const Emulator::Decoded& d, unsigned operand) {
        return d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            d.operands[operand].type == ZYDIS_OPERAND_TYPE_MEMORY && d.operands[operand].size == 64 &&
            d.operands[operand].mem.base == ZYDIS_REGISTER_RSP &&
            d.operands[operand].mem.index == ZYDIS_REGISTER_NONE;
    };
    for (std::size_t count = 1; count < instructions.size(); ++count) {
        const auto& store = instructions[count];
        if (!field(store, 0) || store.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
            continue;
        const auto slot = store.operands[0].mem.disp.value;
        if (slot < 8 || slot > 0x7000)
            continue;
        auto pointer = count;
        for (std::size_t j = count; j > 0 && count - j < 16; --j)
            if (field(instructions[j - 1], 0) && instructions[j - 1].operands[0].mem.disp.value == slot - 8 &&
                instructions[j - 1].operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                pointer = j - 1;
                break;
            }
        if (pointer == count)
            continue;
        bool consumed = false;
        for (std::size_t j = count + 1; j < instructions.size() && j - count < 256; ++j) {
            const auto& load = instructions[j];
            if (!LocalSlot(load.operands[1]) || load.operands[1].mem.disp.value != slot ||
                load.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                load.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
                continue;
            auto aliases = Dependency(load.operands[0].reg.value);
            for (std::size_t k = j + 1; k < instructions.size() && k - j < 8; ++k) {
                const auto& use = instructions[k];
                const auto category = use.instruction.meta.category;
                if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_RET ||
                    category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR)
                    break;
                if (use.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
                    continue;
                const auto target = Dependency(use.operands[0].reg.value);
                if ((aliases & target) && use.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    ((use.instruction.mnemonic == ZYDIS_MNEMONIC_AND &&
                         use.operands[1].imm.value.u == 0x3fffffff) ||
                        (use.instruction.mnemonic == ZYDIS_MNEMONIC_SHL &&
                            use.operands[1].imm.value.u == 34))) {
                    consumed = true;
                    break;
                }
                if (use.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    use.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (aliases & Dependency(use.operands[1].reg.value)))
                    aliases |= target;
                else if (use.operands[0].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
                    aliases &= ~target;
            }
            if (consumed)
                break;
        }
        if (!consumed)
            continue;
        auto begin = pointer;
        while (begin > 0 && store.address - instructions[begin - 1].address < 0x800) {
            const auto category = instructions[begin - 1].instruction.meta.category;
            if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_COND_BR ||
                category == ZYDIS_CATEGORY_UNCOND_BR || category == ZYDIS_CATEGORY_RET)
                break;
            --begin;
        }
        Emulator::Program region{instructions[begin].address, store.address + store.instruction.length,
            {instructions.begin() + begin, instructions.begin() + count + 1}};
        region = Simplify(region);
        auto array = Slice(region, pointer - begin, instructions[pointer].operands[1].reg.value);
        auto size = Slice(region, count - begin, store.operands[1].reg.value);
        if (!array || !size || !array->inputs || array->inputs != size->inputs ||
            (array->inputs & (array->inputs - 1)) || array->output == size->output)
            continue;
        const auto input =
            ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, static_cast<ZyanU8>(std::countr_zero(array->inputs)));
        std::array<std::set<std::int64_t>, 2> members;
        for (unsigned output = 0; output < 2; ++output)
            for (const auto& d : (output ? size : array)->code.instructions)
                for (unsigned operand = 0; operand < d.instruction.operand_count_visible; ++operand) {
                    const auto& o = d.operands[operand];
                    if (o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.size == 64 &&
                        (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) && o.mem.base == input &&
                        o.mem.index == ZYDIS_REGISTER_NONE && o.mem.disp.value > 0 &&
                        o.mem.disp.value < 0x10000)
                        members[output].insert(o.mem.disp.value);
                }
        if (members[0].size() != 1 || members[1].size() != 1 ||
            *members[1].begin() != *members[0].begin() + 8)
            continue;
        const auto last_array = array->code.instructions.back().address;
        bool overwritten = false;
        for (const auto& d : size->code.instructions)
            if (d.address > last_array)
                for (unsigned operand = 0; operand < d.instruction.operand_count; ++operand) {
                    const auto& o = d.operands[operand];
                    overwritten |= o.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                        (Dependency(o.reg.value) & Dependency(array->output));
                }
        if (overwritten)
            continue;
        auto program = std::move(array->code);
        program.instructions.insert(
            program.instructions.end(), size->code.instructions.begin(), size->code.instructions.end());
        std::sort(program.instructions.begin(), program.instructions.end(),
            [](const auto& a, const auto& b) { return a.address < b.address; });
        program.instructions.erase(std::unique(program.instructions.begin(), program.instructions.end(),
                                       [](const auto& a, const auto& b) { return a.address == b.address; }),
            program.instructions.end());
        program.begin = program.instructions.front().address;
        program.end = program.instructions.back().address + program.instructions.back().instruction.length;
        result.push_back({std::move(program), input, array->output, size->output});
    }
    for (std::size_t consumer = 1; consumer < instructions.size(); ++consumer) {
        const auto& shift = instructions[consumer];
        const auto& load = instructions[consumer - 1];
        if (shift.instruction.mnemonic != ZYDIS_MNEMONIC_SHL ||
            shift.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || shift.operands[1].imm.value.u != 34 ||
            !field(load, 1) || load.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            load.operands[0].reg.value != shift.operands[0].reg.value)
            continue;
        const auto slot = load.operands[1].mem.disp.value;
        if (slot < 8 || slot > 0x7000)
            continue;
        std::size_t count = consumer, pointer = consumer;
        for (std::size_t j = consumer; j > 0 && shift.address - instructions[j - 1].address < 0x1000; --j) {
            const auto& d = instructions[j - 1];
            if (!field(d, 0) || d.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
                continue;
            if (count == consumer && d.operands[0].mem.disp.value == slot)
                count = j - 1;
            if (pointer == consumer && d.operands[0].mem.disp.value == slot - 8)
                pointer = j - 1;
            if (count != consumer && pointer != consumer)
                break;
        }
        if (count == consumer || pointer == consumer ||
            (count > pointer ? count - pointer : pointer - count) > 16)
            continue;
        const auto end = std::max(count, pointer) + 1;
        const auto first = std::min(count, pointer);
        std::size_t begin = end;
        ZydisRegister input = ZYDIS_REGISTER_NONE;
        for (std::size_t j = first;
            j > 0 && instructions[first].address - instructions[j - 1].address < 0x800; --j) {
            const auto& a = instructions[j - 1];
            const auto& b = instructions[j];
            if (a.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                b.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                a.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                b.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || a.operands[1].size != 64 ||
                b.operands[1].size != 64 || a.operands[1].mem.base != b.operands[1].mem.base ||
                a.operands[1].mem.index != ZYDIS_REGISTER_NONE ||
                b.operands[1].mem.index != ZYDIS_REGISTER_NONE || a.operands[1].mem.disp.value <= 0 ||
                b.operands[1].mem.disp.value != a.operands[1].mem.disp.value + 8 ||
                !Dependency(a.operands[1].mem.base) || a.operands[1].mem.base == ZYDIS_REGISTER_RSP)
                continue;
            input = a.operands[1].mem.base;
            begin = j - 1;
            while (begin > 0 && instructions[first].address - instructions[begin - 1].address < 0x1000) {
                const auto category = instructions[begin - 1].instruction.meta.category;
                if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_COND_BR ||
                    category == ZYDIS_CATEGORY_UNCOND_BR || category == ZYDIS_CATEGORY_RET)
                    break;
                --begin;
            }
            for (std::size_t k = begin; k < j - 1; ++k) {
                const auto& d = instructions[k];
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[0].reg.value == input &&
                    d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[1].size == 64) {
                    begin = k + 1;
                    break;
                }
            }
            break;
        }
        if (begin == end) {
            for (std::size_t j = first;
                j > 0 && instructions[first].address - instructions[j - 1].address < 0x1000; --j) {
                const auto& store = instructions[j - 1];
                if (store.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                    store.operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                    store.operands[0].mem.base != ZYDIS_REGISTER_RSP ||
                    store.operands[0].mem.index == ZYDIS_REGISTER_NONE ||
                    store.operands[0].mem.disp.value != slot - 8)
                    continue;
                for (std::size_t k = j - 1; k > 0 && store.address - instructions[k - 1].address < 0x200;
                    --k) {
                    const auto& d = instructions[k - 1];
                    if (d.instruction.mnemonic != ZYDIS_MNEMONIC_ADD ||
                        d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || d.operands[0].size != 64 ||
                        d.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !d.operands[1].imm.value.u ||
                        d.operands[1].imm.value.u > 0x10000)
                        continue;
                    const auto reg = d.operands[0].reg.value;
                    bool source = false, bounded = false;
                    for (std::size_t q = k; q < j; ++q) {
                        const auto& v = instructions[q];
                        source |= v.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                            v.operands[1].mem.base == reg && v.operands[1].mem.index != ZYDIS_REGISTER_NONE;
                        bounded |= v.instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
                            v.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                            v.operands[1].imm.value.u == 15;
                    }
                    if (source && bounded) {
                        begin = k - 1;
                        input = reg;
                        break;
                    }
                }
                if (begin != end)
                    break;
            }
        }
        if (begin == end || input == ZYDIS_REGISTER_NONE)
            continue;
        std::vector<bool> seen(end - begin + 1);
        std::vector<std::size_t> pending{begin};
        bool safe = true, tls = false;
        while (!pending.empty() && safe) {
            const auto index = pending.back();
            pending.pop_back();
            if (index == end)
                continue;
            if (index < begin || index > end) {
                safe = false;
                break;
            }
            if (seen[index - begin])
                continue;
            seen[index - begin] = true;
            const auto& d = instructions[index];
            const auto category = d.instruction.meta.category;
            if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_RET) {
                safe = false;
                break;
            }
            for (unsigned k = 0; k < d.instruction.operand_count; ++k) {
                const auto& o = d.operands[k];
                tls |= o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.segment == ZYDIS_REGISTER_GS;
                if (o.type == ZYDIS_OPERAND_TYPE_MEMORY && (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                    o.mem.base != ZYDIS_REGISTER_RSP)
                    safe = false;
            }
            if (category != ZYDIS_CATEGORY_UNCOND_BR)
                pending.push_back(index + 1);
            if (category == ZYDIS_CATEGORY_UNCOND_BR || category == ZYDIS_CATEGORY_COND_BR) {
                const auto& o = d.operands[0];
                if (o.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !o.imm.is_relative) {
                    safe = false;
                    break;
                }
                const auto target = d.address + d.instruction.length + o.imm.value.s;
                const auto found = std::lower_bound(instructions.begin(), instructions.end(), target,
                    [](const auto& v, std::uint64_t at) { return v.address < at; });
                if (found == instructions.end() || found->address != target) {
                    safe = false;
                    break;
                }
                pending.push_back(static_cast<std::size_t>(found - instructions.begin()));
            }
        }
        if (!safe || !tls || !seen[count - begin] || !seen[pointer - begin])
            continue;
        ArrayDescriptor value{
            {instructions[begin].address,
                instructions[end - 1].address + instructions[end - 1].instruction.length, {}},
            input, instructions[pointer].operands[1].reg.value, instructions[count].operands[1].reg.value};
        value.code.instructions.assign(instructions.begin() + begin, instructions.begin() + end);
        result.push_back(std::move(value));
    }
    return result;
}

namespace {
std::uint64_t RipTarget(const Emulator::Decoded& d, unsigned operand) {
    const auto& o = d.operands[operand];
    return o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.base == ZYDIS_REGISTER_RIP
        ? d.address + d.instruction.length + o.mem.disp.value
        : 0;
}

std::uint64_t DirectTarget(const Emulator::Decoded& d) {
    const auto& o = d.operands[0];
    return o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative
        ? d.address + d.instruction.length + o.imm.value.s
        : 0;
}

std::optional<OperatorNameDescriptor> NullableResource(const Emulator::Program& code, bool two_casts) {
    const auto& ins = code.instructions;
    std::vector<std::uint64_t> bounds;
    for (const auto& d : ins)
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_CMP && d.operands[0].size == 16 && RipTarget(d, 1))
            bounds.push_back(RipTarget(d, 1));
    if (bounds.size() != (two_casts ? 4u : 2u) || bounds[1] != bounds[0] + 2 ||
        (two_casts && bounds[3] != bounds[2] + 2))
        return std::nullopt;
    for (std::size_t end = 1; end < ins.size(); ++end) {
        const auto& d = ins[end - 1];
        if ((ins[end].instruction.mnemonic != ZYDIS_MNEMONIC_JZ &&
                ins[end].instruction.mnemonic != ZYDIS_MNEMONIC_JNZ) ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || d.operands[0].size != 64 ||
            !(d.operands[0].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
            continue;
        const auto output = d.operands[0].reg.value;
        if (two_casts) {
            std::optional<std::size_t> payload;
            for (std::size_t j = end + 1; j < ins.size(); ++j) {
                const auto& at = ins[j];
                if (at.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    at.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    at.operands[0].reg.value == ZYDIS_REGISTER_RAX &&
                    at.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && at.operands[1].mem.base == output &&
                    at.operands[1].mem.disp.value == 0) {
                    payload = j;
                    break;
                }
            }
            if (!payload)
                continue;
            bool changes = false;
            for (std::size_t j = *payload + 1; j < ins.size(); ++j) {
                const auto& at = ins[j];
                for (const auto& o : at.operands)
                    if (o.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                        Dependency(o.reg.value) == Dependency(ZYDIS_REGISTER_RAX))
                        changes |= at.instruction.mnemonic != ZYDIS_MNEMONIC_XOR ||
                            at.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                            at.operands[1].reg.value != at.operands[0].reg.value;
            }
            if (changes)
                continue;
        }
        auto path = Flow(code, 0, end, {ZYDIS_REGISTER_RCX}, {output});
        if (!path)
            continue;
        std::optional<std::uint32_t> field;
        for (const auto& at : path->code.instructions) {
            const auto& o = at.operands[1];
            if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.mem.base != ZYDIS_REGISTER_RCX ||
                o.mem.index != ZYDIS_REGISTER_NONE || o.size != 64 || o.mem.disp.value <= 0 ||
                o.mem.disp.value >= 0x10000)
                continue;
            if (field && *field != o.mem.disp.value)
                return std::nullopt;
            field = static_cast<std::uint32_t>(o.mem.disp.value);
        }
        if (field)
            return OperatorNameDescriptor{std::move(*path), *field, code.begin, bounds[bounds.size() - 2]};
    }
    return std::nullopt;
}
}

std::optional<OperatorNameDescriptor> OperatorName(const Emulator::Program& getter) {
    return NullableResource(getter, true);
}

std::optional<OperatorSelectionDescriptor> OperatorSelection(const Emulator::Program& code,
    std::span<const std::byte> bytes, std::uint32_t code_rva, std::uint64_t module,
    std::span<const FunctionRecord> functions, std::uint64_t missing_instance_string) {
    const auto& ins = code.instructions;
    std::set<std::uint64_t> failures;
    for (const auto& d : ins)
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_LEA && RipTarget(d, 1) == missing_instance_string)
            failures.insert(d.address);
    if (failures.empty())
        return std::nullopt;
    std::optional<OperatorSelectionDescriptor> accepted;
    for (std::size_t end = 1; end + 2 < ins.size(); ++end) {
        const auto& branch = ins[end];
        const auto& retain = ins[end + 1];
        if (branch.instruction.mnemonic != ZYDIS_MNEMONIC_JZ || !failures.contains(DirectTarget(branch)) ||
            retain.instruction.mnemonic != ZYDIS_MNEMONIC_INC ||
            !(retain.instruction.attributes & ZYDIS_ATTRIB_HAS_LOCK) ||
            retain.operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY || retain.operands[0].mem.disp.value != 8)
            continue;
        const auto holder = retain.operands[0].mem.base;
        std::optional<std::size_t> member;
        for (std::size_t j = end; j > 0 && end - j < 96; --j) {
            const auto& d = ins[j - 1];
            const auto& o = d.operands[1];
            if (d.instruction.mnemonic == ZYDIS_MNEMONIC_XOR &&
                d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[0].reg.value == holder &&
                o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.size == 64 && o.mem.index == ZYDIS_REGISTER_NONE &&
                o.mem.base != ZYDIS_REGISTER_RIP && o.mem.base != ZYDIS_REGISTER_RSP &&
                o.mem.disp.value >= 0x100 && o.mem.disp.value < 0x10000) {
                member = j - 1;
                break;
            }
        }
        if (!member)
            continue;
        const auto profile = ins[*member].operands[1].mem.base;
        std::size_t begin = *member;
        while (begin > 0) {
            --begin;
            bool writes = false;
            for (const auto& o : ins[begin].operands)
                writes |= o.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                    Dependency(o.reg.value) == Dependency(profile);
            if (writes) {
                ++begin;
                break;
            }
        }
        auto instance = Flow(code, begin, end, {profile}, {holder});
        if (!instance)
            continue;

        std::optional<OperatorNameDescriptor> definition;
        for (std::size_t j = end + 2; j < ins.size() && j < end + 128; ++j) {
            const auto& call = ins[j];
            if (call.instruction.mnemonic != ZYDIS_MNEMONIC_CALL || !DirectTarget(call))
                continue;
            const auto target = DirectTarget(call);
            if (target < module)
                continue;
            const auto f = std::lower_bound(functions.begin(), functions.end(), target - module,
                [](const auto& f, auto rva) { return f.begin < rva; });
            if (f == functions.end() || f->begin != target - module || f->end - f->begin > 0x500 ||
                f->begin < code_rva || f->end - code_rva > bytes.size())
                continue;
            const auto getter =
                Emulator::Decode(bytes.subspan(f->begin - code_rva, f->end - f->begin), target, true);
            if (getter)
                definition = NullableResource(*getter, false);
            if (definition)
                break;
        }
        if (!definition) {
            for (std::size_t gate = end + 5; gate + 4 < ins.size() && gate < end + 160; ++gate) {
                if (ins[gate].instruction.mnemonic != ZYDIS_MNEMONIC_CMP || !RipTarget(ins[gate], 1) ||
                    ins[gate].operands[0].size != 16 ||
                    ins[gate - 3].instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                    ins[gate - 3].operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                    ins[gate - 3].operands[1].mem.disp.value != 0)
                    continue;
                const auto object = ins[gate - 3].operands[1].mem.base;
                std::optional<std::size_t> payload;
                for (std::size_t k = gate - 3; k > end + 2; --k) {
                    const auto& d = ins[k - 1];
                    if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                        d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        d.operands[0].reg.value == object &&
                        d.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        d.operands[1].mem.disp.value == 0) {
                        payload = k - 1;
                        break;
                    }
                }
                if (!payload)
                    continue;
                const auto reference = ins[*payload].operands[1].mem.base;

                auto region = code;
                for (std::size_t k = end + 2; k < *payload; ++k)
                    if (region.instructions[k].instruction.meta.category == ZYDIS_CATEGORY_CALL ||
                        region.instructions[k].instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                        region.instructions[k].instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
                        auto& d = region.instructions[k];
                        d.instruction.mnemonic = ZYDIS_MNEMONIC_NOP;
                        d.instruction.meta.category = ZYDIS_CATEGORY_MISC;
                        d.instruction.cpu_flags = nullptr;
                        d.instruction.operand_count = d.instruction.operand_count_visible = 0;
                        d.operands = {};
                    }
                for (std::size_t load = end + 2; load < *payload; ++load) {
                    const auto& d = ins[load];
                    const auto& o = d.operands[1];
                    if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.size != 64 ||
                        o.mem.index != ZYDIS_REGISTER_NONE || o.mem.base == ZYDIS_REGISTER_RIP ||
                        o.mem.base == ZYDIS_REGISTER_RSP || o.mem.disp.value < 0x10 ||
                        o.mem.disp.value > 0x80)
                        continue;
                    auto path = Flow(region, load, *payload, {o.mem.base}, {reference});
                    if (path) {
                        definition = OperatorNameDescriptor{std::move(*path),
                            static_cast<std::uint32_t>(o.mem.disp.value), code.begin,
                            RipTarget(ins[gate], 1)};
                        break;
                    }
                }
                if (definition)
                    break;
            }
        }
        if (!definition || accepted)
            return std::nullopt;
        accepted = OperatorSelectionDescriptor{std::move(*instance), std::move(definition->reference),
            static_cast<std::uint32_t>(ins[*member].operands[1].mem.disp.value), definition->field,
            code.begin, definition->target_type};
    }
    return accepted;
}

std::optional<OperatorSelectionDescriptor> DiscoverOperatorSelection(std::span<const std::byte> code,
    std::uint32_t code_rva, std::uint64_t module, std::span<const FunctionRecord> functions,
    std::span<const std::byte> rdata, std::uint32_t rdata_rva) {
    constexpr std::string_view label = "[LoadoutSelectionOperator] The characterInstance contained in the "
                                       "PRI is invalid for wanted operator. How is it possible ?";
    const auto needle = std::as_bytes(std::span(label.data(), label.size() + 1));
    const auto at = std::search(rdata.begin(), rdata.end(), needle.begin(), needle.end());
    if (at == rdata.end() ||
        std::search(at + needle.size(), rdata.end(), needle.begin(), needle.end()) != rdata.end())
        return std::nullopt;
    const auto target = module + rdata_rva + (at - rdata.begin());
    std::set<std::uint32_t> consumers;
    for (std::size_t j = 4; j <= code.size(); ++j) {
        std::int32_t displacement{};
        std::memcpy(&displacement, code.data() + j - 4, 4);
        if (module + code_rva + j + displacement != target)
            continue;
        const auto rva = code_rva + j - 4;
        auto f = std::upper_bound(
            functions.begin(), functions.end(), rva, [](auto rva, const auto& f) { return rva < f.begin; });
        if (f == functions.begin())
            continue;
        --f;
        if (rva < f->end && f->end - f->begin < 0x10000)
            consumers.insert(f->begin);
    }
    std::optional<OperatorSelectionDescriptor> result;
    for (const auto begin : consumers) {
        const auto f = std::lower_bound(
            functions.begin(), functions.end(), begin, [](const auto& f, auto rva) { return f.begin < rva; });
        const auto decoded =
            Emulator::Decode(code.subspan(f->begin - code_rva, f->end - f->begin), module + f->begin, true);
        if (!decoded)
            continue;
        const auto references =
            std::count_if(decoded->instructions.begin(), decoded->instructions.end(), [&](const auto& d) {
                return d.instruction.mnemonic == ZYDIS_MNEMONIC_LEA && RipTarget(d, 1) == target;
            });
        if (!references)
            continue;
        auto value = OperatorSelection(*decoded, code, code_rva, module, functions, target);
        if (!value || result)
            return std::nullopt;
        result = std::move(value);
    }
    return result;
}

std::optional<OwnershipDescriptor> OwnerProfile(const Emulator::Program& wrapper) {
    const auto& ins = wrapper.instructions;

    struct Gate {
        std::size_t begin, end;
        std::int64_t table;
    };

    std::vector<Gate> gates;
    const auto rip = [](const Emulator::Decoded& d, unsigned operand) -> std::uint64_t {
        const auto& o = d.operands[operand];
        return o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.base == ZYDIS_REGISTER_RIP
            ? d.address + d.instruction.length + o.mem.disp.value
            : 0;
    };
    const auto branch_target = [](const Emulator::Decoded& d) -> std::uint64_t {
        const auto& o = d.operands[0];
        return o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative
            ? d.address + d.instruction.length + o.imm.value.s
            : 0;
    };
    for (std::size_t j = 0; j + 7 < ins.size(); ++j) {
        const auto& a = ins[j];
        const auto& b = ins[j + 1];
        const auto& c = ins[j + 2];
        if (a.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            a.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            a.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || a.operands[1].mem.disp.value != 0 ||
            b.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            b.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            b.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
            b.operands[1].mem.base != a.operands[0].reg.value || b.operands[1].mem.disp.value < 0 ||
            b.operands[1].mem.disp.value >= 0x1000 || c.instruction.mnemonic != ZYDIS_MNEMONIC_MOVZX ||
            c.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || c.operands[1].size != 16 ||
            c.operands[1].mem.base != b.operands[0].reg.value || c.operands[1].mem.disp.value != 0x40 ||
            ins[j + 3].instruction.mnemonic != ZYDIS_MNEMONIC_CMP || !rip(ins[j + 3], 1) ||
            Dependency(ins[j + 3].operands[0].reg.value) != Dependency(c.operands[0].reg.value))
            continue;

        auto upper = j + 5;
        if (ins[j + 4].instruction.mnemonic == ZYDIS_MNEMONIC_JNB) {
            const auto at = branch_target(ins[j + 4]);
            const auto found = std::lower_bound(
                ins.begin(), ins.end(), at, [](const auto& d, auto address) { return d.address < address; });
            if (found == ins.end() || found->address != at)
                continue;
            upper = static_cast<std::size_t>(found - ins.begin());
        } else if (ins[j + 4].instruction.mnemonic != ZYDIS_MNEMONIC_JB)
            continue;
        if (upper <= j + 4 || upper + 2 >= ins.size() ||
            ins[upper].instruction.mnemonic != ZYDIS_MNEMONIC_MOVZX ||
            ins[upper].operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || ins[upper].operands[1].size != 16 ||
            ins[upper].operands[1].mem.base != b.operands[0].reg.value ||
            ins[upper].operands[1].mem.disp.value != 0x42 ||
            ins[upper + 1].instruction.mnemonic != ZYDIS_MNEMONIC_CMP ||
            Dependency(ins[upper + 1].operands[0].reg.value) !=
                Dependency(ins[upper].operands[0].reg.value) ||
            rip(ins[upper + 1], 1) != rip(ins[j + 3], 1) + 2 ||
            ins[upper + 2].instruction.mnemonic != ZYDIS_MNEMONIC_JNBE)
            continue;
        const auto failure = ins[j + 4].instruction.mnemonic == ZYDIS_MNEMONIC_JB ? branch_target(ins[j + 4])
                                                                                  : ins[j + 5].address;
        if (!failure || branch_target(ins[upper + 2]) != failure)
            continue;
        gates.push_back({j, upper + 2, b.operands[1].mem.disp.value});
    }
    if (gates.size() != 2 || gates[1].begin <= gates[0].end + 2 || gates[0].table != gates[1].table)
        return std::nullopt;
    const auto first = gates[0].begin, second = gates[1].begin;
    const auto owner_reg = ins[first].operands[1].mem.base;
    const auto profile_reg = ins[second].operands[1].mem.base;
    std::optional<std::size_t> mix;
    for (std::size_t j = 0; j + 1 < first; ++j) {
        const auto& d = ins[j];
        const auto& branch = ins[j + 1];
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_XOR ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || d.operands[0].reg.value != owner_reg ||
            d.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
            continue;
        if ((branch.instruction.mnemonic == ZYDIS_MNEMONIC_JZ && j + 2 == first) ||
            (branch.instruction.mnemonic == ZYDIS_MNEMONIC_JNZ &&
                branch_target(branch) == ins[first].address)) {
            if (mix)
                return std::nullopt;
            mix = j;
        }
    }
    if (!mix || ins[second - 1].instruction.mnemonic != ZYDIS_MNEMONIC_JZ)
        return std::nullopt;

    auto owner = Slice(Simplify(wrapper), *mix, owner_reg);
    Emulator::Program profile_code{};
    profile_code.linear = true;

    for (unsigned j = 0; j < 16; ++j) {
        const auto reg = static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + j);
        if (reg == ZYDIS_REGISTER_RSP || reg == owner_reg)
            continue;
        if (auto value = Alias(wrapper, gates[0].end + 1, reg))
            profile_code.instructions.insert(profile_code.instructions.end(),
                value->code.instructions.begin(), value->code.instructions.end());
    }
    profile_code.instructions.insert(
        profile_code.instructions.end(), ins.begin() + gates[0].end + 1, ins.begin() + second - 1);
    if (profile_code.instructions.empty())
        return std::nullopt;
    profile_code.begin = profile_code.instructions.front().address;
    profile_code.end = ins[second - 1].address;
    auto profile = Slice(Simplify(profile_code), profile_code.instructions.size(), profile_reg);
    if (!owner || !profile || owner->inputs != Dependency(ZYDIS_REGISTER_RDX) ||
        profile->inputs != Dependency(owner_reg))
        return std::nullopt;

    return OwnershipDescriptor{
        std::move(*owner), std::move(*profile), rip(ins[first + 3], 1), rip(ins[second + 3], 1)};
}

static std::optional<UsernameDescriptor> Username(const Emulator::Program& wrapper,
    std::span<const std::byte> bytes, std::uint32_t code_rva, std::uint64_t module,
    std::span<const FunctionRecord> functions) {

    const auto paths = OwnerProfile(wrapper);
    if (!paths)
        return std::nullopt;
    const auto& ins = wrapper.instructions;
    std::optional<std::uint32_t> field;
    for (const auto& call : ins) {
        if (call.instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
            call.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !call.operands[0].imm.is_relative)
            continue;
        const auto target = call.address + call.instruction.length + call.operands[0].imm.value.s;
        const auto found = std::lower_bound(functions.begin(), functions.end(), target - module,
            [](const auto& f, std::uint64_t at) { return f.begin < at; });
        if (target < module || found == functions.end() || found->begin != target - module ||
            found->begin < code_rva || found->end - found->begin > 0x400 ||
            found->end - code_rva > bytes.size())
            continue;
        const auto getter =
            Emulator::Decode(bytes.subspan(found->begin - code_rva, found->end - found->begin), target, true);
        if (!getter)
            continue;
        bool initialized = false, nullable = false;
        for (const auto& d : getter->instructions) {
            initialized |= d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                d.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && d.operands[0].size == 8 &&
                d.operands[0].mem.base == ZYDIS_REGISTER_RCX && d.operands[0].mem.disp.value == 15 &&
                d.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.operands[1].imm.value.u == 15;
            nullable |= d.instruction.mnemonic == ZYDIS_MNEMONIC_TEST &&
                d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                d.operands[0].reg.value == ZYDIS_REGISTER_RDX &&
                d.operands[1].reg.value == ZYDIS_REGISTER_RDX;
            if (initialized && nullable && d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                d.operands[0].reg.value == ZYDIS_REGISTER_RDX &&
                d.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                (d.instruction.mnemonic == ZYDIS_MNEMONIC_ADD ||
                    d.instruction.mnemonic == ZYDIS_MNEMONIC_SUB)) {
                const auto offset = d.instruction.mnemonic == ZYDIS_MNEMONIC_SUB
                    ? 0ull - d.operands[1].imm.value.u
                    : d.operands[1].imm.value.u;
                if (offset >= 0x18 && offset < 0x1000) {
                    if (field && *field != offset)
                        return std::nullopt;
                    field = static_cast<std::uint32_t>(offset);
                }
            }
        }
    }
    if (!field)
        return std::nullopt;
    return UsernameDescriptor{paths->owner, paths->profile, paths->owner_type, paths->profile_type, *field};
}

static std::optional<std::pair<ZydisRegister, ZydisRegister>> HealthArguments(
    const Emulator::Program& code, std::size_t begin, ZydisRegister first, ZydisRegister second) {
    const auto index = [](ZydisRegister reg) {
        return ZydisRegisterGetId(ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg));
    };
    if (!Dependency(first) || !Dependency(second) || index(first) == index(second))
        return std::nullopt;

    struct State {
        std::size_t at;
        std::array<unsigned char, 16> origins{};
        bool operator==(const State&) const = default;
    };

    State entry{begin};
    entry.origins[index(first)] = 1;
    entry.origins[index(second)] = 2;
    std::vector<State> pending{entry}, seen;
    std::optional<std::pair<ZydisRegister, ZydisRegister>> result;

    while (!pending.empty() && seen.size() < 2048) {
        auto next = pending.back();
        pending.pop_back();
        if (next.at >= code.instructions.size() || std::find(seen.begin(), seen.end(), next) != seen.end())
            continue;
        seen.push_back(next);
        const auto& d = code.instructions[next.at];
        const auto category = d.instruction.meta.category;
        if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_RET)
            continue;
        const auto before = next.origins;
        for (unsigned j = 0; j < d.instruction.operand_count; ++j) {
            const auto& o = d.operands[j];
            if (o.type != ZYDIS_OPERAND_TYPE_REGISTER || !Dependency(o.reg.value) ||
                !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                continue;
            unsigned char origin{};
            const auto& source = d.operands[1];
            if (j == 0 && o.size >= 32 && d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                source.type == ZYDIS_OPERAND_TYPE_REGISTER && Dependency(source.reg.value) &&
                source.size >= 32)
                origin = before[index(source.reg.value)];
            next.origins[index(o.reg.value)] = origin;
        }
        if (category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) {
            const auto& operand = d.operands[0];
            if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative) {
                const auto target = d.address + d.instruction.length + operand.imm.value.s;
                const auto found = std::lower_bound(code.instructions.begin(), code.instructions.end(),
                    target, [](const auto& item, std::uint64_t address) { return item.address < address; });
                if (found != code.instructions.end() && found->address == target)
                    pending.push_back(
                        {static_cast<std::size_t>(found - code.instructions.begin()), next.origins});
                else if (category == ZYDIS_CATEGORY_UNCOND_BR &&
                    (target < code.begin || target >= code.end)) {
                    const auto current = next.origins[index(ZYDIS_REGISTER_R8)],
                               maximum = next.origins[index(ZYDIS_REGISTER_R9)];
                    if (current && maximum && current != maximum) {
                        const auto value =
                            std::pair{current == 1 ? first : second, maximum == 1 ? first : second};
                        if (result && *result != value)
                            return std::nullopt;
                        result = value;
                    }
                }
            }
        }
        if (category != ZYDIS_CATEGORY_UNCOND_BR) {
            ++next.at;
            pending.push_back(next);
        }
    }
    return seen.size() < 2048 ? result : std::nullopt;
}

static std::optional<HealthDescriptor> Health(const Emulator::Program& source,
    std::span<const std::byte> image, std::uint32_t code_rva, std::uint64_t module,
    std::span<const FunctionRecord> functions) {
    const auto& instructions = source.instructions;
    const auto count = [&](ZydisMnemonic m) {
        return std::count_if(instructions.begin(), instructions.end(),
            [&](const auto& d) { return d.instruction.mnemonic == m; });
    };

    if (count(ZYDIS_MNEMONIC_CVTTSS2SI) < 2 || count(ZYDIS_MNEMONIC_MOVD) < 1)
        return std::nullopt;
    std::optional<HealthDescriptor> result;
    for (std::size_t j = 1; j + 4 < instructions.size(); ++j) {
        const auto& first = instructions[j];
        if (first.instruction.mnemonic != ZYDIS_MNEMONIC_CMOVLE ||
            first.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || first.operands[0].size != 32 ||
            instructions[j - 1].instruction.mnemonic != ZYDIS_MNEMONIC_TEST)
            continue;
        for (std::size_t k = j + 2; k <= j + 4; ++k) {
            const auto& second = instructions[k];
            const auto& following = instructions[k + 1];
            if (second.instruction.mnemonic != ZYDIS_MNEMONIC_CMOVNLE ||
                second.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || second.operands[0].size != 32 ||
                instructions[k - 1].instruction.mnemonic != ZYDIS_MNEMONIC_TEST ||
                following.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                following.operands[0].reg.value != ZYDIS_REGISTER_RCX || !LocalSlot(following.operands[1]))
                continue;
            const auto arguments =
                HealthArguments(source, k + 1, first.operands[0].reg.value, second.operands[0].reg.value);
            if (!arguments)
                continue;
            if (result)
                return std::nullopt;
            auto program = source;
            program.end = following.address;

            std::vector<std::uint64_t> pending{program.begin}, seen, calls;
            while (!pending.empty() && seen.size() < 4096) {
                const auto at = pending.back();
                pending.pop_back();
                if (at == program.end || std::find(seen.begin(), seen.end(), at) != seen.end())
                    continue;
                seen.push_back(at);
                const auto found = std::lower_bound(program.instructions.begin(), program.instructions.end(),
                    at, [](const auto& d, std::uint64_t address) { return d.address < address; });
                if (found == program.instructions.end() || found->address != at)
                    continue;
                const auto d = *found;
                const auto category = d.instruction.meta.category;
                if (category == ZYDIS_CATEGORY_RET)
                    continue;
                const auto next = at + d.instruction.length;
                if (category != ZYDIS_CATEGORY_UNCOND_BR)
                    pending.push_back(next);
                if ((category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_COND_BR ||
                        category == ZYDIS_CATEGORY_UNCOND_BR) &&
                    d.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.operands[0].imm.is_relative) {
                    const auto target = next + d.operands[0].imm.value.s;
                    if (category != ZYDIS_CATEGORY_CALL) {
                        pending.push_back(target);
                        continue;
                    }
                    if (std::find(calls.begin(), calls.end(), target) != calls.end() || calls.size() >= 16)
                        continue;
                    calls.push_back(target);
                    if (target < module || target - module > 0xffffffffu)
                        continue;
                    const auto rva = target - module;
                    const auto f = std::lower_bound(functions.begin(), functions.end(), rva,
                        [](const auto& item, std::uint64_t address) { return item.begin < address; });
                    if (f == functions.end() || f->begin != rva || f->end <= f->begin ||
                        f->end - f->begin > 0x1000 || rva < code_rva || f->end - code_rva > image.size())
                        continue;
                    const auto helper =
                        Emulator::Decode(image.subspan(rva - code_rva, f->end - f->begin), target);
                    if (!helper)
                        continue;
                    program.instructions.insert(
                        program.instructions.end(), helper->instructions.begin(), helper->instructions.end());
                    std::sort(program.instructions.begin(), program.instructions.end(),
                        [](const auto& a, const auto& b) { return a.address < b.address; });
                    pending.push_back(target);
                }
            }
            if (seen.size() >= 4096)
                return std::nullopt;

            for (std::size_t i = 0; i < program.instructions.size(); ++i) {
                auto& d = program.instructions[i];
                if (d.instruction.mnemonic != ZYDIS_MNEMONIC_OR ||
                    d.operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY || d.operands[0].size != 64 ||
                    d.operands[0].mem.index == ZYDIS_REGISTER_NONE || d.operands[0].mem.scale != 8 ||
                    d.operands[0].mem.disp.value != 0 || !d.instruction.cpu_flags)
                    continue;
                bool dead_flags = false;
                auto remaining = d.instruction.cpu_flags->modified | d.instruction.cpu_flags->set_0 |
                    d.instruction.cpu_flags->set_1 | d.instruction.cpu_flags->undefined;
                for (std::size_t n = i + 1; n < program.instructions.size(); ++n) {
                    const auto& successor = program.instructions[n].instruction;
                    if (successor.cpu_flags) {
                        if (successor.cpu_flags->tested & remaining)
                            break;
                        remaining &= ~(successor.cpu_flags->modified | successor.cpu_flags->set_0 |
                            successor.cpu_flags->set_1 | successor.cpu_flags->undefined);
                        if (!remaining) {
                            dead_flags = true;
                            break;
                        }
                    }
                    if (successor.meta.category == ZYDIS_CATEGORY_COND_BR ||
                        successor.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                        successor.meta.category == ZYDIS_CATEGORY_CALL ||
                        successor.meta.category == ZYDIS_CATEGORY_RET)
                        break;
                }
                if (dead_flags)
                    d.instruction.mnemonic = ZYDIS_MNEMONIC_NOP;
            }
            result = HealthDescriptor{std::move(program), arguments->second, arguments->first};
        }
    }
    return result;
}

static std::optional<AffiliationDescriptor> Affiliation(
    const Emulator::Program& code, std::uint64_t profile_type) {
    const auto& ins = code.instructions;

    if (std::none_of(ins.begin(), ins.end(), [](const auto& d) {
            return d.instruction.mnemonic == ZYDIS_MNEMONIC_BT && d.operands[0].size == 32 &&
                d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                d.operands[1].reg.value == ZYDIS_REGISTER_EAX;
        }))
        return std::nullopt;
    for (std::size_t gate = 3; gate + 4 < ins.size(); ++gate) {
        const auto& cmp = ins[gate];
        const auto& ref = cmp.operands[1];
        if (cmp.instruction.mnemonic != ZYDIS_MNEMONIC_CMP || ref.type != ZYDIS_OPERAND_TYPE_MEMORY ||
            ref.mem.base != ZYDIS_REGISTER_RIP ||
            cmp.address + cmp.instruction.length + ref.mem.disp.value != profile_type)
            continue;
        const auto& vtable = ins[gate - 3];
        const auto& info = ins[gate - 2];
        const auto& low = ins[gate - 1];
        if (vtable.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            vtable.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || vtable.operands[1].mem.disp.value != 0 ||
            info.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            info.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || info.operands[1].mem.disp.value != 0x30 ||
            info.operands[1].mem.base != vtable.operands[0].reg.value ||
            low.instruction.mnemonic != ZYDIS_MNEMONIC_MOVZX ||
            low.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || low.operands[1].size != 16 ||
            low.operands[1].mem.base != info.operands[0].reg.value || low.operands[1].mem.disp.value != 0x40)
            continue;
        const auto profile = vtable.operands[1].mem.base;
        for (std::size_t j = gate + 4; j + 1 < ins.size(); ++j) {
            const auto& d = ins[j];
            const bool zero_pointer = d.instruction.mnemonic == ZYDIS_MNEMONIC_ADD;
            const bool encoded_null = d.instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
                d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ins[j - 1].instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                ins[j - 1].operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ins[j - 1].operands[0].reg.value == d.operands[1].reg.value &&
                ins[j - 1].operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
            if ((!zero_pointer && !encoded_null) || d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                d.operands[0].size != 64 || d.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                ins[j + 1].instruction.mnemonic != ZYDIS_MNEMONIC_JZ)
                continue;
            Emulator::Program member{};
            member.linear = true;
            member.instructions.assign(ins.begin() + gate + 1, ins.begin() + j + 1);
            member.begin = member.instructions.front().address;
            member.end = d.address + d.instruction.length;
            auto value = Slice(Simplify(member), member.instructions.size(), d.operands[0].reg.value);
            if (!value || value->inputs != Dependency(profile))
                continue;
            std::optional<std::uint32_t> field;
            for (const auto& step : value->code.instructions)
                for (unsigned k = 0; k < step.instruction.operand_count_visible; ++k) {
                    const auto& o = step.operands[k];
                    if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.mem.base != profile ||
                        o.mem.index != ZYDIS_REGISTER_NONE || o.size != 64 || o.mem.disp.value <= 0 ||
                        o.mem.disp.value >= 0x10000)
                        continue;
                    if (field && *field != o.mem.disp.value)
                        return std::nullopt;
                    field = static_cast<std::uint32_t>(o.mem.disp.value);
                }
            if (field)
                return AffiliationDescriptor{std::move(*value), profile, *field,
                    encoded_null ? ins[j - 1].operands[1].imm.value.u : 0, zero_pointer};
        }
    }
    return std::nullopt;
}

NativeDescriptor Discover(std::span<const std::byte> code, std::uint32_t code_rva, std::uint64_t module,
    std::span<const FunctionRecord> functions, std::stop_token stop,
    const std::function<void(std::size_t, std::size_t)>& progress, const DiscoveryObserver& observer,
    const ScanObserver& checkpoint, const ValidationObserver& validation) {
    NativeDescriptor result;
    result.functions.assign(functions.begin(), functions.end());
    std::map<std::vector<std::uint64_t>, MetadataDescriptor> metadata;
    std::vector<FunctionRecord> affiliation_candidates;
    std::set<std::uint32_t> local_profile_fields;
    unsigned defuser_candidates{};
    const auto contains = [](std::span<const std::byte> bytes, std::uint32_t word) {
        const auto pattern = std::as_bytes(std::span(&word, 1));
        return std::search(bytes.begin(), bytes.end(), pattern.begin(), pattern.end()) != bytes.end();
    };
    for (std::size_t index = 0; index < functions.size(); ++index) {
        if (stop.stop_requested())
            return {};
        if (progress && index % 512 == 0)
            progress(index, functions.size());
        const auto& f = functions[index];
        if (checkpoint)
            checkpoint("function", index, f);
        if (f.begin < code_rva || f.end <= f.begin || f.begin - code_rva >= code.size() ||
            f.end - f.begin > code.size() - (f.begin - code_rva))
            continue;
        const auto bytes = code.subspan(f.begin - code_rva, f.end - f.begin);
        const auto prefix = bytes.first(std::min<std::size_t>(bytes.size(), 0x200));
        if (bytes.size() < 0x1000 && contains(prefix.first(std::min<std::size_t>(prefix.size(), 96)), 0x1c))
            if (auto decoded = Emulator::Decode(bytes, module + f.begin, true))
                if (auto value = equipment::DefuserOwner(*decoded)) {
                    ++defuser_candidates;
                    result.defuser = std::move(value);
                }
        bool object = false, gs = false, zero = false;
        for (std::size_t j = 0; j + 3 <= prefix.size(); ++j) {
            const auto a = std::to_integer<unsigned>(prefix[j]), b = std::to_integer<unsigned>(prefix[j + 1]),
                       c = std::to_integer<unsigned>(prefix[j + 2]);
            object |= j < 48 && (a == 0x48 || a == 0x4c) && b == 0x8b && (c & 0xc7) == 1;
            gs |= a == 0x65 && (b == 0x48 || b == 0x4c) && c == 0x8b;
            zero |= j < 96 && a == 0x0f && b == 0x57 && ((c >> 3) & 7) == (c & 7);
        }
        if (!gs && bytes.size() < 0x1000)
            for (std::size_t j = prefix.size() - 2; j + 3 <= bytes.size(); ++j)
                gs |= bytes[j] == std::byte{0x65} &&
                    (bytes[j + 1] == std::byte{0x48} || bytes[j + 1] == std::byte{0x4c}) &&
                    bytes[j + 2] == std::byte{0x8b};
        const bool root_anchor =
            bytes.size() < 0x4000 && contains(bytes, 0x14f8b589) && contains(bytes, 0xc350);
        if (bytes.size() < 0x4000 && contains(bytes, 0x1d2e4b8f)) {
            if (checkpoint)
                checkpoint("health", index, f);
            const auto before = result.health.size();
            auto decoded = Emulator::Decode(bytes, module + f.begin, true);
            if (decoded)
                if (auto value = Health(*decoded, code, code_rva, module, functions))
                    result.health.push_back(std::move(*value));
            if (observer)
                observer("health", f, bytes, decoded ? &*decoded : nullptr, result.health.size() - before);
        }
        if (bytes.size() < 0x10000 && contains(bytes, 0xa9cefd4a)) {
            if (checkpoint)
                checkpoint("rig", index, f);
            const auto before = result.rigs.size();
            auto decoded = Emulator::Decode(bytes, module + f.begin, true);
            if (decoded) {
                auto values = RigLookups(*decoded);
                result.rigs.insert(result.rigs.end(), std::make_move_iterator(values.begin()),
                    std::make_move_iterator(values.end()));
            }
            if (observer)
                observer("rig", f, bytes, decoded ? &*decoded : nullptr, result.rigs.size() - before);
        }
        const bool camera_anchor = bytes.size() < 0x2000 && gs && zero;
        const bool manager_anchor = bytes.size() < 0x1000 && gs;
        if (bytes.size() < 0x4000)
            affiliation_candidates.push_back(f);
        unsigned casts{};
        if (bytes.size() < 0x1000)
            for (std::size_t j = 0; j + 2 <= bytes.size(); ++j)
                casts += bytes[j] == std::byte{0x0f} && bytes[j + 1] == std::byte{0xb7};
        if ((gs && bytes.size() < 0x500) || (casts >= 4 && bytes.size() < 0x1000))
            if (auto decoded = Emulator::Decode(bytes, module + f.begin, true)) {
                if (auto value = OwnerProfile(*decoded))
                    result.ownership.push_back(std::move(*value));
                if (auto value = Username(*decoded, code, code_rva, module, functions))
                    result.usernames.push_back(std::move(*value));
                if (auto value = OperatorName(*decoded))
                    result.operator_names.push_back(std::move(*value));
            }
        bool array_anchor = false;
        if (bytes.size() > 0x1000 && bytes.size() < 0x10000)
            for (std::size_t j = 0; j + 3 <= bytes.size(); ++j)
                if (bytes[j] == std::byte{0xc1} && (std::to_integer<unsigned>(bytes[j + 1]) & 0xf8) == 0xe0 &&
                    bytes[j + 2] == std::byte{0x22}) {
                    array_anchor = true;
                    break;
                }
        if (!array_anchor && bytes.size() > 0x1000 && bytes.size() < 0x10000 && contains(bytes, 0x3fffffff))
            for (std::size_t j = 0; j + 4 <= bytes.size(); ++j)
                if ((bytes[j] == std::byte{0x48} || bytes[j] == std::byte{0x49} ||
                        bytes[j] == std::byte{0x4c} || bytes[j] == std::byte{0x4d}) &&
                    bytes[j + 1] == std::byte{0xc1} &&
                    (std::to_integer<unsigned>(bytes[j + 2]) & 0xf0) == 0xc0) {
                    array_anchor = true;
                    break;
                }
        if (array_anchor) {
            if (checkpoint)
                checkpoint("array", index, f);
            const auto before = result.arrays.size();
            auto decoded = Emulator::Decode(bytes, module + f.begin, true);
            if (decoded) {
                auto values = Arrays(*decoded);
                result.arrays.insert(result.arrays.end(), std::make_move_iterator(values.begin()),
                    std::make_move_iterator(values.end()));
            }
            if (observer)
                observer("array", f, bytes, decoded ? &*decoded : nullptr, result.arrays.size() - before);
        }
        bool pose_anchor = false;
        if (bytes.size() > 0x1000 && bytes.size() < 0x10000)
            for (std::size_t j = 0; j + 3 <= bytes.size(); ++j)
                if (bytes[j] == std::byte{0xc1} && (std::to_integer<unsigned>(bytes[j + 1]) & 0xf8) == 0xe0 &&
                    bytes[j + 2] == std::byte{5}) {
                    pose_anchor = true;
                    break;
                }
        if (pose_anchor) {
            if (checkpoint)
                checkpoint("pose", index, f);
            const auto before = result.poses.size();
            auto decoded = Emulator::Decode(bytes, module + f.begin, true);
            if (decoded) {
                auto values = Poses(*decoded, validation);
                result.poses.insert(result.poses.end(), std::make_move_iterator(values.begin()),
                    std::make_move_iterator(values.end()));
            }
            if (observer)
                observer("pose", f, bytes, decoded ? &*decoded : nullptr, result.poses.size() - before);
        }
        if (root_anchor || camera_anchor || manager_anchor) {
            if (checkpoint)
                checkpoint(root_anchor ? "root_context" : camera_anchor ? "camera" : "manager", index, f);
            const auto roots_before = result.roots.size(), cameras_before = result.cameras.size(),
                       managers_before = result.managers.size();
            auto decoded = Emulator::Decode(bytes, module + f.begin, true);
            if (decoded && root_anchor)
                if (auto value = Root(*decoded, validation)) {
                    std::optional<Expression> context;
                    const auto& instructions = decoded->instructions;
                    for (std::size_t j = 0; j + 5 < instructions.size(); ++j) {
                        const auto& call = instructions[j];
                        const auto& test = instructions[j + 1];
                        const auto& branch = instructions[j + 2];
                        auto alternate_index = j + 3;
                        if (branch.instruction.mnemonic == ZYDIS_MNEMONIC_JNZ &&
                            branch.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                            branch.operands[0].imm.is_relative) {
                            const auto address =
                                branch.address + branch.instruction.length + branch.operands[0].imm.value.s;
                            const auto found =
                                std::lower_bound(instructions.begin(), instructions.end(), address,
                                    [](const auto& value, std::uint64_t at) { return value.address < at; });
                            if (found == instructions.end() || found->address != address)
                                continue;
                            alternate_index = static_cast<std::size_t>(found - instructions.begin());
                        }
                        if (alternate_index + 2 >= instructions.size())
                            continue;
                        const auto& alternate = instructions[alternate_index];
                        const auto& output = instructions[alternate_index + 1];
                        if (call.instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
                            call.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                            !call.operands[0].imm.is_relative ||
                            test.instruction.mnemonic != ZYDIS_MNEMONIC_TEST ||
                            test.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                            test.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                            test.operands[0].reg.value != ZYDIS_REGISTER_AL ||
                            test.operands[1].reg.value != ZYDIS_REGISTER_AL ||
                            (branch.instruction.mnemonic != ZYDIS_MNEMONIC_JZ &&
                                branch.instruction.mnemonic != ZYDIS_MNEMONIC_JNZ) ||
                            alternate.instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
                            output.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                            output.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                            output.operands[1].reg.value != ZYDIS_REGISTER_RAX ||
                            instructions[alternate_index + 2].instruction.mnemonic != ZYDIS_MNEMONIC_JMP)
                            continue;
                        const auto target =
                            call.address + call.instruction.length + call.operands[0].imm.value.s;
                        if (target < module || target - module > 0xffffffffu)
                            continue;
                        const auto found =
                            std::lower_bound(functions.begin(), functions.end(), target - module,
                                [](const auto& item, std::uint64_t at) { return item.begin < at; });
                        const auto rva = target - module;
                        if (rva < code_rva || rva - code_rva >= code.size())
                            continue;
                        const bool unwind = found != functions.end() && found->begin == rva;

                        if (!unwind && found != functions.begin() && std::prev(found)->end > rva)
                            continue;
                        const auto end = unwind
                            ? std::uint64_t(found->end)
                            : std::min<std::uint64_t>(
                                  found == functions.end() ? code_rva + code.size() : found->begin,
                                  rva + 0x1000);
                        if (end <= rva || end - rva > 0x1000 || end - code_rva > code.size())
                            continue;
                        auto leaf = Emulator::Decode(code.subspan(rva - code_rva, end - rva), target, true);
                        if (!leaf)
                            continue;
                        if (!unwind) {
                            const auto returned = std::find_if(leaf->instructions.begin(),
                                leaf->instructions.end(),
                                [](const auto& d) { return d.instruction.mnemonic == ZYDIS_MNEMONIC_RET; });
                            if (returned == leaf->instructions.end() ||
                                std::any_of(leaf->instructions.begin(), returned, [](const auto& d) {
                                    return d.instruction.meta.category == ZYDIS_CATEGORY_CALL ||
                                        d.instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                                        d.instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
                                }))
                                continue;
                            leaf->end = returned->address + returned->instruction.length;
                            leaf->instructions.erase(std::next(returned), leaf->instructions.end());
                        }
                        std::optional<Expression> candidate;
                        bool valid = true;
                        for (std::size_t k = 0; k < leaf->instructions.size(); ++k) {
                            if (leaf->instructions[k].instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
                                valid = false;
                                break;
                            }
                            if (leaf->instructions[k].instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
                                if (candidate) {
                                    valid = false;
                                    break;
                                }
                                candidate = Slice(*leaf, k, ZYDIS_REGISTER_EAX);
                            }
                        }
                        if (valid && candidate && !candidate->inputs) {
                            if (context) {
                                context.reset();
                                break;
                            }
                            context = std::move(candidate);
                        }
                    }
                    if (context) {
                        result.roots.push_back(std::move(*value));
                        result.contexts.push_back(std::move(*context));
                    } else if (validation)
                        validation("root context helper proof missing", module + f.begin, 0);
                }
            if (decoded && camera_anchor)
                if (auto value = Camera(*decoded))
                    result.cameras.push_back(std::move(*value));
            if (decoded && manager_anchor) {
                auto values = Manager(*decoded);
                result.managers.insert(result.managers.end(), std::make_move_iterator(values.begin()),
                    std::make_move_iterator(values.end()));
            }
            if (observer) {
                if (root_anchor)
                    observer("root_context", f, bytes, decoded ? &*decoded : nullptr,
                        result.roots.size() - roots_before);
                if (camera_anchor)
                    observer("camera", f, bytes, decoded ? &*decoded : nullptr,
                        result.cameras.size() - cameras_before);
                if (manager_anchor)
                    observer("manager", f, bytes, decoded ? &*decoded : nullptr,
                        result.managers.size() - managers_before);
            }
        }
        if (!object)
            continue;
        if (checkpoint)
            checkpoint("metadata", index, f);
        auto decoded =
            Emulator::Decode(prefix.first(std::min<std::size_t>(prefix.size(), 128)), module + f.begin, true);
        auto candidate = decoded ? locators::Metadata(*decoded) : std::nullopt;
        if (observer)
            observer("metadata", f, prefix.first(std::min<std::size_t>(prefix.size(), 128)),
                decoded ? &*decoded : nullptr, candidate ? 1 : 0);
        if (!candidate)
            continue;
        std::vector<std::uint64_t> key{candidate->table_field, candidate->hash_field};
        bool scalar = true;
        std::vector<std::uint64_t> operations;
        for (const auto& d : candidate->decode.code.instructions) {
            if (d.operands[0].size != 32)
                continue;
            const auto& source = d.operands[1];
            operations.push_back(d.instruction.mnemonic);
            operations.push_back(source.type);
            operations.push_back(source.size);
            if (source.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                operations.push_back(source.imm.value.u);
            else if (source.type == ZYDIS_OPERAND_TYPE_MEMORY)
                scalar &= source.mem.disp.value == candidate->hash_field && source.size == 32;
            else if (source.type == ZYDIS_OPERAND_TYPE_REGISTER)
                scalar &= source.reg.value == d.operands[0].reg.value;
            else
                scalar = false;
        }
        if (scalar) {
            key.push_back(0);
            key.insert(key.end(), operations.begin(), operations.end());
            metadata.try_emplace(std::move(key), std::move(*candidate));
            continue;
        }
        key.push_back(1);
        std::map<ZydisRegister, std::uint64_t> registers{{ZYDIS_REGISTER_RCX, 1}};
        const auto reg = [&](ZydisRegister value) {
            if (!Dependency(value))
                return std::uint64_t(value) << 32;
            const auto enclosing = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, value);
            const auto [found, inserted] = registers.try_emplace(enclosing, registers.size() + 1);
            return found->second |
                (std::uint64_t(ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, value)) << 32);
        };
        for (const auto& d : candidate->decode.code.instructions) {
            key.push_back(d.instruction.mnemonic);
            key.push_back(d.instruction.operand_count_visible);
            for (unsigned j = 0; j < d.instruction.operand_count_visible; ++j) {
                const auto& o = d.operands[j];
                key.push_back(o.type);
                key.push_back(o.size);
                key.push_back(o.actions);
                if (o.type == ZYDIS_OPERAND_TYPE_REGISTER)
                    key.push_back(reg(o.reg.value));
                if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    key.push_back(reg(o.mem.base));
                    key.push_back(reg(o.mem.index));
                    key.push_back(o.mem.segment);
                    key.push_back(o.mem.scale);
                    key.push_back(static_cast<std::uint64_t>(o.mem.disp.value));
                }
                if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    key.push_back(o.imm.value.u);
                    key.push_back(o.imm.is_relative);
                }
            }
        }
        key.push_back(reg(candidate->decode.output));
        metadata.try_emplace(std::move(key), std::move(*candidate));
    }
    for (auto& [key, value] : metadata)
        result.metadata.push_back(std::move(value));
    if (result.usernames.size() == 1)
        for (const auto& f : affiliation_candidates) {
            if (stop.stop_requested())
                return {};
            const auto bytes = code.subspan(f.begin - code_rva, f.end - f.begin);
            bool references_profile = false;
            for (std::size_t j = 4; j <= bytes.size(); ++j) {
                std::int32_t displacement{};
                std::memcpy(&displacement, bytes.data() + j - 4, 4);
                if (module + f.begin + j + displacement == result.usernames.front().profile_type) {
                    references_profile = true;
                    break;
                }
            }
            if (!references_profile)
                continue;
            if (auto decoded = Emulator::Decode(bytes, module + f.begin, true)) {
                if (auto value = Affiliation(*decoded, result.usernames.front().profile_type))
                    result.affiliations.push_back(std::move(*value));

                const auto& ins = decoded->instructions;
                const bool selection_event = std::any_of(
                    ins.begin(), ins.begin() + std::min<std::size_t>(ins.size(), 16), [](const auto& d) {
                        return d.instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
                            d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                            d.operands[0].reg.value == ZYDIS_REGISTER_R8D &&
                            d.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                            d.operands[1].imm.value.u == 15;
                    });
                if (selection_event)
                    for (std::size_t j = 3; j < ins.size(); ++j) {
                        const auto& d = ins[j];
                        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_CMP ||
                            d.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                            d.operands[1].mem.base != ZYDIS_REGISTER_RIP ||
                            d.address + d.instruction.length + d.operands[1].mem.disp.value !=
                                result.usernames.front().profile_type ||
                            ins[j - 3].operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY)
                            continue;
                        const auto profile = ins[j - 3].operands[1].mem.base;
                        for (std::size_t k = j + 1; k + 1 < ins.size(); ++k) {
                            const auto& flag = ins[k];
                            if (flag.instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
                                flag.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                                flag.operands[0].size == 8 && flag.operands[0].mem.base == profile &&
                                flag.operands[0].mem.index == ZYDIS_REGISTER_NONE &&
                                flag.operands[0].mem.disp.value > 0 &&
                                flag.operands[0].mem.disp.value < 0x10000 &&
                                flag.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                                flag.operands[1].imm.value.u == 0 &&
                                ins[k + 1].instruction.mnemonic == ZYDIS_MNEMONIC_JZ)
                                local_profile_fields.insert(
                                    static_cast<std::uint32_t>(flag.operands[0].mem.disp.value));
                        }
                    }
            }
        }
    if (local_profile_fields.size() == 1)
        result.local_profile_field = *local_profile_fields.begin();
    if (defuser_candidates != 1)
        result.defuser.reset();
    if (progress)
        progress(functions.size(), functions.size());
    return result;
}

std::vector<Expression> Manager(const Emulator::Program& code) {
    std::vector<Expression> result;
    bool gate = false;
    for (std::size_t j = 0; j < std::min<std::size_t>(16, code.instructions.size()); ++j) {
        const auto& d = code.instructions[j];
        gate |= d.instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && d.operands[0].size == 8 &&
            d.operands[0].mem.base == ZYDIS_REGISTER_RCX && d.operands[0].mem.disp.value > 0 &&
            d.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.operands[1].imm.value.u == 0;
    }
    if (!gate)
        return result;
    for (std::size_t j = 0; j < code.instructions.size(); ++j) {
        const auto& d = code.instructions[j];
        const bool compare = d.instruction.mnemonic == ZYDIS_MNEMONIC_CMP;
        const bool decoded_null = j + 1 < code.instructions.size() &&
            (d.instruction.mnemonic == ZYDIS_MNEMONIC_ADD || d.instruction.mnemonic == ZYDIS_MNEMONIC_SUB ||
                d.instruction.mnemonic == ZYDIS_MNEMONIC_XOR) &&
            (code.instructions[j + 1].instruction.mnemonic == ZYDIS_MNEMONIC_JZ ||
                code.instructions[j + 1].instruction.mnemonic == ZYDIS_MNEMONIC_JNZ);
        if (!compare && !decoded_null)
            continue;
        for (unsigned operand = 0; operand < (compare ? 2u : 1u); ++operand) {
            if (d.operands[operand].type != ZYDIS_OPERAND_TYPE_REGISTER || d.operands[operand].size != 64)
                continue;
            auto candidate = Slice(code, j + (compare ? 0 : 1), d.operands[operand].reg.value);
            if (!candidate || candidate->inputs != 2u)
                continue;
            const bool seed = std::any_of(
                candidate->code.instructions.begin(), candidate->code.instructions.end(), [](const auto& v) {
                    return v.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                        v.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        ((v.operands[1].mem.segment == ZYDIS_REGISTER_GS &&
                             v.operands[1].mem.disp.value == 0x58) ||
                            v.operands[1].mem.base == ZYDIS_REGISTER_RIP);
                });
            if (!seed)
                continue;
            const bool duplicate = std::any_of(result.begin(), result.end(), [&](const auto& v) {
                return v.output == candidate->output &&
                    v.code.instructions.size() == candidate->code.instructions.size() &&
                    std::equal(v.code.instructions.begin(), v.code.instructions.end(),
                        candidate->code.instructions.begin(),
                        [](const auto& a, const auto& b) { return a.address == b.address; });
            });
            if (!duplicate)
                result.push_back(std::move(*candidate));
        }
    }
    return result;
}

std::vector<PoseDescriptor> Poses(const Emulator::Program& code, const ValidationObserver& validation) {
    std::vector<PoseDescriptor> result;
    const auto& instructions = code.instructions;
    std::string_view reason = "pose native vector access not found";
    std::uint64_t reason_at = code.begin, observed{};
    unsigned reached{};
    const auto failed = [&](unsigned depth, std::string_view text, std::uint64_t at,
                            std::uint64_t value = 0) {
        if (depth >= reached) {
            reached = depth;
            reason = text;
            reason_at = at;
            observed = value;
        }
    };
    const auto target = [&](const Emulator::Decoded& d) {
        if (d.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !d.operands[0].imm.is_relative)
            return instructions.size();
        const auto at = d.address + d.instruction.length + d.operands[0].imm.value.s;
        const auto found = std::lower_bound(instructions.begin(), instructions.end(), at,
            [](const auto& value, std::uint64_t address) { return value.address < address; });
        return found != instructions.end() && found->address == at
            ? static_cast<std::size_t>(found - instructions.begin())
            : instructions.size();
    };
    for (std::size_t pair = 1; pair + 1 < instructions.size(); ++pair) {
        const auto& a = instructions[pair];
        const auto& b = instructions[pair + 1];
        const auto& shift = instructions[pair - 1];
        const auto vector_load = [](const Emulator::Decoded& d) {
            return d.instruction.mnemonic == ZYDIS_MNEMONIC_MOVAPS ||
                d.instruction.mnemonic == ZYDIS_MNEMONIC_MOVUPS ||
                d.instruction.mnemonic == ZYDIS_MNEMONIC_MOVDQA ||
                d.instruction.mnemonic == ZYDIS_MNEMONIC_MOVDQU;
        };
        if (vector_load(a) && vector_load(b) && a.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            b.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            failed(1, "pose vector index or 0x20 stride not proven", a.address,
                shift.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE ? shift.operands[1].imm.value.u : 0);
        if (!vector_load(a) || !vector_load(b) || a.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
            b.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
            a.operands[1].mem.base != b.operands[1].mem.base ||
            a.operands[1].mem.index != b.operands[1].mem.index ||
            a.operands[1].mem.base == ZYDIS_REGISTER_RSP || !Dependency(a.operands[1].mem.base) ||
            !Dependency(a.operands[1].mem.index) ||
            b.operands[1].mem.disp.value != a.operands[1].mem.disp.value + 16 ||
            shift.instruction.mnemonic != ZYDIS_MNEMONIC_SHL ||
            shift.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            shift.operands[0].reg.value != a.operands[1].mem.index ||
            shift.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || shift.operands[1].imm.value.u != 5)
            continue;
        std::size_t flag = pair;
        ZydisRegister asset = ZYDIS_REGISTER_NONE;
        for (std::size_t j = pair; j > 0 && a.address - instructions[j - 1].address < 0x800; --j) {
            const auto& d = instructions[j - 1];
            const auto& o = d.operands[d.instruction.mnemonic == ZYDIS_MNEMONIC_TEST ? 0 : 1];
            if ((d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV &&
                    d.instruction.mnemonic != ZYDIS_MNEMONIC_MOVZX &&
                    d.instruction.mnemonic != ZYDIS_MNEMONIC_TEST) ||
                o.type != ZYDIS_OPERAND_TYPE_MEMORY || (o.size != 8 && o.size != 32) ||
                o.mem.index != ZYDIS_REGISTER_NONE || o.mem.disp.value <= 0 || !Dependency(o.mem.base) ||
                o.mem.base == ZYDIS_REGISTER_RSP)
                continue;
            flag = j - 1;
            asset = o.mem.base;
            break;
        }
        if (flag == pair) {
            failed(2, "pose owning asset flag not found", a.address);
            continue;
        }
        auto buffer = Flow(code, flag, pair, {asset}, {a.operands[1].mem.base});
        if (!buffer) {
            failed(3, "pose buffer dataflow not proven", a.address);
            continue;
        }

        auto consume = flag;
        auto decoded_asset = asset;
        for (std::size_t j = flag; j > 0; --j) {
            const auto& d = instructions[j - 1];
            bool writes = false;
            for (unsigned k = 0; k < d.instruction.operand_count; ++k) {
                const auto& o = d.operands[k];
                writes |= o.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                    Dependency(o.reg.value) == Dependency(asset);
            }
            if (!writes)
                continue;
            if (d.instruction.mnemonic != ZYDIS_MNEMONIC_XOR ||
                d.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
                break;
            bool guarded = false;
            for (std::size_t k = j - 1; k > 0 && j - k < 64; --k) {
                const auto& guard = instructions[k - 1];
                if (guard.instruction.mnemonic != ZYDIS_MNEMONIC_CMOVB ||
                    guard.operands[0].reg.value != asset ||
                    guard.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
                    continue;
                const auto zero = guard.operands[1].reg.value;
                for (std::size_t n = k - 1; n > 0 && k - n < 64; --n) {
                    const auto& z = instructions[n - 1];
                    if (z.instruction.mnemonic == ZYDIS_MNEMONIC_XOR &&
                        z.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        z.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        Dependency(z.operands[0].reg.value) == Dependency(zero) &&
                        z.operands[0].reg.value == z.operands[1].reg.value) {
                        guarded = true;
                        break;
                    }
                }
                break;
            }
            if (guarded) {
                consume = j - 1;
                decoded_asset = d.operands[1].reg.value;
            }
            break;
        }
        if (consume == flag) {
            failed(4, "pose asset xor and conditional owner not proven", instructions[flag].address);
            continue;
        }
        failed(5, "pose selector branches or asset dataflow not proven", instructions[consume].address);
        for (std::size_t branch = 1; branch < flag; ++branch) {
            auto test_index = branch - 1;
            while (test_index > 0 && branch - test_index < 8) {
                const auto* flags = instructions[test_index].instruction.cpu_flags;
                if (flags && (flags->modified | flags->set_0 | flags->set_1 | flags->undefined))
                    break;
                --test_index;
            }
            const auto& test = instructions[test_index];
            const auto& conditional = instructions[branch];
            if (test.instruction.mnemonic != ZYDIS_MNEMONIC_TEST ||
                test.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                test.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || test.operands[1].imm.value.u != 1 ||
                conditional.instruction.meta.category != ZYDIS_CATEGORY_COND_BR)
                continue;
            const auto other = target(conditional);
            if (other >= instructions.size() || other <= branch)
                continue;
            auto join = instructions.size(), jump = join;
            for (std::size_t j = branch + 1; j < instructions.size() && j < branch + 192; ++j) {
                if (instructions[j].instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
                    const auto to = target(instructions[j]);
                    if (to > other && to < flag) {
                        join = to;
                        jump = j;
                    }
                    break;
                }
                if (instructions[j].instruction.meta.category == ZYDIS_CATEGORY_CALL || j == other)
                    break;
            }
            if (join == instructions.size())
                for (std::size_t j = other; j < instructions.size() && j < other + 192; ++j) {
                    if (instructions[j].instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
                        const auto to = target(instructions[j]);
                        if (to > branch && to < flag && to < other) {
                            join = to;
                            jump = j;
                        }
                        break;
                    }
                    if (instructions[j].instruction.meta.category == ZYDIS_CATEGORY_CALL)
                        break;
                }
            if (join == instructions.size())
                continue;
            const auto first_end = other < join ? jump : join;
            const auto second_end = other < join ? join : jump;
            std::array<std::map<ZydisRegister, std::vector<std::int64_t>>, 2> fields;
            for (unsigned arm = 0; arm < 2; ++arm)
                for (std::size_t j = arm ? other : branch + 1; j < (arm ? second_end : first_end); ++j) {
                    const auto& d = instructions[j];
                    for (unsigned k = 0; k < d.instruction.operand_count_visible; ++k) {
                        const auto& o = d.operands[k];
                        if (o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.size == 64 &&
                            (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) &&
                            o.mem.index == ZYDIS_REGISTER_NONE && o.mem.disp.value > 0 &&
                            Dependency(o.mem.base) && o.mem.base != ZYDIS_REGISTER_RSP)
                            fields[arm][o.mem.base].push_back(o.mem.disp.value);
                    }
                }
            for (const auto& [receiver, offsets] : fields[0]) {
                if (!fields[1].contains(receiver))
                    continue;
                std::size_t start = branch;
                Location input{receiver};
                for (std::size_t j = branch - 1; j > 0 && test.address - instructions[j - 1].address < 0x400;
                    --j) {
                    const auto& d = instructions[j - 1];
                    for (unsigned k = 0; k < d.instruction.operand_count_visible; ++k) {
                        const auto& o = d.operands[k];
                        if (o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.base == receiver &&
                            o.mem.index == ZYDIS_REGISTER_NONE && o.mem.disp.value > 0 &&
                            (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ)) {
                            start = j - 1;
                            break;
                        }
                    }
                    if (start != branch)
                        break;
                }
                if (start == branch)
                    continue;
                for (std::size_t j = start;
                    j > 0 && instructions[start].address - instructions[j - 1].address < 0x100; --j) {
                    const auto& d = instructions[j - 1];
                    if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                        d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        d.operands[0].reg.value == receiver && LocalSlot(d.operands[1]) &&
                        d.operands[1].size == 64) {
                        input = {ZYDIS_REGISTER_NONE, d.operands[1].mem.disp.value, true};
                        break;
                    }
                }

                if (auto selector = Flow(code, start, consume, input, {decoded_asset}))
                    result.push_back({std::move(*selector), *buffer});
            }
        }
    }
    if (validation && result.empty())
        validation(reason, reason_at, observed);
    return result;
}
}
