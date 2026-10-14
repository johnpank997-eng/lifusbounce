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
using ResolvedBranches = std::map<std::uint64_t, std::vector<std::uint64_t>>;

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

std::uint32_t TrackedDependency(ZydisRegister reg) {
    if (ZydisRegisterGetClass(reg) == ZYDIS_REGCLASS_XMM) {
        const auto id = ZydisRegisterGetId(reg);
        return id >= 0 && id < 16 ? 1u << (16 + id) : 0;
    }
    return Dependency(reg);
}

bool StackProbe(const Emulator::Program& code) {
    const auto& ins = code.instructions;
    constexpr std::array operations{ZYDIS_MNEMONIC_SUB, ZYDIS_MNEMONIC_MOV, ZYDIS_MNEMONIC_MOV,
        ZYDIS_MNEMONIC_XOR, ZYDIS_MNEMONIC_LEA, ZYDIS_MNEMONIC_SUB, ZYDIS_MNEMONIC_CMOVB, ZYDIS_MNEMONIC_MOV,
        ZYDIS_MNEMONIC_CMP, ZYDIS_MNEMONIC_JNB, ZYDIS_MNEMONIC_AND, ZYDIS_MNEMONIC_LEA, ZYDIS_MNEMONIC_MOV,
        ZYDIS_MNEMONIC_CMP, ZYDIS_MNEMONIC_JNZ, ZYDIS_MNEMONIC_MOV, ZYDIS_MNEMONIC_MOV, ZYDIS_MNEMONIC_ADD,
        ZYDIS_MNEMONIC_RET};
    if (ins.size() != operations.size() || code.begin != ins.front().address ||
        code.end != ins.back().address + ins.back().instruction.length)
        return false;
    for (std::size_t j = 0; j < ins.size(); ++j)
        if (ins[j].instruction.mnemonic != operations[j] ||
            (j && ins[j].address != ins[j - 1].address + ins[j - 1].instruction.length))
            return false;
    const auto reg = [&](std::size_t j, unsigned k, ZydisRegister value) {
        const auto& o = ins[j].operands[k];
        return o.type == ZYDIS_OPERAND_TYPE_REGISTER && o.reg.value == value;
    };
    const auto immediate = [&](std::size_t j, unsigned k, std::uint64_t value) {
        const auto& o = ins[j].operands[k];
        return o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !o.imm.is_relative && o.size && o.size <= 64 &&
            (o.imm.value.u & (o.size == 64 ? ~0ull : (1ull << o.size) - 1)) == value;
    };
    const auto memory = [&](std::size_t j, unsigned k, ZydisRegister base, std::int64_t displacement,
                            unsigned bits, ZydisRegister segment = ZYDIS_REGISTER_SS) {
        const auto& o = ins[j].operands[k];
        return o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.base == base &&
            o.mem.index == ZYDIS_REGISTER_NONE && o.mem.disp.value == displacement && o.size == bits &&
            o.mem.segment == segment;
    };
    const auto branch = [&](std::size_t j, std::size_t target) {
        const auto& o = ins[j].operands[0];
        return o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative &&
            ins[j].address + ins[j].instruction.length + o.imm.value.s == ins[target].address;
    };
    return reg(0, 0, ZYDIS_REGISTER_RSP) && immediate(0, 1, 16) && memory(1, 0, ZYDIS_REGISTER_RSP, 0, 64) &&
        reg(1, 1, ZYDIS_REGISTER_R10) && memory(2, 0, ZYDIS_REGISTER_RSP, 8, 64) &&
        reg(2, 1, ZYDIS_REGISTER_R11) && reg(3, 0, ZYDIS_REGISTER_R11) && reg(3, 1, ZYDIS_REGISTER_R11) &&
        reg(4, 0, ZYDIS_REGISTER_R10) && memory(4, 1, ZYDIS_REGISTER_RSP, 24, 64) &&
        reg(5, 0, ZYDIS_REGISTER_R10) && reg(5, 1, ZYDIS_REGISTER_RAX) && reg(6, 0, ZYDIS_REGISTER_R10) &&
        reg(6, 1, ZYDIS_REGISTER_R11) && reg(7, 0, ZYDIS_REGISTER_R11) &&
        memory(7, 1, ZYDIS_REGISTER_NONE, 16, 64, ZYDIS_REGISTER_GS) && reg(8, 0, ZYDIS_REGISTER_R10) &&
        reg(8, 1, ZYDIS_REGISTER_R11) && branch(9, 15) && reg(10, 0, ZYDIS_REGISTER_R10W) &&
        immediate(10, 1, 0xf000) && reg(11, 0, ZYDIS_REGISTER_R11) &&
        memory(11, 1, ZYDIS_REGISTER_R11, -0x1000, 64, ZYDIS_REGISTER_DS) &&
        memory(12, 0, ZYDIS_REGISTER_R11, 0, 8, ZYDIS_REGISTER_DS) && immediate(12, 1, 0) &&
        reg(13, 0, ZYDIS_REGISTER_R10) && reg(13, 1, ZYDIS_REGISTER_R11) && branch(14, 11) &&
        reg(15, 0, ZYDIS_REGISTER_R10) && memory(15, 1, ZYDIS_REGISTER_RSP, 0, 64) &&
        reg(16, 0, ZYDIS_REGISTER_R11) && memory(16, 1, ZYDIS_REGISTER_RSP, 8, 64) &&
        reg(17, 0, ZYDIS_REGISTER_RSP) && immediate(17, 1, 16) &&
        ins[18].instruction.operand_count_visible == 0;
}

std::optional<std::int64_t> CallerSlot(const Emulator::Program& code, std::size_t before,
    const NativeResolver& resolve = {}, const ResolvedBranches* branches = nullptr,
    bool allow_entry = false) {
    if (code.instructions.empty() || before > code.instructions.size())
        return std::nullopt;
    constexpr auto unknown = std::numeric_limits<std::int64_t>::min();
    std::vector<std::optional<std::int64_t>> states(code.instructions.size() + 1);
    states[0] = 0;
    std::vector<std::size_t> pending{0};
    while (!pending.empty()) {
        const auto j = pending.back();
        pending.pop_back();
        if (j == code.instructions.size())
            continue;
        const auto& d = code.instructions[j];
        const auto& x = d.operands[0];
        const auto& y = d.operands[1];
        auto depth = *states[j];
        if (depth != unknown && d.instruction.mnemonic == ZYDIS_MNEMONIC_PUSH && x.size == 64)
            depth += 8;
        else if (depth != unknown && d.instruction.mnemonic == ZYDIS_MNEMONIC_POP && x.size == 64)
            depth = x.type == ZYDIS_OPERAND_TYPE_REGISTER && x.reg.value == ZYDIS_REGISTER_RSP ? unknown
                                                                                               : depth - 8;
        else if (depth != unknown &&
            (d.instruction.mnemonic == ZYDIS_MNEMONIC_SUB || d.instruction.mnemonic == ZYDIS_MNEMONIC_ADD) &&
            x.type == ZYDIS_OPERAND_TYPE_REGISTER && x.reg.value == ZYDIS_REGISTER_RSP &&
            y.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (y.imm.value.u > 0x8000)
                depth = unknown;
            else {
                const auto amount = static_cast<std::int64_t>(y.imm.value.u);
                depth += d.instruction.mnemonic == ZYDIS_MNEMONIC_SUB ? amount : -amount;
            }
        } else if (depth != unknown && j >= 2 && resolve && d.instruction.mnemonic == ZYDIS_MNEMONIC_SUB &&
            x.reg.value == ZYDIS_REGISTER_RSP && x.type == ZYDIS_OPERAND_TYPE_REGISTER &&
            y.type == ZYDIS_OPERAND_TYPE_REGISTER && y.reg.value == ZYDIS_REGISTER_RAX &&
            code.instructions[j - 1].instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
            code.instructions[j - 2].instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            code.instructions[j - 2].operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            code.instructions[j - 2].operands[0].reg.value == ZYDIS_REGISTER_EAX &&
            code.instructions[j - 2].operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            code.instructions[j - 2].operands[1].imm.value.u <= 0x7ff8) {
            const auto& call = code.instructions[j - 1];
            const auto& target = call.operands[0];
            const bool bypass =
                std::any_of(code.instructions.begin(), code.instructions.end(), [&](const auto& branch) {
                    const auto category = branch.instruction.meta.category;
                    const auto& destination = branch.operands[0];
                    if ((category != ZYDIS_CATEGORY_COND_BR && category != ZYDIS_CATEGORY_UNCOND_BR) ||
                        destination.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !destination.imm.is_relative)
                        return false;
                    const auto address = branch.address + branch.instruction.length + destination.imm.value.s;
                    return address == call.address || address == d.address;
                });
            if (!bypass && target.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && target.imm.is_relative) {
                const auto probe = resolve(call.address + call.instruction.length + target.imm.value.s);
                depth = probe && StackProbe(*probe)
                    ? depth + static_cast<std::int64_t>(code.instructions[j - 2].operands[1].imm.value.u)
                    : unknown;
            } else
                depth = unknown;
        } else if (d.instruction.meta.category != ZYDIS_CATEGORY_CALL && depth != unknown)
            for (unsigned k = 0; k < d.instruction.operand_count; ++k) {
                const auto& o = d.operands[k];
                if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                    (Dependency(o.reg.value) & Dependency(ZYDIS_REGISTER_RSP)))
                    depth = unknown;
            }
        if (depth < 0 || depth > 0x7ff8)
            depth = unknown;
        const auto push = [&](std::size_t target) {
            if (target > code.instructions.size())
                return;
            if (!states[target]) {
                states[target] = depth;
                pending.push_back(target);
            } else if (*states[target] != depth && *states[target] != unknown) {
                states[target] = unknown;
                pending.push_back(target);
            }
        };
        const auto category = d.instruction.meta.category;
        if (category != ZYDIS_CATEGORY_RET && category != ZYDIS_CATEGORY_UNCOND_BR)
            push(j + 1);
        if ((category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) &&
            x.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && x.imm.is_relative) {
            const auto target = d.address + d.instruction.length + x.imm.value.s;
            const auto found = std::lower_bound(code.instructions.begin(), code.instructions.end(), target,
                [](const auto& value, std::uint64_t at) { return value.address < at; });
            if (found != code.instructions.end() && found->address == target)
                push(static_cast<std::size_t>(found - code.instructions.begin()));
        } else if (category == ZYDIS_CATEGORY_UNCOND_BR && branches) {
            if (const auto found = branches->find(d.address); found != branches->end())
                for (const auto target : found->second) {
                    const auto at =
                        std::lower_bound(code.instructions.begin(), code.instructions.end(), target,
                            [](const auto& value, std::uint64_t address) { return value.address < address; });
                    if (at != code.instructions.end() && at->address == target)
                        push(static_cast<std::size_t>(at - code.instructions.begin()));
                }
        }
    }
    return states[before] && (*states[before] > 0 || (allow_entry && *states[before] == 0)) ? states[before]
                                                                                            : std::nullopt;
}

struct Word {
    std::uint64_t constant{};
    std::map<std::size_t, std::uint64_t> terms;
    bool operator==(const Word&) const = default;
};

struct Algebra {
    bool complement{};

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
                    if (b.operation != ZYDIS_MNEMONIC_AND)
                        continue;
                    Word left, right;
                    std::uint64_t right_coefficient = 1;
                    if (a.left == b.left && same_mask &&
                        multiple == coefficient * (a.operation == ZYDIS_MNEMONIC_XOR ? 2 : 1)) {
                        left = a.left;
                        right = a.right;
                    } else if (complement && a.operation == ZYDIS_MNEMONIC_XOR &&
                        multiple == coefficient * ~1ull) {
                        const auto inverted = [](const Word& value) {
                            Word result{~0ull};
                            Add(result, value, ~0ull);
                            return result;
                        };
                        const auto first = inverted(a.left), second = inverted(a.right);
                        if ((first == b.left && a.right == b.right) ||
                            (first == b.right && a.right == b.left)) {
                            left = a.left;
                            right = a.right;
                        } else if ((second == b.left && a.left == b.right) ||
                            (second == b.right && a.left == b.left)) {
                            left = a.right;
                            right = a.left;
                        } else
                            continue;
                        right_coefficient = ~0ull;
                    } else
                        continue;
                    const auto amount = coefficient;
                    value.terms.erase(id);
                    value.terms.erase(other);
                    Add(value, left, amount);
                    Add(value, right, amount * right_coefficient);
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

Emulator::Program Simplify(const Emulator::Program& source, bool complement = false) {
    auto result = source;
    Algebra math;
    math.complement = complement;
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

std::optional<Emulator::Program> PruneArray(const Emulator::Program& source, ZydisRegister input,
    ZydisRegister array, ZydisRegister count, std::int64_t pair, std::optional<std::uint32_t> caller,
    bool initialized, std::uint32_t* external = nullptr, std::set<std::int64_t>* external_slots = nullptr) {
    struct Live {
        std::uint32_t registers{};
        ZydisAccessedFlagsMask flags{};
        std::set<std::int64_t> slots;
        bool operator==(const Live&) const = default;
    };

    const auto size = source.instructions.size();
    if (size < 2 || size > 2048)
        return std::nullopt;
    std::vector<std::vector<std::size_t>> successors(size);
    std::vector<bool> reachable(size + 1), selected(size);
    std::vector<std::size_t> pending{0};
    while (!pending.empty()) {
        const auto index = pending.back();
        pending.pop_back();
        if (index > size || reachable[index])
            continue;
        reachable[index] = true;
        if (index == size)
            continue;
        const auto& d = source.instructions[index];
        const auto category = d.instruction.meta.category;
        if (category != ZYDIS_CATEGORY_UNCOND_BR && category != ZYDIS_CATEGORY_RET)
            successors[index].push_back(index + 1);
        if (category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) {
            const auto& o = d.operands[0];
            if (o.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !o.imm.is_relative)
                return std::nullopt;
            const auto target = d.address + d.instruction.length + o.imm.value.s;
            const auto at = std::lower_bound(source.instructions.begin(), source.instructions.end(), target,
                [](const auto& instruction, std::uint64_t address) { return instruction.address < address; });
            if (target == source.end)
                successors[index].push_back(size);
            else if (at != source.instructions.end() && at->address == target)
                successors[index].push_back(static_cast<std::size_t>(at - source.instructions.begin()));
            else
                return std::nullopt;
        }
        pending.insert(pending.end(), successors[index].begin(), successors[index].end());
    }
    if (!reachable[size])
        return std::nullopt;
    std::vector<Live> states(size + 1);
    states[size].registers = Dependency(array) | Dependency(count);
    bool changed = true;
    unsigned rounds{};
    while (changed && ++rounds <= 2048) {
        changed = false;
        for (std::size_t at = size; at > 0; --at) {
            const auto index = at - 1;
            if (!reachable[index])
                continue;
            Live next;
            for (const auto successor : successors[index]) {
                const auto& value = states[successor];
                next.registers |= value.registers;
                next.flags |= value.flags;
                next.slots.insert(value.slots.begin(), value.slots.end());
            }
            const auto& d = source.instructions[index];
            const auto& ins = d.instruction;
            const auto written = ins.cpu_flags ? ins.cpu_flags->modified | ins.cpu_flags->set_0 |
                    ins.cpu_flags->set_1 | ins.cpu_flags->undefined
                                               : 0;
            bool keep = ins.meta.category == ZYDIS_CATEGORY_COND_BR ||
                ins.meta.category == ZYDIS_CATEGORY_UNCOND_BR || (next.flags & written);
            for (unsigned j = 0; j < ins.operand_count; ++j) {
                const auto& o = d.operands[j];
                if (!(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                    continue;
                keep |= o.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (next.registers & TrackedDependency(o.reg.value));
                keep |= o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.base == ZYDIS_REGISTER_RSP &&
                    ((o.mem.index != ZYDIS_REGISTER_NONE && o.mem.disp.value == pair) ||
                        (o.mem.index == ZYDIS_REGISTER_NONE && next.slots.contains(o.mem.disp.value)));
            }
            if (keep) {
                if (ins.cpu_flags && (next.flags & ins.cpu_flags->undefined))
                    return std::nullopt;
                next.flags = (next.flags & ~written) | (ins.cpu_flags ? ins.cpu_flags->tested : 0);
                for (unsigned j = 0; j < ins.operand_count; ++j) {
                    const auto& o = d.operands[j];
                    if (!(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) ||
                        (o.actions & ZYDIS_OPERAND_ACTION_CONDWRITE))
                        continue;
                    if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && o.size >= 32)
                        next.registers &= ~TrackedDependency(o.reg.value);
                    if (LocalSlot(o) && o.size >= 64)
                        next.slots.erase(o.mem.disp.value);
                }
                const bool zero =
                    (ins.mnemonic == ZYDIS_MNEMONIC_XOR || ins.mnemonic == ZYDIS_MNEMONIC_XORPS) &&
                    d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    d.operands[0].reg.value == d.operands[1].reg.value;
                for (unsigned j = 0; j < ins.operand_count; ++j) {
                    const auto& o = d.operands[j];
                    if (o.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) && !zero)
                        next.registers |= TrackedDependency(o.reg.value);
                    if (o.type != ZYDIS_OPERAND_TYPE_MEMORY)
                        continue;
                    next.registers |= TrackedDependency(o.mem.base) | TrackedDependency(o.mem.index);
                    if ((o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) && ins.mnemonic != ZYDIS_MNEMONIC_LEA &&
                        o.mem.base == ZYDIS_REGISTER_RSP) {
                        if (o.mem.index == ZYDIS_REGISTER_NONE)
                            next.slots.insert(o.mem.disp.value);
                        else if (o.mem.disp.value == pair) {
                            next.slots.insert(pair);
                            next.slots.insert(pair + 8);
                        } else
                            return std::nullopt;
                    }
                }
            }
            next.registers &= ~Dependency(ZYDIS_REGISTER_RSP);
            selected[index] = keep;
            if (states[index] != next) {
                states[index] = std::move(next);
                changed = true;
            }
        }
    }
    if (external)
        *external = states[0].registers & ~Dependency(input);
    if (external_slots) {
        external_slots->clear();
        for (const auto slot : states[0].slots)
            if ((!caller || slot != *caller) && (!initialized || (slot != pair && slot != pair + 8)))
                external_slots->insert(slot);
    }
    if (changed || states[0].flags || states[0].registers != Dependency(input))
        return std::nullopt;
    for (const auto slot : states[0].slots)
        if ((!caller || slot != *caller) && (!initialized || (slot != pair && slot != pair + 8)))
            return std::nullopt;
    auto result = source;
    for (std::size_t j = 0; j < size; ++j)
        if (!selected[j]) {
            auto& d = result.instructions[j];
            d.instruction.mnemonic = ZYDIS_MNEMONIC_NOP;
            d.instruction.meta.category = ZYDIS_CATEGORY_NOP;
            d.instruction.operand_count = d.instruction.operand_count_visible = 0;
            d.instruction.cpu_flags = nullptr;
            d.operands = {};
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
    std::optional<Location> input = std::nullopt, const ResolvedBranches* branches = nullptr,
    bool* return_cancellation = nullptr) {
    if (return_cancellation)
        *return_cancellation = false;
    if (before > code.instructions.size() || (!output.stack && !TrackedDependency(output.reg)))
        return std::nullopt;
    Expression result{{0, 0, {}, true}, output.reg, 0};
    auto needed = output.stack ? 0 : TrackedDependency(output.reg);
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
        } else if (category == ZYDIS_CATEGORY_UNCOND_BR && branches) {
            if (const auto found = branches->find(d.address); found != branches->end())
                for (const auto address : found->second) {
                    const auto target = std::lower_bound(code.instructions.begin(), boundary, address,
                        [](const auto& value, std::uint64_t at) { return value.address < at; });
                    if (target != boundary && target->address == address)
                        predecessors[target - code.instructions.begin()].push_back(at);
                }
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
                bound |= needed & TrackedDependency(input->reg);
                needed &= ~TrackedDependency(input->reg);
            }
        }
        const auto& d = code.instructions[index - 1];
        const auto& i = d.instruction;
        if (i.mnemonic == ZYDIS_MNEMONIC_CALL && ((needed & 0x3f0f07u) || flags)) {
            if (return_cancellation)
                *return_cancellation =
                    (needed & 0x3f0f07u) == Dependency(ZYDIS_REGISTER_RAX) && !flags && slots.empty();
            return std::nullopt;
        }
        const auto writes = i.cpu_flags
            ? (i.cpu_flags->modified | i.cpu_flags->set_0 | i.cpu_flags->set_1 | i.cpu_flags->undefined)
            : 0;
        bool selected = (flags & writes) != 0;
        for (unsigned j = 0; j < i.operand_count; ++j) {
            const auto& o = d.operands[j];
            if (!(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                continue;
            if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && (needed & TrackedDependency(o.reg.value)))
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
            if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && !(o.actions & ZYDIS_OPERAND_ACTION_CONDWRITE)) {
                const bool vector = ZydisRegisterGetClass(o.reg.value) == ZYDIS_REGCLASS_XMM;
                const bool complete = vector ? o.size == 128 || i.mnemonic == ZYDIS_MNEMONIC_MOVQ ||
                        i.mnemonic == ZYDIS_MNEMONIC_MOVD ||
                        (i.mnemonic == ZYDIS_MNEMONIC_MOVSS &&
                            d.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
                                             : o.size >= 32;
                if (complete)
                    needed &= ~TrackedDependency(o.reg.value);
            }
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
        if ((i.mnemonic == ZYDIS_MNEMONIC_XOR || i.mnemonic == ZYDIS_MNEMONIC_XORPS) &&
            i.operand_count_visible == 2 && d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            d.operands[0].reg.value == d.operands[1].reg.value)
            zero = true;
        for (unsigned j = 0; j < i.operand_count; ++j) {
            const auto& o = d.operands[j];
            if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                needed |= TrackedDependency(o.mem.base) | TrackedDependency(o.mem.index);
                if (LocalSlot(o) && (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) &&
                    i.mnemonic != ZYDIS_MNEMONIC_LEA)
                    slots[o.mem.disp.value] =
                        std::max(slots[o.mem.disp.value], static_cast<unsigned>(o.size));
            }
            if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) &&
                !zero)
                needed |= TrackedDependency(o.reg.value);
        }
        result.code.instructions.push_back(d);
        definitions.push_back(index - 1);
    }
    needed &= ~(1u << 4);
    if (input) {
        if (input->stack)
            slots.erase(input->slot);
        else {
            bound |= needed & TrackedDependency(input->reg);
            needed &= ~TrackedDependency(input->reg);
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
                if (o.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !o.imm.is_relative) {
                    if (!branches)
                        return std::nullopt;
                    const auto found = branches->find(d.address);
                    if (found == branches->end())
                        return std::nullopt;
                    for (const auto address : found->second) {
                        const auto target =
                            std::lower_bound(code.instructions.begin(), code.instructions.end(), address,
                                [](const auto& value, std::uint64_t at) { return value.address < at; });
                        if (target == code.instructions.end() || target->address != address)
                            return std::nullopt;
                        pending.push_back(static_cast<std::size_t>(target - code.instructions.begin()));
                    }
                    continue;
                }
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
            Dependency(source));
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
        if (!value && target.stack && CallerSlot(source, begin) == target.slot) {
            std::array<unsigned char, 18> immediate{0x48, 0xb8};
            std::memcpy(immediate.data() + 2, &source.begin, 8);
            const std::array<unsigned char, 4> store{0x48, 0x89, 0x84, 0x24};
            std::copy(store.begin(), store.end(), immediate.begin() + 10);
            const auto slot = static_cast<std::uint32_t>(target.slot);
            std::memcpy(immediate.data() + 14, &slot, 4);
            if (auto constant = Emulator::Decode(std::as_bytes(std::span(immediate)), source.begin)) {
                constant->linear = true;
                value = Expression{std::move(*constant), ZYDIS_REGISTER_RAX, 0};
            }
        }
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
    const auto find = [&](const Emulator::Program& source) -> std::optional<Expression> {
        for (std::size_t j = 0; j < source.instructions.size(); ++j) {
            const auto& d = source.instructions[j];
            if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                d.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                d.operands[1].mem.index != ZYDIS_REGISTER_NONE ||
                d.operands[1].mem.base == ZYDIS_REGISTER_RIP ||
                d.operands[1].mem.base == ZYDIS_REGISTER_RSP || d.operands[1].mem.disp.value <= 0)
                continue;
            auto result = Slice(source, j, d.operands[1].mem.base);
            if (!result || result->inputs || result->code.instructions.empty()) {
                if (validation)
                    validation(!result ? "root receiver dataflow unresolved"
                                       : "root receiver requires external inputs",
                        d.address, result ? result->inputs : 0);
                continue;
            }
            const auto& tail = result->code.instructions.back();
            const bool tls = tail.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                tail.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && tail.operands[1].mem.scale == 8 &&
                tail.operands[1].mem.index != ZYDIS_REGISTER_NONE &&
                std::any_of(result->code.instructions.begin(), result->code.instructions.end(),
                    [&](const auto& load) {
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
        return std::nullopt;
    };
    if (auto result = find(code))
        return result;
    if (auto result = find(Simplify(code))) {
        if (validation)
            validation(
                "root receiver algebra normalized", result->code.begin, result->code.instructions.size());
        return result;
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
        const bool interleaved = instructions[j + 1].instruction.mnemonic == ZYDIS_MNEMONIC_SHL;
        const auto& shift = instructions[j + (interleaved ? 1 : 2)];
        const bool reversed = instructions[j].operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            instructions[j].operands[0].reg.value == shift.operands[0].reg.value;
        const auto& table = instructions[j + (interleaved ? 2 : reversed ? 1 : 0)];
        const auto& count = instructions[j + (interleaved || reversed ? 0 : 1)];
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
        if (!index)
            for (std::size_t k = j + 3;
                k + 1 < instructions.size() && instructions[k].address - table.address < 0x100; ++k) {
                const auto& compare = instructions[k];
                const auto& branch = instructions[k + 1];
                if (compare.instruction.mnemonic != ZYDIS_MNEMONIC_CMP ||
                    compare.operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                    compare.operands[0].mem.base != indexed ||
                    compare.operands[0].mem.index != ZYDIS_REGISTER_NONE ||
                    compare.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                    static_cast<std::uint32_t>(compare.operands[1].imm.value.u) != 0xa9cefd4a ||
                    branch.instruction.mnemonic != ZYDIS_MNEMONIC_JZ ||
                    branch.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                    !branch.operands[0].imm.is_relative)
                    continue;
                const auto target =
                    branch.address + branch.instruction.length + branch.operands[0].imm.value.s;
                const auto found = std::lower_bound(instructions.begin(), instructions.end(), target,
                    [](const auto& d, std::uint64_t at) { return d.address < at; });
                if (found != instructions.end() && found->address == target)
                    index = found->instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX &&
                        found->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        found->operands[1].size == 16 && found->operands[1].mem.base == indexed &&
                        found->operands[1].mem.index == ZYDIS_REGISTER_NONE &&
                        found->operands[1].mem.disp.value == 4;
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

std::vector<ArrayDescriptor> Arrays(const Emulator::Program& code, const NativeResolver& resolve,
    std::span<const std::byte> native_bytes, std::vector<Expression>* closed_owners) {
    std::vector<ArrayDescriptor> result;
    const auto& instructions = code.instructions;
    ResolvedBranches branches;
    const auto register_width = [](const ZydisDecodedOperand& operand, unsigned bits) {
        return operand.type == ZYDIS_OPERAND_TYPE_REGISTER && operand.size == bits &&
            Dependency(operand.reg.value) &&
            ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, operand.reg.value) == bits;
    };
    for (std::size_t j = 8; j < instructions.size(); ++j) {
        const auto& jump = instructions[j];
        if (jump.instruction.meta.category != ZYDIS_CATEGORY_UNCOND_BR ||
            !register_width(jump.operands[0], 64) || jump.instruction.address_width != 64)
            continue;
        const auto& saved = instructions[j - 4];
        const bool preservation = saved.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            register_width(saved.operands[0], 64) && register_width(saved.operands[1], 64);
        if (preservation && j < 9)
            continue;
        const auto first_index = j - (preservation ? 9 : 8);
        const auto& move = instructions[first_index];
        const auto& shift = instructions[first_index + 1];
        const auto& mask = instructions[first_index + 2];
        const auto& bound = instructions[first_index + 3];
        const auto& exit = instructions[first_index + 4];
        const auto& table = instructions[j - 3];
        const auto& load = instructions[j - 2];
        const auto& add = instructions[j - 1];
        const auto index = move.operands[0].reg.value;
        const auto target = jump.operands[0].reg.value;
        if (move.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || !register_width(move.operands[0], 32) ||
            !register_width(move.operands[1], 32) || shift.instruction.mnemonic != ZYDIS_MNEMONIC_SHR ||
            !register_width(shift.operands[0], 32) || shift.operands[0].reg.value != index ||
            shift.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || shift.operands[1].imm.value.u >= 32 ||
            mask.instruction.mnemonic != ZYDIS_MNEMONIC_AND || !register_width(mask.operands[0], 32) ||
            mask.operands[0].reg.value != index || mask.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
            bound.instruction.mnemonic != ZYDIS_MNEMONIC_CMP || !register_width(bound.operands[0], 32) ||
            bound.operands[0].reg.value != index || bound.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
            !bound.operands[1].imm.value.u || bound.operands[1].imm.value.u > 15 ||
            mask.operands[1].imm.value.u < bound.operands[1].imm.value.u ||
            exit.instruction.mnemonic != ZYDIS_MNEMONIC_JNBE ||
            exit.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !exit.operands[0].imm.is_relative ||
            table.instruction.mnemonic != ZYDIS_MNEMONIC_LEA || !register_width(table.operands[0], 64) ||
            table.instruction.address_width != 64 || table.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
            table.operands[1].mem.base != ZYDIS_REGISTER_RIP ||
            table.operands[1].mem.index != ZYDIS_REGISTER_NONE ||
            load.instruction.mnemonic != ZYDIS_MNEMONIC_MOVSXD || !register_width(load.operands[0], 64) ||
            load.operands[0].reg.value != target || load.instruction.address_width != 64 ||
            load.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || load.operands[1].size != 32 ||
            load.operands[1].mem.base != table.operands[0].reg.value ||
            load.operands[1].mem.segment != ZYDIS_REGISTER_DS ||
            ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, load.operands[1].mem.index) != 64 ||
            Dependency(load.operands[1].mem.index) != Dependency(index) || load.operands[1].mem.scale != 4 ||
            load.operands[1].mem.disp.value || add.instruction.mnemonic != ZYDIS_MNEMONIC_ADD ||
            !register_width(add.operands[0], 64) || add.operands[0].reg.value != target ||
            !register_width(add.operands[1], 64) || add.operands[1].reg.value != table.operands[0].reg.value)
            continue;
        if (preservation &&
            (Dependency(saved.operands[0].reg.value) &
                (Dependency(index) | Dependency(target) | Dependency(table.operands[0].reg.value) |
                    Dependency(ZYDIS_REGISTER_RSP))))
            continue;
        bool valid = true;
        for (auto k = first_index; k < j; ++k)
            valid &=
                instructions[k].address + instructions[k].instruction.length == instructions[k + 1].address;
        const auto first = move.address;
        for (const auto& d : instructions) {
            const auto& o = d.operands[0];
            const auto category = d.instruction.meta.category;
            if ((category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) &&
                o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative) {
                const auto at = d.address + d.instruction.length + o.imm.value.s;
                if (at > first && at <= jump.address)
                    valid = false;
            }
        }
        const auto at = table.address + table.instruction.length + table.operands[1].mem.disp.value;
        const auto size = (bound.operands[1].imm.value.u + 1) * 4;
        if (!valid || native_bytes.size() > 0x10000 || code.end < code.begin ||
            code.end - code.begin > native_bytes.size() || at < code.begin ||
            at - code.begin > native_bytes.size() ||
            size > native_bytes.size() - static_cast<std::size_t>(at - code.begin))
            continue;
        std::vector<std::uint64_t> targets;
        for (std::size_t k = 0; k < size; k += 4) {
            std::int32_t displacement{};
            std::memcpy(&displacement, native_bytes.data() + at - code.begin + k, 4);
            const auto destination = at + displacement;
            const auto found = std::lower_bound(instructions.begin(), instructions.end(), destination,
                [](const auto& d, std::uint64_t address) { return d.address < address; });
            if (found == instructions.end() || found->address != destination || destination <= jump.address ||
                found->instruction.mnemonic == ZYDIS_MNEMONIC_POP ||
                found->instruction.mnemonic == ZYDIS_MNEMONIC_RET ||
                (found->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (found->operands[0].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                    (Dependency(found->operands[0].reg.value) & Dependency(ZYDIS_REGISTER_RSP))))
                valid = false;
            targets.push_back(destination);
        }
        if (valid)
            branches.emplace(jump.address, std::move(targets));
    }
    std::vector<bool> function_reachable(instructions.size());
    std::vector<std::size_t> function_pending{0};
    bool unclosed_control_flow{};
    while (!function_pending.empty()) {
        const auto at = function_pending.back();
        function_pending.pop_back();
        if (at >= instructions.size() || function_reachable[at])
            continue;
        function_reachable[at] = true;
        const auto& d = instructions[at];
        const auto category = d.instruction.meta.category;
        if (category == ZYDIS_CATEGORY_RET)
            continue;
        if (category != ZYDIS_CATEGORY_UNCOND_BR) {
            if (at + 1 >= instructions.size() ||
                d.address + d.instruction.length != instructions[at + 1].address)
                unclosed_control_flow = true;
            else
                function_pending.push_back(at + 1);
        }
        const auto push = [&](std::uint64_t address) {
            const auto target = std::lower_bound(instructions.begin(), instructions.end(), address,
                [](const auto& value, std::uint64_t target_address) {
                    return value.address < target_address;
                });
            if (target != instructions.end() && target->address == address)
                function_pending.push_back(static_cast<std::size_t>(target - instructions.begin()));
            else if (address >= code.begin && address < code.end)
                unclosed_control_flow = true;
        };
        if (category == ZYDIS_CATEGORY_UNCOND_BR || category == ZYDIS_CATEGORY_COND_BR) {
            const auto& o = d.operands[0];
            if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative)
                push(d.address + d.instruction.length + o.imm.value.s);
            else if (const auto found = branches.find(d.address); found != branches.end())
                for (const auto address : found->second)
                    push(address);
            else
                unclosed_control_flow = true;
        }
    }
    const auto indexed_pair = [&](std::size_t write, std::int64_t pair, bool strict = false) {
        const auto& destination = instructions[write].operands[0];
        if (destination.type != ZYDIS_OPERAND_TYPE_MEMORY || destination.mem.base != ZYDIS_REGISTER_RSP ||
            destination.mem.scale != 1 || destination.mem.disp.value != pair ||
            (destination.size != 8 && destination.size != 64))
            return false;
        ZydisRegister counter = ZYDIS_REGISTER_NONE;
        for (std::size_t j = write; j > 0 && write - j < 6; --j) {
            const auto& d = instructions[j - 1];
            if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[0].size == 32 &&
                Dependency(d.operands[0].reg.value) == Dependency(destination.mem.index) &&
                d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[1].size == 32) {
                counter = d.operands[1].reg.value;
                break;
            }
        }
        if (counter == ZYDIS_REGISTER_NONE)
            for (std::size_t j = write + 1; j < instructions.size() && j - write < 16; ++j) {
                const auto& d = instructions[j];
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[0].size == 32 &&
                    Dependency(d.operands[0].reg.value) == Dependency(destination.mem.index) &&
                    d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[1].size == 32) {
                    counter = d.operands[1].reg.value;
                    break;
                }
            }
        if (counter == ZYDIS_REGISTER_NONE)
            return false;
        for (std::size_t j = write > 32 ? write - 32 : 0; j + 5 < instructions.size() && j < write + 32;
            ++j) {
            const auto& advance = instructions[j];
            const auto& compare = instructions[j + 1];
            const auto& assign = instructions[j + 2];
            const auto& exit = instructions[j + 3];
            if (advance.instruction.mnemonic != ZYDIS_MNEMONIC_LEA ||
                advance.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || advance.operands[0].size != 32 ||
                advance.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                Dependency(advance.operands[1].mem.base) != Dependency(counter) ||
                advance.operands[1].mem.index != ZYDIS_REGISTER_NONE ||
                advance.operands[1].mem.disp.value != 1 ||
                compare.instruction.mnemonic != ZYDIS_MNEMONIC_CMP ||
                compare.operands[0].reg.value != counter ||
                compare.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                compare.operands[1].imm.value.u != 15 || assign.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                assign.operands[0].reg.value != counter ||
                assign.operands[1].reg.value != advance.operands[0].reg.value ||
                exit.instruction.mnemonic != ZYDIS_MNEMONIC_JNB ||
                exit.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !exit.operands[0].imm.is_relative)
                continue;
            auto head_index = j + 4;
            const auto& alias = instructions[head_index];
            if (alias.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                alias.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && alias.operands[0].size == 32 &&
                Dependency(alias.operands[0].reg.value) == Dependency(destination.mem.index) &&
                alias.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                alias.operands[1].reg.value == counter)
                ++head_index;
            if (head_index + 1 >= instructions.size())
                continue;
            const auto& head = instructions[head_index];
            const auto& split = instructions[head_index + 1];
            if (head.instruction.mnemonic != ZYDIS_MNEMONIC_CMP || head.operands[0].reg.value != counter ||
                head.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || head.operands[1].imm.value.u != 8 ||
                split.instruction.mnemonic != ZYDIS_MNEMONIC_JNBE ||
                split.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !split.operands[0].imm.is_relative)
                continue;
            const auto byte_begin = split.address + split.instruction.length + split.operands[0].imm.value.s;
            const auto end = exit.address + exit.instruction.length + exit.operands[0].imm.value.s;
            const auto at = instructions[write].address;
            if (byte_begin >= advance.address || end <= split.address || at < byte_begin || at >= end ||
                (destination.size == 8 ? at >= advance.address : at <= split.address))
                continue;
            const auto first = std::lower_bound(instructions.begin(), instructions.end(), byte_begin,
                [](const auto& d, std::uint64_t address) { return d.address < address; });
            const auto last = std::lower_bound(instructions.begin(), instructions.end(), end,
                [](const auto& d, std::uint64_t address) { return d.address < address; });
            if (first == instructions.end() || first->address != byte_begin || last == instructions.end() ||
                last->address != end || last == instructions.begin())
                continue;
            const auto word = std::find_if(instructions.begin() + head_index + 2, last, [&](const auto& d) {
                const auto& o = d.operands[0];
                return o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.base == ZYDIS_REGISTER_RSP &&
                    o.mem.index != ZYDIS_REGISTER_NONE && o.mem.disp.value == pair && o.size == 64 &&
                    (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE);
            });
            if (word == last || word + 1 == last)
                continue;
            auto next = word + 1;
            if (next->instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                next->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && next->operands[0].size == 64 &&
                next->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && next->operands[1].size == 64 &&
                Dependency(next->operands[0].reg.value) != Dependency(counter) &&
                Dependency(next->operands[0].reg.value) != Dependency(destination.mem.index) &&
                word->instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                word->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                next->operands[0].reg.value == word->operands[1].reg.value &&
                (!next->instruction.cpu_flags ||
                    !(next->instruction.cpu_flags->modified | next->instruction.cpu_flags->set_0 |
                        next->instruction.cpu_flags->set_1 | next->instruction.cpu_flags->undefined |
                        next->instruction.cpu_flags->tested)) &&
                std::any_of(instructions.begin() + head_index + 2, word, [&](const auto& load) {
                    const auto& data = load.operands[0];
                    const auto& pointer = load.operands[1];
                    return load.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                        data.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        data.reg.value == next->operands[0].reg.value &&
                        pointer.type == ZYDIS_OPERAND_TYPE_MEMORY && pointer.size == 64 &&
                        pointer.mem.base == next->operands[1].reg.value &&
                        pointer.mem.index == word->operands[0].mem.index && pointer.mem.scale == 1 &&
                        pointer.mem.disp.value == 0;
                }))
                ++next;
            if (next != last && next->instruction.mnemonic == ZYDIS_MNEMONIC_ADD &&
                next->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && next->operands[0].size == 32 &&
                next->operands[0].reg.value == counter &&
                next->operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && next->operands[1].imm.value.u == 7)
                ++next;
            if (next == last)
                continue;
            const auto& repeat = *next;
            if (repeat.instruction.mnemonic != ZYDIS_MNEMONIC_JMP ||
                repeat.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                !repeat.operands[0].imm.is_relative ||
                repeat.address + repeat.instruction.length + repeat.operands[0].imm.value.s !=
                    advance.address)
                continue;
            std::optional<std::size_t> zero;
            for (auto k = static_cast<std::size_t>(first - instructions.begin());
                k > 0 && byte_begin - instructions[k - 1].address < 0x100; --k) {
                const auto& d = instructions[k - 1];
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_XOR && d.operands[0].reg.value == counter &&
                    d.operands[1].reg.value == counter) {
                    zero = k - 1;
                    break;
                }
            }
            if (!zero)
                continue;
            const auto finish = static_cast<std::size_t>(last - instructions.begin());
            if (strict) {
                bool incoming{};
                for (std::size_t source = 0; source < instructions.size(); ++source) {
                    if (!function_reachable[source] || (source >= *zero && source < finish))
                        continue;
                    const auto& d = instructions[source];
                    const auto category = d.instruction.meta.category;
                    if (category != ZYDIS_CATEGORY_COND_BR && category != ZYDIS_CATEGORY_UNCOND_BR)
                        continue;
                    const auto test = [&](std::uint64_t target) {
                        incoming |= target > instructions[*zero].address && target < last->address;
                    };
                    const auto& o = d.operands[0];
                    if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative)
                        test(d.address + d.instruction.length + o.imm.value.s);
                    else if (const auto found = branches.find(d.address); found != branches.end())
                        for (const auto target : found->second)
                            test(target);
                }
                if (incoming)
                    continue;
            }
            std::vector<bool> reachable(finish - *zero + 1);
            std::vector<std::size_t> pending{*zero};
            bool safe = true, step{};
            while (!pending.empty() && safe) {
                const auto k = pending.back();
                pending.pop_back();
                if (k < *zero || k > finish) {
                    safe = false;
                    break;
                }
                if (reachable[k - *zero])
                    continue;
                reachable[k - *zero] = true;
                if (k == finish)
                    continue;
                const auto& d = instructions[k];
                const auto category = d.instruction.meta.category;
                if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_RET) {
                    safe = false;
                    break;
                }
                if (category != ZYDIS_CATEGORY_UNCOND_BR)
                    pending.push_back(k + 1);
                if (category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) {
                    const auto& target = d.operands[0];
                    if (target.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !target.imm.is_relative) {
                        safe = false;
                        break;
                    }
                    const auto address = d.address + d.instruction.length + target.imm.value.s;
                    const auto found = std::lower_bound(instructions.begin(), instructions.end(), address,
                        [](const auto& instruction, std::uint64_t at) { return instruction.address < at; });
                    if (found == instructions.end() || found->address != address) {
                        safe = false;
                        break;
                    }
                    pending.push_back(static_cast<std::size_t>(found - instructions.begin()));
                }
            }
            for (std::size_t k = *zero + 1; safe && k < finish; ++k) {
                if (!reachable[k - *zero])
                    continue;
                const auto& d = instructions[k];
                for (unsigned operand = 0; operand < d.instruction.operand_count; ++operand) {
                    const auto& o = d.operands[operand];
                    if (o.type != ZYDIS_OPERAND_TYPE_REGISTER ||
                        !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) ||
                        Dependency(o.reg.value) != Dependency(counter))
                        continue;
                    const bool skip = d.instruction.mnemonic == ZYDIS_MNEMONIC_ADD && k > head_index + 1 &&
                        d.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.operands[1].imm.value.u == 7;
                    step |= skip;
                    safe &= k == j + 2 || skip;
                }
            }
            if (safe && step)
                return true;
        }
        return false;
    };
    const auto ownership_update = [&](std::size_t index) {
        const auto& d = instructions[index];
        const auto& destination = d.operands[0];
        const auto caller = CallerSlot(code, index, resolve, &branches);
        if (!caller || d.instruction.mnemonic != ZYDIS_MNEMONIC_OR ||
            destination.type != ZYDIS_OPERAND_TYPE_MEMORY || destination.size != 64 ||
            destination.mem.index == ZYDIS_REGISTER_NONE || destination.mem.scale != 8 ||
            !d.instruction.cpu_flags)
            return false;
        bool header{}, size{}, bound{};
        for (std::size_t k = index; k > 0 && d.address - instructions[k - 1].address < 0x200; --k) {
            const auto& before = instructions[k - 1];
            const auto& x = before.operands[0];
            const auto& y = before.operands[1];
            header |= before.instruction.mnemonic == ZYDIS_MNEMONIC_MOVSXD &&
                y.type == ZYDIS_OPERAND_TYPE_MEMORY && y.mem.base == ZYDIS_REGISTER_RIP &&
                ((before.address + before.instruction.length + y.mem.disp.value) & 0xffff) == 0x3c;
            size |= before.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                y.type == ZYDIS_OPERAND_TYPE_MEMORY && y.size == 32 && y.mem.index != ZYDIS_REGISTER_NONE &&
                y.mem.disp.value == 0x50;
            if (before.instruction.mnemonic == ZYDIS_MNEMONIC_CMP && x.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                x.size == 64 && y.type == ZYDIS_OPERAND_TYPE_REGISTER)
                if (auto source = Trace(
                        code, k - 1, {x.reg.value}, Location{ZYDIS_REGISTER_NONE, *caller, true}, &branches);
                    source && !source->inputs)
                    bound = std::any_of(source->code.instructions.begin(), source->code.instructions.end(),
                        [&](const auto& read) {
                            return LocalSlot(read.operands[1]) && read.operands[1].size == 64 &&
                                read.instruction.address_width == 64 &&
                                read.operands[1].mem.segment == ZYDIS_REGISTER_SS &&
                                read.operands[1].mem.disp.value == *caller;
                        });
        }
        if (!header || !size || !bound)
            return false;
        auto remaining = d.instruction.cpu_flags->modified | d.instruction.cpu_flags->set_0 |
            d.instruction.cpu_flags->set_1 | d.instruction.cpu_flags->undefined;
        auto next = index + 1;
        for (unsigned checked = 0; checked < 64 && next < instructions.size(); ++checked) {
            const auto& after = instructions[next];
            const auto* flags = after.instruction.cpu_flags;
            if (flags && (flags->tested & remaining))
                return false;
            if (flags)
                remaining &= ~(flags->modified | flags->set_0 | flags->set_1 | flags->undefined);
            if (!remaining)
                return true;
            const auto category = after.instruction.meta.category;
            if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_RET ||
                category == ZYDIS_CATEGORY_COND_BR)
                return false;
            if (category == ZYDIS_CATEGORY_UNCOND_BR) {
                const auto& target = after.operands[0];
                if (target.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !target.imm.is_relative)
                    return false;
                const auto at = after.address + after.instruction.length + target.imm.value.s;
                const auto found = std::lower_bound(instructions.begin(), instructions.end(), at,
                    [](const auto& instruction, std::uint64_t address) {
                        return instruction.address < address;
                    });
                if (found == instructions.end() || found->address != at)
                    return false;
                next = static_cast<std::size_t>(found - instructions.begin());
            } else
                ++next;
        }
        return false;
    };
    const auto field = [](const Emulator::Decoded& d, unsigned operand) {
        return d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            d.operands[operand].type == ZYDIS_OPERAND_TYPE_MEMORY && d.operands[operand].size == 64 &&
            d.operands[operand].mem.base == ZYDIS_REGISTER_RSP &&
            d.operands[operand].mem.index == ZYDIS_REGISTER_NONE;
    };
    const auto byte_pointer_consumer = [&](std::size_t shift_index, std::int64_t slot) {
        if (unclosed_control_flow || !function_reachable[shift_index])
            return std::optional<std::size_t>{};
        const auto end_register = Dependency(instructions[shift_index].operands[0].reg.value);
        if (end_register & Dependency(ZYDIS_REGISTER_RSP))
            return std::optional<std::size_t>{};
        std::optional<std::size_t> pointer;
        ZydisRegister pointer_register = ZYDIS_REGISTER_NONE;
        std::size_t add = instructions.size();
        for (auto j = shift_index + 1;
            j < instructions.size() && instructions[j].address - instructions[shift_index].address < 0x80;
            ++j) {
            const auto& d = instructions[j];
            if (d.instruction.meta.category == ZYDIS_CATEGORY_CALL ||
                d.instruction.meta.category == ZYDIS_CATEGORY_RET ||
                d.instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR)
                break;
            if (field(d, 1) && d.operands[1].mem.disp.value == slot - 8 &&
                register_width(d.operands[0], 64) && d.instruction.address_width == 64 &&
                d.operands[1].mem.segment == ZYDIS_REGISTER_SS &&
                d.operands[0].reg.value != ZYDIS_REGISTER_RSP &&
                !(Dependency(d.operands[0].reg.value) & end_register)) {
                if (pointer)
                    return std::optional<std::size_t>{};
                pointer = j;
                pointer_register = d.operands[0].reg.value;
            }
            if (pointer && d.instruction.mnemonic == ZYDIS_MNEMONIC_ADD &&
                d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[0].size == 64 &&
                Dependency(d.operands[0].reg.value) == end_register && register_width(d.operands[0], 64) &&
                register_width(d.operands[1], 64) && d.operands[1].reg.value == pointer_register) {
                add = j;
                break;
            }
            if (d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                (d.operands[0].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                ((Dependency(d.operands[0].reg.value) & end_register) ||
                    (pointer && j != *pointer && d.operands[0].reg.value == pointer_register)))
                return std::optional<std::size_t>{};
        }
        if (!pointer || add == instructions.size())
            return std::optional<std::size_t>{};
        const auto closed_walk = [&](std::size_t tail) {
            const auto finish = tail + 4;
            const auto first_address = instructions[add + 1].address;
            const auto last_address = instructions[finish].address;
            for (std::size_t at = 0; at < instructions.size(); ++at) {
                const auto& d = instructions[at];
                const auto category = d.instruction.meta.category;
                if (category != ZYDIS_CATEGORY_UNCOND_BR && category != ZYDIS_CATEGORY_COND_BR)
                    continue;
                const auto& o = d.operands[0];
                if (o.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !o.imm.is_relative) {
                    if (at >= shift_index && at <= finish)
                        return false;
                    if (const auto found = branches.find(d.address); found != branches.end()) {
                        for (const auto target : found->second)
                            if (target > instructions[shift_index].address && target <= last_address)
                                return false;
                    } else if (function_reachable[at])
                        return false;
                    continue;
                }
                const auto target = d.address + d.instruction.length + o.imm.value.s;
                if ((target > instructions[shift_index].address && target <= instructions[add].address &&
                        (at < shift_index || at > add)) ||
                    (target >= first_address && target <= last_address && (at <= add || at > finish)))
                    return false;
            }
            const auto& skip = instructions[tail + 1];
            const auto target = skip.address + skip.instruction.length + skip.operands[0].imm.value.s;
            const auto exit = std::lower_bound(instructions.begin(), instructions.end(), target,
                [](const auto& d, std::uint64_t address) { return d.address < address; });
            if (exit == instructions.end() || exit->address != target ||
                (target >= instructions[shift_index].address && target <= last_address))
                return false;
            using Roles = std::array<unsigned char, 16>;
            std::vector<std::optional<Roles>> states(finish - add);
            Roles entry{};
            entry[std::countr_zero(Dependency(pointer_register))] = 1;
            entry[std::countr_zero(end_register)] = 2;
            states[0] = entry;
            std::vector<std::size_t> pending{add + 1};
            while (!pending.empty()) {
                const auto at = pending.back();
                pending.pop_back();
                const auto& d = instructions[at];
                const auto& i = d.instruction;
                const auto old = *states[at - add - 1];
                auto next = old;
                const auto role = [&](ZydisRegister reg) {
                    const auto bit = Dependency(reg);
                    return bit ? old[std::countr_zero(bit)] : 0;
                };
                if (i.meta.category == ZYDIS_CATEGORY_CALL || i.meta.category == ZYDIS_CATEGORY_RET)
                    return false;
                for (unsigned op = 0; op < i.operand_count; ++op) {
                    const auto& o = d.operands[op];
                    if (o.type != ZYDIS_OPERAND_TYPE_REGISTER ||
                        !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) || !Dependency(o.reg.value))
                        continue;
                    unsigned char value{};
                    if (op == 0 && o.size == 64 && i.mnemonic == ZYDIS_MNEMONIC_MOV &&
                        d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[1].size == 64)
                        value = static_cast<unsigned char>(role(d.operands[1].reg.value));
                    if (op == 0 && o.size == 64 && i.mnemonic == ZYDIS_MNEMONIC_ADD &&
                        role(o.reg.value) == 1 && d.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                        d.operands[1].imm.value.u && d.operands[1].imm.value.u <= 0x100 &&
                        !(d.operands[1].imm.value.u & 7))
                        value = 1;
                    if ((o.actions & ZYDIS_OPERAND_ACTION_CONDWRITE) && role(o.reg.value) != value)
                        value = 0;
                    next[std::countr_zero(Dependency(o.reg.value))] = value;
                }
                const auto push = [&](std::size_t to) {
                    if (to <= add || to > finish)
                        return;
                    auto& state = states[to - add - 1];
                    bool changed{};
                    if (!state) {
                        state = next;
                        changed = true;
                    } else
                        for (unsigned reg = 0; reg < 16; ++reg)
                            if ((*state)[reg] != next[reg] && (*state)[reg]) {
                                (*state)[reg] = 0;
                                changed = true;
                            }
                    if (changed)
                        pending.push_back(to);
                };
                if (i.meta.category != ZYDIS_CATEGORY_UNCOND_BR)
                    push(at + 1);
                if (i.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                    i.meta.category == ZYDIS_CATEGORY_COND_BR) {
                    const auto& o = d.operands[0];
                    if (o.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !o.imm.is_relative)
                        return false;
                    const auto branch = d.address + i.length + o.imm.value.s;
                    const auto found = std::lower_bound(instructions.begin(), instructions.end(), branch,
                        [](const auto& value, std::uint64_t address) { return value.address < address; });
                    if (found == instructions.end() || found->address != branch)
                        return false;
                    push(static_cast<std::size_t>(found - instructions.begin()));
                }
            }
            const auto& load_state = states[tail - add - 1];
            const auto& end_state = states[tail + 3 - add - 1];
            return load_state && end_state &&
                (*load_state)[std::countr_zero(Dependency(instructions[tail].operands[0].mem.base))] == 1 &&
                (*end_state)[std::countr_zero(end_register)] == 2;
        };
        auto aliases = Dependency(pointer_register);
        for (auto j = add + 1;
            j + 4 < instructions.size() && instructions[j].address - instructions[add].address < 0x180; ++j) {
            const auto& d = instructions[j];
            const auto category = d.instruction.meta.category;
            if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_RET)
                break;
            if (d.instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
                d.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && d.operands[0].size == 64 &&
                d.instruction.address_width == 64 && d.operands[0].mem.segment == ZYDIS_REGISTER_DS &&
                register_width(d.operands[1], 64) && d.operands[0].mem.index == ZYDIS_REGISTER_NONE &&
                d.operands[0].mem.disp.value == 0 && (Dependency(d.operands[0].mem.base) & aliases)) {
                const auto& skip = instructions[j + 1];
                const auto& advance = instructions[j + 2];
                const auto& compare = instructions[j + 3];
                const auto& repeat = instructions[j + 4];
                if (skip.instruction.mnemonic == ZYDIS_MNEMONIC_JZ &&
                    skip.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    skip.operands[0].imm.is_relative && advance.instruction.mnemonic == ZYDIS_MNEMONIC_ADD &&
                    register_width(advance.operands[0], 64) &&
                    advance.operands[0].reg.value == d.operands[0].mem.base &&
                    advance.operands[0].size == 64 &&
                    advance.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    advance.operands[1].imm.value.u == 8 &&
                    compare.instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
                    register_width(compare.operands[0], 64) && register_width(compare.operands[1], 64) &&
                    compare.operands[0].reg.value == advance.operands[0].reg.value &&
                    compare.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    compare.operands[1].size == 64 &&
                    Dependency(compare.operands[1].reg.value) == end_register &&
                    repeat.instruction.mnemonic == ZYDIS_MNEMONIC_JB &&
                    repeat.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    repeat.operands[0].imm.is_relative &&
                    repeat.address + repeat.instruction.length + repeat.operands[0].imm.value.s ==
                        d.address &&
                    closed_walk(j))
                    return pointer;
            }
            if (d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                (d.operands[0].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) {
                const auto target = Dependency(d.operands[0].reg.value);
                if (target & end_register)
                    return std::optional<std::size_t>{};
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && d.operands[0].size == 64 &&
                    d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (Dependency(d.operands[1].reg.value) & aliases))
                    aliases |= target;
                else if (d.instruction.mnemonic == ZYDIS_MNEMONIC_ADD && d.operands[0].size == 64 &&
                    (target & aliases) && d.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    d.operands[1].imm.value.u && d.operands[1].imm.value.u <= 0x100 &&
                    !(d.operands[1].imm.value.u & 7)) {
                } else if (!(d.operands[0].actions & ZYDIS_OPERAND_ACTION_CONDWRITE))
                    aliases &= ~target;
            }
        }
        return std::optional<std::size_t>{};
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
        bool consumed = false, modified = false;
        for (std::size_t j = count + 1; j < instructions.size() && j - count < 256; ++j) {
            const auto& load = instructions[j];
            for (unsigned k = 0; k < load.instruction.operand_count; ++k) {
                const auto& write = load.operands[k];
                modified |= write.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    (write.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                    write.mem.base == ZYDIS_REGISTER_RSP &&
                    ((write.mem.index == ZYDIS_REGISTER_NONE && write.mem.disp.value >= slot - 8 &&
                         write.mem.disp.value < slot + 8) ||
                        (write.mem.index != ZYDIS_REGISTER_NONE && write.mem.disp.value == slot - 8));
            }
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
        if (!consumed || modified)
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
        const bool packed = shift.instruction.mnemonic == ZYDIS_MNEMONIC_SHL &&
            shift.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && shift.operands[1].imm.value.u == 34;
        const bool masked = shift.instruction.mnemonic == ZYDIS_MNEMONIC_AND &&
            shift.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            shift.operands[1].imm.value.u == 0x3fffffff;
        const bool compact = shift.instruction.mnemonic == ZYDIS_MNEMONIC_SHL &&
            register_width(shift.operands[0], 32) && shift.instruction.address_width == 64 &&
            shift.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && shift.operands[1].imm.value.u == 3;
        if ((!packed && !masked && !compact) || shift.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            !Dependency(shift.operands[0].reg.value))
            continue;
        auto load_index = consumer;
        auto count_register = Dependency(shift.operands[0].reg.value);
        for (std::size_t j = consumer; j > 0 && consumer - j < (masked ? 8u : 1u); --j) {
            const auto& d = instructions[j - 1];
            const auto category = d.instruction.meta.category;
            if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_RET ||
                category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR)
                break;
            const auto& destination = d.operands[0];
            if (destination.type != ZYDIS_OPERAND_TYPE_REGISTER ||
                !(destination.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) ||
                Dependency(destination.reg.value) != count_register)
                continue;
            if ((!compact && field(d, 1)) ||
                (compact && d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    d.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && d.operands[1].size == 32 &&
                    register_width(d.operands[0], 32) && d.instruction.address_width == 64 &&
                    d.operands[1].mem.segment == ZYDIS_REGISTER_SS &&
                    d.operands[1].mem.base == ZYDIS_REGISTER_RSP &&
                    d.operands[1].mem.index == ZYDIS_REGISTER_NONE)) {
                load_index = j - 1;
                break;
            }
            if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || destination.size < 32 ||
                d.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER || !Dependency(d.operands[1].reg.value))
                break;
            count_register = Dependency(d.operands[1].reg.value);
        }
        if (load_index == consumer)
            continue;
        const auto& load = instructions[load_index];
        const auto slot = load.operands[1].mem.disp.value;
        if (slot < 8 || slot > 0x7000)
            continue;
        const auto compact_pointer = compact ? byte_pointer_consumer(consumer, slot) : std::nullopt;
        if (compact && !compact_pointer)
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
        bool scalar = count != consumer && pointer != consumer &&
            (count > pointer ? count - pointer : pointer - count) <= 16;
        std::optional<std::size_t> indexed;
        for (std::size_t j = consumer; j > 0 && shift.address - instructions[j - 1].address < 0x1000; --j) {
            const auto& d = instructions[j - 1];
            const auto& destination = d.operands[0];
            if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                destination.type == ZYDIS_OPERAND_TYPE_MEMORY && destination.mem.base == ZYDIS_REGISTER_RSP &&
                destination.mem.index != ZYDIS_REGISTER_NONE && destination.mem.disp.value == slot - 8 &&
                destination.size == 64 && (!scalar || j - 1 > std::max(pointer, count)))
                indexed = j - 1;
        }
        if (indexed)
            scalar = false;
        if (!scalar && !indexed)
            continue;
        const bool postprocessed = indexed ||
            std::any_of(instructions.begin() + std::max(pointer, count) + 1, instructions.begin() + consumer,
                [&](const auto& d) {
                    const auto& o = d.operands[0];
                    return o.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) && o.mem.base == ZYDIS_REGISTER_RSP &&
                        ((o.mem.index != ZYDIS_REGISTER_NONE && o.mem.disp.value == slot - 8) ||
                            (o.mem.index == ZYDIS_REGISTER_NONE && o.mem.disp.value >= slot - 8 &&
                                o.mem.disp.value < slot + 8));
                });
        const auto end = postprocessed ? consumer : std::max(count, pointer) + 1;
        const auto first = indexed ? *indexed : std::min(count, pointer);
        std::size_t begin = end;
        ZydisRegister input = ZYDIS_REGISTER_NONE;
        for (std::size_t j = first;
            scalar && !indexed && j > 0 && instructions[first].address - instructions[j - 1].address < 0x800;
            --j) {
            const auto& a = instructions[j - 1];
            const auto& b = instructions[j];
            if ((a.instruction.mnemonic != ZYDIS_MNEMONIC_MOV &&
                    a.instruction.mnemonic != ZYDIS_MNEMONIC_ADD) ||
                (b.instruction.mnemonic != ZYDIS_MNEMONIC_MOV &&
                    b.instruction.mnemonic != ZYDIS_MNEMONIC_ADD) ||
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
        if (scalar && !indexed && begin == end) {
            auto prefix = first;
            while (prefix > 0 && instructions[first].address - instructions[prefix - 1].address < 0x1000) {
                const auto category = instructions[prefix - 1].instruction.meta.category;
                if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_COND_BR ||
                    category == ZYDIS_CATEGORY_UNCOND_BR || category == ZYDIS_CATEGORY_RET)
                    break;
                --prefix;
            }
            const auto last = std::max(pointer, count) + 1;
            const auto region = Simplify({instructions[prefix].address,
                instructions[last - 1].address + instructions[last - 1].instruction.length,
                {instructions.begin() + prefix, instructions.begin() + last}});
            const auto array = Slice(region, pointer - prefix, instructions[pointer].operands[1].reg.value);
            const auto size = Slice(region, count - prefix, instructions[count].operands[1].reg.value);
            if (array && size && array->inputs == size->inputs && array->inputs && array->inputs < 0x10000) {
                std::array<std::map<ZydisRegister, std::set<std::int64_t>>, 2> fields;
                for (unsigned output = 0; output < 2; ++output)
                    for (const auto& d : (output ? size : array)->code.instructions)
                        for (unsigned operand = 0; operand < d.instruction.operand_count_visible; ++operand) {
                            const auto& member = d.operands[operand];
                            if (member.type == ZYDIS_OPERAND_TYPE_MEMORY && member.size == 64 &&
                                (member.actions & ZYDIS_OPERAND_ACTION_MASK_READ) &&
                                (Dependency(member.mem.base) & array->inputs) &&
                                member.mem.index == ZYDIS_REGISTER_NONE && member.mem.disp.value > 0 &&
                                member.mem.disp.value < 0x10000)
                                fields[output][member.mem.base].insert(member.mem.disp.value);
                        }
                bool conflict{};
                for (const auto& [owner, members] : fields[0]) {
                    const auto found = fields[1].find(owner);
                    if (members.size() != 1 || found == fields[1].end() || found->second.size() != 1 ||
                        *found->second.begin() != *members.begin() + 8)
                        continue;
                    conflict |= input != ZYDIS_REGISTER_NONE;
                    input = owner;
                }
                if (!conflict && input != ZYDIS_REGISTER_NONE)
                    begin = prefix;
                else
                    input = ZYDIS_REGISTER_NONE;
            }
        }
        if (begin == end) {
            for (std::size_t j = first + 1;
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
                        indexed = j - 1;
                        while (begin > 0 && store.address - instructions[begin - 1].address < 0x200) {
                            const auto& prefix = instructions[begin - 1];
                            const auto category = prefix.instruction.meta.category;
                            if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_COND_BR ||
                                category == ZYDIS_CATEGORY_UNCOND_BR || category == ZYDIS_CATEGORY_RET ||
                                (prefix.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                    (prefix.operands[0].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                                    Dependency(prefix.operands[0].reg.value) == Dependency(input)))
                                break;
                            --begin;
                        }
                        break;
                    }
                }
                if (begin != end)
                    break;
            }
        }
        if (begin == end || input == ZYDIS_REGISTER_NONE)
            continue;
        std::vector<std::vector<std::size_t>> context_successors;
        std::vector<std::size_t> context_reentries;
        if (compact) {
            std::vector<std::vector<std::size_t>> predecessors(instructions.size());
            context_successors.resize(instructions.size());
            for (std::size_t at = 0; at < instructions.size(); ++at) {
                const auto& d = instructions[at];
                const auto category = d.instruction.meta.category;
                if (category != ZYDIS_CATEGORY_RET && category != ZYDIS_CATEGORY_UNCOND_BR &&
                    at + 1 < instructions.size())
                    predecessors[at + 1].push_back(at);
                const auto push = [&](std::uint64_t target) {
                    const auto found = std::lower_bound(instructions.begin(), instructions.end(), target,
                        [](const auto& value, std::uint64_t address) { return value.address < address; });
                    if (found != instructions.end() && found->address == target)
                        predecessors[found - instructions.begin()].push_back(at);
                };
                if (category == ZYDIS_CATEGORY_UNCOND_BR || category == ZYDIS_CATEGORY_COND_BR) {
                    const auto& o = d.operands[0];
                    if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative)
                        push(d.address + d.instruction.length + o.imm.value.s);
                    else if (const auto found = branches.find(d.address); found != branches.end())
                        for (const auto target : found->second)
                            push(target);
                }
            }
            for (std::size_t at = 0; at < predecessors.size(); ++at)
                for (const auto source : predecessors[at])
                    context_successors[source].push_back(at);
            std::vector<bool> ancestor(instructions.size());
            std::vector<std::size_t> pending{begin};
            while (!pending.empty()) {
                const auto at = pending.back();
                pending.pop_back();
                if (ancestor[at])
                    continue;
                ancestor[at] = true;
                for (const auto source : predecessors[at]) {
                    if (at <= begin && source >= begin && function_reachable[source])
                        context_reentries.push_back(at);
                    pending.push_back(source);
                }
            }
        }
        if (postprocessed &&
            std::any_of(instructions.begin() + begin, instructions.begin() + end, [&](const auto& d) {
                const auto& destination = d.operands[0];
                return destination.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    (destination.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                    destination.mem.base == ZYDIS_REGISTER_RSP &&
                    destination.mem.index != ZYDIS_REGISTER_NONE && destination.mem.disp.value == slot - 8 &&
                    !indexed_pair(static_cast<std::size_t>(&d - instructions.data()), slot - 8);
            }))
            continue;
        std::vector<bool> seen(end - begin + 1);
        std::vector<std::size_t> pending{begin};
        bool safe = true, tls = false;
        std::set<std::size_t> updates;
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
                    o.mem.base != ZYDIS_REGISTER_RSP) {
                    if (ownership_update(index))
                        updates.insert(index);
                    else
                        safe = false;
                }
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
        if (!safe || (!tls && !postprocessed) || (scalar && (!seen[count - begin] || !seen[pointer - begin])))
            continue;
        ArrayDescriptor value{
            {instructions[begin].address,
                instructions[end - 1].address + instructions[end - 1].instruction.length, {}},
            input, scalar ? instructions[pointer].operands[1].reg.value : ZYDIS_REGISTER_RDX,
            scalar ? instructions[count].operands[1].reg.value : ZYDIS_REGISTER_RAX};
        value.code.instructions.assign(instructions.begin() + begin, instructions.begin() + end);
        if (compact) {
            bool members_valid = true;
            for (const auto& d : value.code.instructions)
                for (unsigned operand = 0; operand < d.instruction.operand_count; ++operand) {
                    const auto& member = d.operands[operand];
                    if (member.type == ZYDIS_OPERAND_TYPE_MEMORY && member.mem.base == input &&
                        (member.actions & ZYDIS_OPERAND_ACTION_MASK_READ))
                        members_valid &= d.instruction.address_width == 64 && member.size == 64 &&
                            (member.mem.segment == ZYDIS_REGISTER_DS ||
                                member.mem.segment == ZYDIS_REGISTER_SS) &&
                            member.mem.index == ZYDIS_REGISTER_NONE;
                }
            if (!members_valid)
                continue;
            value.count_mask = 0x1fffffffull;
        }
        if (!postprocessed &&
            !PruneArray(value.code, input, value.array, value.count, slot - 8, std::nullopt, false)) {
            if (closed_owners)
                for (const auto& d : value.code.instructions) {
                    const auto& member = d.operands[1];
                    if (member.type != ZYDIS_OPERAND_TYPE_MEMORY || member.size != 64 ||
                        member.mem.base != input || member.mem.index != ZYDIS_REGISTER_NONE ||
                        member.mem.disp.value <= 0 || !(member.actions & ZYDIS_OPERAND_ACTION_MASK_READ))
                        continue;
                    const auto found = std::lower_bound(instructions.begin(), instructions.end(), d.address,
                        [](const auto& instruction, std::uint64_t at) { return instruction.address < at; });
                    if (found != instructions.end() && found->address == d.address)
                        if (auto owner = Slice(code, found - instructions.begin(), input);
                            owner && !owner->inputs)
                            closed_owners->push_back(std::move(*owner));
                    break;
                }
            continue;
        }
        if (postprocessed) {
            for (const auto index : updates) {
                auto& d = value.code.instructions[index - begin];
                d.instruction.mnemonic = ZYDIS_MNEMONIC_NOP;
                d.instruction.operand_count = d.instruction.operand_count_visible = 0;
                d.instruction.cpu_flags = nullptr;
                d.operands = {};
            }
            auto pointer_load = compact ? instructions[*compact_pointer] : load;
            pointer_load.address = value.code.instructions.back().address;
            pointer_load.instruction.length = value.code.instructions.back().instruction.length;
            pointer_load.operands[0].reg.value = ZYDIS_REGISTER_RDX;
            pointer_load.operands[1].mem.disp.value = slot - 8;
            value.code.instructions.back() = pointer_load;
            auto count_load = load;
            count_load.address = shift.address;
            count_load.instruction.length = shift.instruction.length;
            count_load.operands[0].reg.value = compact ? ZYDIS_REGISTER_EAX : ZYDIS_REGISTER_RAX;
            value.code.instructions.push_back(count_load);
            value.array = ZYDIS_REGISTER_RDX;
            value.count = compact ? ZYDIS_REGISTER_EAX : ZYDIS_REGISTER_RAX;
            value.code.end = shift.address + shift.instruction.length;
            value.code = Simplify(value.code);
            if (const auto caller = CallerSlot(code, begin, resolve, &branches)) {
                value.caller_slot = static_cast<std::uint32_t>(*caller);
                value.caller = code.begin;
            }
            if (compact) {
                bool protected_caller = value.caller_slot.has_value();
                for (std::size_t at = 0; at < begin && protected_caller; ++at) {
                    if (!function_reachable[at])
                        continue;
                    const auto& d = instructions[at];
                    for (unsigned operand = 0; operand < d.instruction.operand_count_visible; ++operand) {
                        const auto& o = d.operands[operand];
                        if (o.type != ZYDIS_OPERAND_TYPE_MEMORY ||
                            !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) ||
                            !(Dependency(o.mem.base) & Dependency(ZYDIS_REGISTER_RSP)))
                            continue;
                        const auto depth = CallerSlot(code, at, resolve, &branches, true);
                        const auto pair = o.mem.disp.value;
                        if (!depth || d.instruction.address_width != 64 || o.mem.base != ZYDIS_REGISTER_RSP ||
                            (o.mem.segment != ZYDIS_REGISTER_SS && o.mem.segment != ZYDIS_REGISTER_DS) ||
                            !o.size || (o.size & 7)) {
                            protected_caller = false;
                            break;
                        }
                        if (o.mem.index != ZYDIS_REGISTER_NONE) {
                            if (!indexed_pair(at, pair, true) || (pair < *depth + 8 && pair + 16 > *depth)) {
                                protected_caller = false;
                                break;
                            }
                        } else if (pair < *depth + 8 && pair + o.size / 8 > *depth) {
                            protected_caller = false;
                            break;
                        }
                    }
                }
                if (!protected_caller)
                    continue;
            }
            std::uint32_t external{};
            std::set<std::int64_t> external_slots;
            auto pruned = PruneArray(value.code, input, value.array, value.count, slot - 8, value.caller_slot,
                indexed.has_value(), &external, &external_slots);
            if (!pruned && compact && value.caller_slot &&
                std::popcount(external) + external_slots.size() <= 8) {
                std::vector<Emulator::Decoded> definitions;
                const auto add_seed = [&](Location location) {
                    const auto expression = Trace(code, begin, location,
                        Location{ZYDIS_REGISTER_NONE, *value.caller_slot, true}, &branches);
                    if (!expression || expression->inputs)
                        return false;
                    for (const auto& d : expression->code.instructions) {
                        bool frame{};
                        for (unsigned operand = 0; operand < d.instruction.operand_count; ++operand) {
                            const auto& o = d.operands[operand];
                            frame |=
                                (o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.base == ZYDIS_REGISTER_RSP) ||
                                (o.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                    (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) &&
                                    (Dependency(o.reg.value) & Dependency(ZYDIS_REGISTER_RSP)));
                        }
                        if (frame) {
                            const auto at = std::lower_bound(instructions.begin(), instructions.end(),
                                d.address, [](const auto& value, std::uint64_t address) {
                                    return value.address < address;
                                });
                            if (at == instructions.end() || at->address != d.address ||
                                CallerSlot(code, static_cast<std::size_t>(at - instructions.begin()), resolve,
                                    &branches) != value.caller_slot)
                                return false;
                        }
                    }
                    definitions.insert(definitions.end(), expression->code.instructions.begin(),
                        expression->code.instructions.end());
                    return true;
                };
                bool complete = true;
                for (unsigned reg = 0; reg < 16 && complete; ++reg)
                    if (external & (1u << reg))
                        complete =
                            add_seed({ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, static_cast<ZyanU8>(reg))});
                for (const auto member : external_slots)
                    complete &= add_seed({ZYDIS_REGISTER_NONE, member, true});
                if (complete && !definitions.empty()) {
                    definitions.insert(
                        definitions.end(), value.code.instructions.begin(), value.code.instructions.end());
                    std::sort(definitions.begin(), definitions.end(),
                        [](const auto& a, const auto& b) { return a.address < b.address; });
                    definitions.erase(
                        std::unique(definitions.begin(), definitions.end(),
                            [](const auto& a, const auto& b) { return a.address == b.address; }),
                        definitions.end());
                    auto bound = value.code;
                    bound.instructions = std::move(definitions);
                    bound.begin = bound.instructions.front().address;
                    bound.sparse = true;
                    if (auto closed = PruneArray(bound, input, value.array, value.count, slot - 8,
                            value.caller_slot, indexed.has_value()))
                        pruned = std::move(closed);
                }
            }
            if (!pruned && external && !(external & (external - 1)) && external < 0x10000 &&
                value.caller_slot) {
                const auto reg = ZydisRegisterEncode(
                    ZYDIS_REGCLASS_GPR64, static_cast<ZyanU8>(std::countr_zero(external)));
                if (const auto alias = Alias(code, begin, reg); alias && !alias->inputs &&
                    alias->code.instructions.size() == 1 && alias->code.begin < value.code.begin) {
                    const auto& seed = alias->code.instructions.front();
                    const auto& source = seed.operands[1];
                    const auto at = std::lower_bound(instructions.begin(), instructions.end(), seed.address,
                        [](const auto& d, std::uint64_t address) { return d.address < address; });
                    if (seed.instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
                        source.type == ZYDIS_OPERAND_TYPE_MEMORY && source.mem.base == ZYDIS_REGISTER_RSP &&
                        source.mem.index == ZYDIS_REGISTER_NONE && source.mem.disp.value >= 0 &&
                        source.mem.disp.value <= 0x7ff8 && at != instructions.end() &&
                        at->address == seed.address &&
                        CallerSlot(code, static_cast<std::size_t>(at - instructions.begin()), resolve) ==
                            value.caller_slot) {
                        value.code.instructions.insert(value.code.instructions.begin(), seed);
                        value.code.begin = seed.address;
                        value.code.sparse = true;
                        pruned = PruneArray(value.code, input, value.array, value.count, slot - 8,
                            value.caller_slot, indexed.has_value());
                    }
                }
            }
            if (!pruned)
                continue;
            if (compact) {
                bool definitions_dominate = true;
                for (const auto& seed : pruned->instructions) {
                    if (seed.address >= instructions[begin].address)
                        continue;
                    const auto definition =
                        std::lower_bound(instructions.begin(), instructions.end(), seed.address,
                            [](const auto& value, std::uint64_t address) { return value.address < address; });
                    if (definition == instructions.end() || definition->address != seed.address) {
                        definitions_dominate = false;
                        break;
                    }
                    const auto excluded = static_cast<std::size_t>(definition - instructions.begin());
                    for (const auto entry : context_reentries) {
                        std::vector<bool> visited(instructions.size());
                        std::vector<std::size_t> work{entry};
                        while (!work.empty() && definitions_dominate) {
                            const auto at = work.back();
                            work.pop_back();
                            if (at == excluded || visited[at] || !function_reachable[at])
                                continue;
                            if (at == begin) {
                                definitions_dominate = false;
                                break;
                            }
                            visited[at] = true;
                            work.insert(
                                work.end(), context_successors[at].begin(), context_successors[at].end());
                        }
                    }
                    if (!definitions_dominate)
                        break;
                }
                if (!definitions_dominate)
                    continue;
            }
            value.code = std::move(*pruned);
            const auto start = std::find_if(value.code.instructions.begin(), value.code.instructions.end(),
                [](const auto& d) { return d.instruction.mnemonic != ZYDIS_MNEMONIC_NOP; });
            if (start == value.code.instructions.end())
                continue;
            value.code.begin = start->address;
            value.code.instructions.erase(value.code.instructions.begin(), start);
        }
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

std::optional<OperatorNameDescriptor> BoundedNullableResource(const Emulator::Program& code);
bool OperatorNull(const Emulator::Program& code, std::size_t branch, ZydisRegister holder);
bool ResourceReturns(const Emulator::Program& code, std::size_t start, ZydisRegister holder,
    const std::array<std::uint64_t, 4>& bounds);

std::optional<OperatorNameDescriptor> LegacyNullableResource(const Emulator::Program& code, bool two_casts) {
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

std::optional<OperatorNameDescriptor> NullableResource(const Emulator::Program& code, bool two_casts) {
    if (auto value = LegacyNullableResource(code, two_casts)) {
        if (!two_casts)
            return value;
        std::vector<std::uint64_t> found;
        bool widths = true;
        for (const auto& d : code.instructions) {
            for (const auto& operand : d.operands)
                if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.type == ZYDIS_MEMOP_TYPE_MEM)
                    widths &= d.instruction.address_width == 64;
            if (d.instruction.mnemonic == ZYDIS_MNEMONIC_CMP && d.operands[0].size == 16 && RipTarget(d, 1))
                found.push_back(RipTarget(d, 1));
        }
        if (widths && found.size() == 4)
            for (std::size_t at = 0; at < code.instructions.size(); ++at)
                if (code.instructions[at].address == value->reference.code.end &&
                    OperatorNull(code, at, value->reference.output.reg) &&
                    ResourceReturns(
                        code, at, value->reference.output.reg, {found[0], found[1], found[2], found[3]}))
                    return value;
    }
    return two_casts ? BoundedNullableResource(code) : std::nullopt;
}
}

std::optional<OperatorNameDescriptor> OperatorName(const Emulator::Program& getter) {
    return NullableResource(getter, true);
}

static std::optional<OperatorSelectionDescriptor> LegacyOperatorSelection(const Emulator::Program& code,
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

namespace {
std::optional<std::size_t> OperatorWrite(
    const Emulator::Program& code, std::size_t before, ZydisRegister reg) {
    const auto dependency = Dependency(reg);
    if (!dependency)
        return std::nullopt;
    for (std::size_t at = before; at > 0; --at)
        for (const auto& operand : code.instructions[at - 1].operands)
            if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                (operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                Dependency(operand.reg.value) == dependency)
                return at - 1;
    return std::nullopt;
}

std::optional<std::pair<std::uint32_t, std::size_t>> OperatorValue(
    const Emulator::Program& code, std::size_t before, ZydisRegister reg, bool zero, unsigned budget = 32) {
    if (!budget || !Dependency(reg) || ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, reg) != 64)
        return std::nullopt;
    const auto writer = OperatorWrite(code, before, reg);
    if (!writer)
        return std::pair{Dependency(reg), code.instructions.size()};
    const auto& at = code.instructions[*writer];
    const auto& output = at.operands[0];
    if (output.type != ZYDIS_OPERAND_TYPE_REGISTER || output.size != 64 || output.reg.value != reg)
        return std::nullopt;
    if (at.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && at.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        at.operands[1].size == 64)
        return OperatorValue(code, *writer, at.operands[1].reg.value, zero, budget - 1);
    if (zero &&
        (at.instruction.mnemonic == ZYDIS_MNEMONIC_ROL || at.instruction.mnemonic == ZYDIS_MNEMONIC_ROR ||
            at.instruction.mnemonic == ZYDIS_MNEMONIC_NEG))
        return OperatorValue(code, *writer, reg, true, budget - 1);
    return std::pair{Dependency(reg), *writer};
}

bool OperatorNull(const Emulator::Program& code, std::size_t branch, ZydisRegister holder) {
    const auto& ins = code.instructions;
    std::optional<std::size_t> producer;
    for (std::size_t at = branch; at > 0 && branch - at < 16; --at) {
        const auto& instruction = ins[at - 1].instruction;
        if (instruction.meta.category == ZYDIS_CATEGORY_CALL ||
            instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
            instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR)
            return false;
        if (instruction.cpu_flags &&
            ((instruction.cpu_flags->modified | instruction.cpu_flags->set_0 | instruction.cpu_flags->set_1 |
                 instruction.cpu_flags->undefined) &
                ZYDIS_CPUFLAG_ZF)) {
            if (!(instruction.cpu_flags->modified & ZYDIS_CPUFLAG_ZF))
                return false;
            producer = at - 1;
            break;
        }
    }
    if (!producer)
        return false;
    const auto& at = ins[*producer];
    const auto& a = at.operands[0];
    const auto& b = at.operands[1];
    const auto output = OperatorValue(code, branch, holder, true);
    if (!output)
        return false;
    if (at.instruction.mnemonic == ZYDIS_MNEMONIC_TEST && a.type == ZYDIS_OPERAND_TYPE_REGISTER &&
        b.type == ZYDIS_OPERAND_TYPE_REGISTER && a.size == 64 && b.size == 64 && a.reg.value == b.reg.value)
        return output == OperatorValue(code, *producer, a.reg.value, true);
    if ((at.instruction.mnemonic == ZYDIS_MNEMONIC_ADD || at.instruction.mnemonic == ZYDIS_MNEMONIC_SUB ||
            at.instruction.mnemonic == ZYDIS_MNEMONIC_XOR) &&
        a.type == ZYDIS_OPERAND_TYPE_REGISTER && a.size == 64)
        return output == OperatorValue(code, *producer + 1, a.reg.value, true);
    if (at.instruction.mnemonic != ZYDIS_MNEMONIC_CMP || a.type != ZYDIS_OPERAND_TYPE_REGISTER ||
        a.size != 64)
        return false;
    if (b.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !b.imm.is_relative && b.imm.value.u == 0)
        return output == OperatorValue(code, *producer, a.reg.value, true);
    if (b.type != ZYDIS_OPERAND_TYPE_REGISTER || b.size != 64 || output->second >= ins.size())
        return false;
    const auto& difference = ins[output->second];
    if (difference.instruction.mnemonic != ZYDIS_MNEMONIC_SUB ||
        difference.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || difference.operands[0].size != 64 ||
        difference.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER || difference.operands[1].size != 64)
        return false;
    const auto left = OperatorValue(code, output->second, difference.operands[0].reg.value, false);
    const auto right = OperatorValue(code, output->second, difference.operands[1].reg.value, false);
    const auto compared_left = OperatorValue(code, *producer, a.reg.value, false);
    const auto compared_right = OperatorValue(code, *producer, b.reg.value, false);
    return left && right && compared_left && compared_right &&
        ((left == compared_left && right == compared_right) ||
            (left == compared_right && right == compared_left));
}

bool ResourceReturns(const Emulator::Program& code, std::size_t start, ZydisRegister holder,
    const std::array<std::uint64_t, 4>& bounds) {
    enum class Value : unsigned char { unknown, wrapper, payload, table, metadata, lower, upper, zero };

    struct State {
        std::size_t at;
        std::array<Value, 16> values{};
        std::array<std::uint64_t, 16> origins{};
        std::array<std::int64_t, 16> links{};
        unsigned gates{};
        std::optional<unsigned> flags;
        std::uint64_t flag_origin{};
        std::int64_t flag_link{};
        std::array<std::uint64_t, 4> gate_origins{};
        std::array<std::int64_t, 4> gate_links{};

        bool operator<(const State& other) const {
            return std::tie(at, values, origins, links, gates, flags, flag_origin, flag_link, gate_origins,
                       gate_links) < std::tie(other.at, other.values, other.origins, other.links, other.gates,
                                         other.flags, other.flag_origin, other.flag_link, other.gate_origins,
                                         other.gate_links);
        }
    };

    const auto index = [](ZydisRegister reg) -> unsigned {
        const auto largest = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
        return largest >= ZYDIS_REGISTER_RAX && largest <= ZYDIS_REGISTER_R15
            ? unsigned(largest - ZYDIS_REGISTER_RAX)
            : 16;
    };
    const auto& ins = code.instructions;
    const auto target = [&](std::uint64_t address) -> std::optional<std::size_t> {
        const auto found = std::lower_bound(ins.begin(), ins.end(), address,
            [](const auto& value, auto needle) { return value.address < needle; });
        return found != ins.end() && found->address == address
            ? std::optional<std::size_t>(found - ins.begin())
            : std::nullopt;
    };
    if (start >= ins.size() || index(holder) >= 16)
        return false;
    State entry{start};
    entry.values[index(holder)] = Value::wrapper;
    std::vector<State> pending{entry};
    std::set<State> visited;
    bool returned{};
    while (!pending.empty() && visited.size() < 4096) {
        auto state = pending.back();
        pending.pop_back();
        if (state.at >= ins.size())
            return false;
        if (!visited.insert(state).second)
            continue;
        const auto& d = ins[state.at];
        const auto before = state.values;
        const auto before_origins = state.origins;
        const auto before_links = state.links;
        for (const auto& operand : d.operands)
            if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                (operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) && index(operand.reg.value) < 16) {
                state.values[index(operand.reg.value)] = Value::unknown;
                state.origins[index(operand.reg.value)] = 0;
                state.links[index(operand.reg.value)] = 0;
            }
        if (d.instruction.cpu_flags &&
            (d.instruction.cpu_flags->modified | d.instruction.cpu_flags->set_0 |
                d.instruction.cpu_flags->set_1 | d.instruction.cpu_flags->undefined))
            state.flags.reset();
        const auto& a = d.operands[0];
        const auto& b = d.operands[1];
        if (a.type == ZYDIS_OPERAND_TYPE_REGISTER && index(a.reg.value) < 16) {
            auto& value = state.values[index(a.reg.value)];
            if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && a.size == 64 &&
                b.type == ZYDIS_OPERAND_TYPE_REGISTER && b.size == 64 && index(b.reg.value) < 16) {
                value = before[index(b.reg.value)];
                state.origins[index(a.reg.value)] = before_origins[index(b.reg.value)];
                state.links[index(a.reg.value)] = before_links[index(b.reg.value)];
            } else if ((d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV ||
                           d.instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX) &&
                d.instruction.address_width == 64 && b.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                b.mem.index == ZYDIS_REGISTER_NONE && b.mem.segment != ZYDIS_REGISTER_FS &&
                b.mem.segment != ZYDIS_REGISTER_GS && index(b.mem.base) < 16) {
                const auto base = before[index(b.mem.base)];
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && a.size == 64 && b.size == 64) {
                    if (base == Value::wrapper && b.mem.disp.value == 0) {
                        value = Value::payload;
                        state.origins[index(a.reg.value)] = d.address;
                        if (a.reg.value == ZYDIS_REGISTER_RAX)
                            state.gates = 0;
                    } else if (base == Value::payload && b.mem.disp.value == 0) {
                        value = Value::table;
                        state.origins[index(a.reg.value)] = before_origins[index(b.mem.base)];
                    } else if (base == Value::table && b.mem.disp.value >= 0 && b.mem.disp.value < 0x1000 &&
                        !(b.mem.disp.value & 7)) {
                        value = Value::metadata;
                        state.origins[index(a.reg.value)] = before_origins[index(b.mem.base)];
                        state.links[index(a.reg.value)] = b.mem.disp.value;
                    }
                } else if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX && a.size == 32 && b.size == 16 &&
                    base == Value::metadata) {
                    value = b.mem.disp.value == 0x40 ? Value::lower
                        : b.mem.disp.value == 0x42   ? Value::upper
                                                     : Value::unknown;
                    state.origins[index(a.reg.value)] = before_origins[index(b.mem.base)];
                    state.links[index(a.reg.value)] = before_links[index(b.mem.base)];
                }
            } else if ((d.instruction.mnemonic == ZYDIS_MNEMONIC_XOR ||
                           d.instruction.mnemonic == ZYDIS_MNEMONIC_SUB) &&
                a.size >= 32 && b.type == ZYDIS_OPERAND_TYPE_REGISTER && b.reg.value == a.reg.value)
                value = Value::zero;
            else if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && a.size >= 32 &&
                b.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !b.imm.value.u)
                value = Value::zero;
        }
        if (d.instruction.address_width == 64 && d.instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
            a.type == ZYDIS_OPERAND_TYPE_REGISTER && a.size == 16 && index(a.reg.value) < 16 &&
            b.size == 16 && b.mem.segment != ZYDIS_REGISTER_FS && b.mem.segment != ZYDIS_REGISTER_GS &&
            RipTarget(d, 1))
            for (unsigned gate = 0; gate < bounds.size(); ++gate)
                if (RipTarget(d, 1) == bounds[gate] &&
                    before[index(a.reg.value)] == (gate & 1 ? Value::upper : Value::lower)) {
                    state.flags = gate;
                    state.flag_origin = before_origins[index(a.reg.value)];
                    state.flag_link = before_links[index(a.reg.value)];
                }
        const auto category = d.instruction.meta.category;
        if (category == ZYDIS_CATEGORY_CALL) {
            state.flags.reset();
            for (const auto reg : {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
                     ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11}) {
                state.values[index(reg)] = Value::unknown;
                state.origins[index(reg)] = 0;
                state.links[index(reg)] = 0;
            }
        }
        if (category == ZYDIS_CATEGORY_RET) {
            const auto value = state.values[index(ZYDIS_REGISTER_RAX)];
            if (value != Value::zero && (value != Value::payload || state.gates != 15))
                return false;
            if (value == Value::payload)
                for (unsigned gate = 0; gate < 4; ++gate)
                    if (state.gate_origins[gate] != state.origins[index(ZYDIS_REGISTER_RAX)] ||
                        state.gate_links[gate] != state.gate_links[0])
                        return false;
            returned |= value == Value::payload;
            continue;
        }
        if (category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) {
            const auto destination = target(DirectTarget(d));
            if (!destination)
                return false;
            auto branch = state;
            branch.at = *destination;
            if (state.flags) {
                const auto gate = *state.flags;
                const auto verify = [&](State& selected) {
                    selected.gates |= 1u << gate;
                    selected.gate_origins[gate] = state.flag_origin;
                    selected.gate_links[gate] = state.flag_link;
                };
                if (!(gate & 1) && d.instruction.mnemonic == ZYDIS_MNEMONIC_JB)
                    verify(state);
                else if (!(gate & 1) && d.instruction.mnemonic == ZYDIS_MNEMONIC_JNB)
                    verify(branch);
                else if ((gate & 1) && d.instruction.mnemonic == ZYDIS_MNEMONIC_JNBE)
                    verify(state);
                else if ((gate & 1) && d.instruction.mnemonic == ZYDIS_MNEMONIC_JBE)
                    verify(branch);
            }
            pending.push_back(branch);
            if (category == ZYDIS_CATEGORY_UNCOND_BR)
                continue;
        }
        ++state.at;
        pending.push_back(state);
    }
    return returned && pending.empty();
}

std::optional<OperatorNameDescriptor> BoundedNullableResource(const Emulator::Program& code) {
    const auto& ins = code.instructions;
    if (ins.empty() || ins.size() > 1024 || code.end - code.begin >= 0x1000)
        return std::nullopt;
    std::vector<std::uint64_t> found;
    for (const auto& d : ins)
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_CMP && d.operands[0].size == 16 &&
            d.operands[1].size == 16 && RipTarget(d, 1))
            found.push_back(RipTarget(d, 1));
    if (found.size() != 4 || found[1] != found[0] + 2 || found[3] != found[2] + 2 || found[0] == found[2])
        return std::nullopt;
    const std::array<std::uint64_t, 4> bounds{found[0], found[1], found[2], found[3]};
    std::optional<OperatorNameDescriptor> accepted;
    for (std::size_t payload = 0; payload < ins.size(); ++payload) {
        const auto& d = ins[payload];
        const auto& source = d.operands[1];
        if (d.instruction.address_width != 64 || d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            d.operands[0].reg.value != ZYDIS_REGISTER_RAX || d.operands[0].size != 64 ||
            source.type != ZYDIS_OPERAND_TYPE_MEMORY || source.size != 64 ||
            source.mem.index != ZYDIS_REGISTER_NONE || source.mem.disp.value != 0 ||
            source.mem.segment == ZYDIS_REGISTER_FS || source.mem.segment == ZYDIS_REGISTER_GS)
            continue;
        for (std::size_t branch = 1; branch < payload; ++branch) {
            if ((ins[branch].instruction.mnemonic != ZYDIS_MNEMONIC_JZ &&
                    ins[branch].instruction.mnemonic != ZYDIS_MNEMONIC_JNZ) ||
                !OperatorNull(code, branch, source.mem.base))
                continue;
            auto path = Flow(code, 0, branch, {ZYDIS_REGISTER_RCX}, {source.mem.base});
            if (!path || !ResourceReturns(code, branch, source.mem.base, bounds))
                continue;
            std::set<std::uint32_t> fields;
            for (const auto& at : path->code.instructions)
                for (const auto& operand : at.operands)
                    if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.size == 64 &&
                        operand.mem.base == ZYDIS_REGISTER_RCX && operand.mem.index == ZYDIS_REGISTER_NONE &&
                        operand.mem.disp.value > 0 && operand.mem.disp.value < 0x10000 &&
                        operand.mem.segment != ZYDIS_REGISTER_FS &&
                        operand.mem.segment != ZYDIS_REGISTER_GS &&
                        (operand.actions & ZYDIS_OPERAND_ACTION_MASK_READ))
                        fields.insert(static_cast<std::uint32_t>(operand.mem.disp.value));
            if (fields.size() != 1 || accepted)
                return std::nullopt;
            accepted = OperatorNameDescriptor{std::move(*path), *fields.begin(), code.begin, bounds[2]};
        }
    }
    return accepted;
}

bool OperatorPayload(const Emulator::Program& code, std::size_t retain, std::size_t member,
    ZydisRegister holder, ZydisRegister input) {
    const auto& ins = code.instructions;

    struct State {
        std::size_t at;
        std::uint32_t aliases;
        bool holder_stable;

        bool operator<(const State& other) const {
            return std::tie(at, aliases, holder_stable) <
                std::tie(other.at, other.aliases, other.holder_stable);
        }
    };

    const auto target = [&](std::uint64_t address) -> std::optional<std::size_t> {
        const auto found = std::lower_bound(ins.begin(), ins.end(), address,
            [](const auto& value, auto needle) { return value.address < needle; });
        return found != ins.end() && found->address == address
            ? std::optional<std::size_t>(found - ins.begin())
            : std::nullopt;
    };
    std::set<State> visited;
    std::vector<State> pending{{retain + 1, 0, true}};
    for (std::size_t next = 0; next < pending.size() && visited.size() < 512; ++next) {
        auto state = pending[next];
        if (state.at >= ins.size() || !visited.insert(state).second)
            continue;
        if (state.at == member && (state.aliases & Dependency(input)))
            return true;
        const auto& instruction = ins[state.at];
        const auto before = state.aliases;
        const auto holder_before = state.holder_stable;
        for (const auto& operand : instruction.operands)
            if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                (operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) {
                state.aliases &= ~Dependency(operand.reg.value);
                if (Dependency(operand.reg.value) == Dependency(holder))
                    state.holder_stable = false;
            }
        if (instruction.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            instruction.operands[0].size == 64 && instruction.operands[1].size == 64 &&
            (before & Dependency(instruction.operands[1].reg.value)))
            state.aliases |= Dependency(instruction.operands[0].reg.value);
        const auto& source = instruction.operands[1];
        if (holder_before && instruction.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            instruction.instruction.address_width == 64 &&
            instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            instruction.operands[0].size == 64 && source.type == ZYDIS_OPERAND_TYPE_MEMORY &&
            source.size == 64 && source.mem.base == holder && source.mem.index == ZYDIS_REGISTER_NONE &&
            source.mem.disp.value == 0 && source.mem.segment != ZYDIS_REGISTER_FS &&
            source.mem.segment != ZYDIS_REGISTER_GS)
            state.aliases |= Dependency(instruction.operands[0].reg.value);
        const auto category = instruction.instruction.meta.category;
        if (category == ZYDIS_CATEGORY_CALL) {
            const auto volatile_registers = Dependency(ZYDIS_REGISTER_RAX) | Dependency(ZYDIS_REGISTER_RCX) |
                Dependency(ZYDIS_REGISTER_RDX) | Dependency(ZYDIS_REGISTER_R8) |
                Dependency(ZYDIS_REGISTER_R9) | Dependency(ZYDIS_REGISTER_R10) |
                Dependency(ZYDIS_REGISTER_R11);
            state.aliases &= ~volatile_registers;
            if (Dependency(holder) & volatile_registers)
                state.holder_stable = false;
        }
        if (instruction.instruction.mnemonic == ZYDIS_MNEMONIC_RET)
            continue;
        if (category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) {
            if (const auto destination = target(DirectTarget(instruction)))
                pending.push_back({*destination, state.aliases, state.holder_stable});
            if (category == ZYDIS_CATEGORY_UNCOND_BR)
                continue;
        }
        pending.push_back({state.at + 1, state.aliases, state.holder_stable});
    }
    return false;
}

bool OperatorMember(const PointerDescriptor& path, std::uint64_t member) {
    if (path.input.stack || path.output.stack)
        return false;
    std::set<std::uint64_t> reads;
    const auto evaluate = [&](const Emulator::Program& code, std::uint32_t supplied,
                              const std::map<std::int64_t, bool>& supplied_slots) {
        std::uint32_t dependent = Dependency(path.input.reg) | supplied;
        auto slots = supplied_slots;
        for (const auto& value : code.instructions) {
            bool derived{};
            for (unsigned at = 0; at < value.instruction.operand_count; ++at) {
                const auto& operand = value.operands[at];
                if (!(operand.actions & ZYDIS_OPERAND_ACTION_MASK_READ))
                    continue;
                if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER)
                    derived |= (dependent & Dependency(operand.reg.value)) != 0;
                else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    const bool address =
                        (dependent & (Dependency(operand.mem.base) | Dependency(operand.mem.index))) != 0;
                    if (address && value.instruction.mnemonic != ZYDIS_MNEMONIC_LEA &&
                        operand.mem.index == ZYDIS_REGISTER_NONE && operand.mem.disp.value >= 0 &&
                        operand.mem.disp.value < 0x10000)
                        reads.insert(value.address);
                    derived |= address || (LocalSlot(operand) && slots[operand.mem.disp.value]);
                }
            }
            if (value.instruction.mnemonic == ZYDIS_MNEMONIC_XOR &&
                value.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                value.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                value.operands[0].reg.value == value.operands[1].reg.value)
                derived = false;
            for (unsigned at = 0; at < value.instruction.operand_count; ++at) {
                const auto& operand = value.operands[at];
                if (!(operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                    continue;
                if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    dependent &= ~Dependency(operand.reg.value);
                    if (derived)
                        dependent |= Dependency(operand.reg.value);
                } else if (LocalSlot(operand))
                    slots[operand.mem.disp.value] = derived;
            }
        }
        return std::pair{dependent, std::move(slots)};
    };
    std::uint32_t seeds{};
    std::map<std::int64_t, bool> seed_slots;
    for (const auto& seed : path.seeds) {
        const auto [dependent, slots] = evaluate(seed.value.code, 0, {});
        if (seed.target.stack) {
            const auto found = slots.find(seed.target.slot);
            seed_slots[seed.target.slot] = found != slots.end() && found->second;
        } else if (dependent & Dependency(seed.value.output))
            seeds |= Dependency(seed.target.reg);
    }
    evaluate(path.code, seeds, seed_slots);
    return reads.size() == 1 && reads.contains(member);
}

std::optional<OperatorSelectionDescriptor> BoundedOperatorSelection(const Emulator::Program& code,
    std::uint64_t missing_instance_string, const ValidationObserver& validation) {
    const auto& ins = code.instructions;
    const auto report = [&](std::string_view rule, std::uint64_t address, std::uint64_t observed) {
        if (validation)
            validation(rule, address, observed);
    };
    if (ins.empty() || ins.size() > 4096)
        return std::nullopt;
    const auto index = [&](std::uint64_t address) -> std::optional<std::size_t> {
        const auto found = std::lower_bound(ins.begin(), ins.end(), address,
            [](const auto& value, auto needle) { return value.address < needle; });
        return found != ins.end() && found->address == address
            ? std::optional<std::size_t>(found - ins.begin())
            : std::nullopt;
    };
    const auto member_operand = [&](const auto& operand) {
        return operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.size == 64 &&
            operand.mem.index == ZYDIS_REGISTER_NONE && Dependency(operand.mem.base) &&
            operand.mem.base != ZYDIS_REGISTER_RSP && operand.mem.disp.value >= 8 &&
            operand.mem.disp.value < 0x10000 && operand.mem.segment != ZYDIS_REGISTER_FS &&
            operand.mem.segment != ZYDIS_REGISTER_GS;
    };
    std::optional<OperatorSelectionDescriptor> accepted;
    for (std::size_t end = 1; end + 1 < ins.size(); ++end) {
        const auto& branch = ins[end];
        std::optional<std::size_t> retain, failure;
        if (branch.instruction.mnemonic == ZYDIS_MNEMONIC_JZ) {
            retain = end + 1;
            failure = index(DirectTarget(branch));
        } else if (branch.instruction.mnemonic == ZYDIS_MNEMONIC_JNZ) {
            retain = index(DirectTarget(branch));
            failure = end + 1;
        }
        if (!retain || !failure || *retain + 2 >= ins.size() ||
            ins[*failure].instruction.mnemonic != ZYDIS_MNEMONIC_LEA ||
            RipTarget(ins[*failure], 1) != missing_instance_string)
            continue;
        const auto& reference = ins[*retain];
        const auto& object_check = ins[*retain + 1];
        const auto& object_branch = ins[*retain + 2];
        const auto& holder_memory = reference.operands[0];
        if (reference.instruction.mnemonic != ZYDIS_MNEMONIC_INC ||
            reference.instruction.address_width != 64 || object_check.instruction.address_width != 64 ||
            !(reference.instruction.attributes & ZYDIS_ATTRIB_HAS_LOCK) ||
            holder_memory.type != ZYDIS_OPERAND_TYPE_MEMORY || holder_memory.size != 64 ||
            holder_memory.mem.index != ZYDIS_REGISTER_NONE || holder_memory.mem.disp.value != 8 ||
            holder_memory.mem.segment == ZYDIS_REGISTER_FS ||
            holder_memory.mem.segment == ZYDIS_REGISTER_GS || !Dependency(holder_memory.mem.base) ||
            object_check.instruction.mnemonic != ZYDIS_MNEMONIC_CMP ||
            object_check.operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
            object_check.operands[0].size != 64 ||
            object_check.operands[0].mem.base != holder_memory.mem.base ||
            object_check.operands[0].mem.index != ZYDIS_REGISTER_NONE ||
            object_check.operands[0].mem.disp.value != 0 ||
            object_check.operands[0].mem.segment == ZYDIS_REGISTER_FS ||
            object_check.operands[0].mem.segment == ZYDIS_REGISTER_GS ||
            object_check.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
            object_check.operands[1].imm.is_relative || object_check.operands[1].imm.value.u != 0 ||
            object_branch.instruction.mnemonic != ZYDIS_MNEMONIC_JZ ||
            DirectTarget(object_branch) != ins[*failure].address ||
            !OperatorNull(code, end, holder_memory.mem.base)) {
            report("operator_selection_holder_gate_rejected", branch.address, *retain);
            continue;
        }
        std::optional<PointerDescriptor> instance;
        std::optional<std::uint32_t> instance_field;
        for (std::size_t member = end; member > 0 && end - member < 384; --member) {
            const auto& at = ins[member - 1];
            for (unsigned operand = 0; operand < at.instruction.operand_count_visible; ++operand) {
                const auto& source = at.operands[operand];
                if (at.instruction.address_width != 64 || !member_operand(source) ||
                    !(source.actions & ZYDIS_OPERAND_ACTION_MASK_READ))
                    continue;
                auto path = Flow(code, member - 1, end, {source.mem.base}, {holder_memory.mem.base});
                if (!path || !OperatorMember(*path, at.address) ||
                    std::none_of(path->code.instructions.begin(), path->code.instructions.end(),
                        [&](const auto& value) { return value.address == at.address; })) {
                    report("operator_selection_instance_flow_rejected", at.address, source.mem.disp.value);
                    continue;
                }
                if (instance) {
                    report("operator_selection_instance_ambiguous", at.address, source.mem.disp.value);
                    return std::nullopt;
                }
                instance = std::move(path);
                instance_field = static_cast<std::uint32_t>(source.mem.disp.value);
            }
        }
        if (!instance) {
            report("operator_selection_instance_missing", branch.address, *retain);
            continue;
        }
        std::optional<OperatorNameDescriptor> definition;
        for (std::size_t gate = *retain + 5; gate + 4 < ins.size(); ++gate) {
            if (ins[gate].instruction.mnemonic != ZYDIS_MNEMONIC_CMP || ins[gate].operands[0].size != 16 ||
                !RipTarget(ins[gate], 1) || ins[gate + 1].instruction.mnemonic != ZYDIS_MNEMONIC_JB ||
                ins[gate + 3].instruction.mnemonic != ZYDIS_MNEMONIC_CMP ||
                ins[gate + 3].operands[0].size != 16 ||
                RipTarget(ins[gate + 3], 1) != RipTarget(ins[gate], 1) + 2 ||
                (ins[gate + 4].instruction.mnemonic != ZYDIS_MNEMONIC_JBE &&
                    (ins[gate + 4].instruction.mnemonic != ZYDIS_MNEMONIC_JNBE ||
                        DirectTarget(ins[gate + 4]) != DirectTarget(ins[gate + 1]))))
                continue;
            const auto& table = ins[gate - 3];
            const auto& info = ins[gate - 2];
            const auto& lower = ins[gate - 1];
            const auto& upper = ins[gate + 2];
            const auto memory = [](const auto& value, ZydisRegister base, std::int64_t field, unsigned bits) {
                return value.type == ZYDIS_OPERAND_TYPE_MEMORY && value.size == bits &&
                    value.mem.base == base && value.mem.index == ZYDIS_REGISTER_NONE &&
                    value.mem.disp.value == field && value.mem.segment != ZYDIS_REGISTER_FS &&
                    value.mem.segment != ZYDIS_REGISTER_GS;
            };
            const auto reg = [](const auto& value, unsigned bits) {
                return value.type == ZYDIS_OPERAND_TYPE_REGISTER && value.size == bits &&
                    Dependency(value.reg.value);
            };
            const auto interval = [&](const auto& value, const auto& compare, std::int64_t field) {
                return value.instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX &&
                    value.instruction.address_width == 64 && reg(value.operands[0], 32) &&
                    memory(value.operands[1], info.operands[0].reg.value, field, 16) &&
                    compare.instruction.address_width == 64 && reg(compare.operands[0], 16) &&
                    Dependency(compare.operands[0].reg.value) == Dependency(value.operands[0].reg.value) &&
                    memory(compare.operands[1], ZYDIS_REGISTER_RIP, compare.operands[1].mem.disp.value, 16);
            };
            if (table.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || table.instruction.address_width != 64 ||
                !reg(table.operands[0], 64) || table.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                !Dependency(table.operands[1].mem.base) ||
                !memory(table.operands[1], table.operands[1].mem.base, 0, 64) ||
                info.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || info.instruction.address_width != 64 ||
                !reg(info.operands[0], 64) || info.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                info.operands[1].mem.disp.value < 8 || info.operands[1].mem.disp.value >= 0x100 ||
                info.operands[1].mem.disp.value % 8 != 0 ||
                !memory(info.operands[1], table.operands[0].reg.value, info.operands[1].mem.disp.value, 64) ||
                !interval(lower, ins[gate], 0x40) || !interval(upper, ins[gate + 3], 0x42)) {
                report("operator_selection_definition_type_rejected", ins[gate].address,
                    RipTarget(ins[gate], 1));
                continue;
            }
            const auto payload = OperatorWrite(code, gate - 3, table.operands[1].mem.base);
            if (!payload || *payload <= *retain || ins[*payload].instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                ins[*payload].instruction.address_width != 64 ||
                ins[*payload].operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                ins[*payload].operands[0].size != 64 ||
                ins[*payload].operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                ins[*payload].operands[1].size != 64 ||
                ins[*payload].operands[1].mem.index != ZYDIS_REGISTER_NONE ||
                ins[*payload].operands[1].mem.disp.value != 0 ||
                ins[*payload].operands[1].mem.segment == ZYDIS_REGISTER_FS ||
                ins[*payload].operands[1].mem.segment == ZYDIS_REGISTER_GS)
                continue;
            const auto reference_register = ins[*payload].operands[1].mem.base;
            for (std::size_t null_gate = *payload; null_gate > *retain + 3 && *payload - null_gate < 128;
                --null_gate) {
                const auto& null_branch = ins[null_gate - 1];
                const auto failure_address = DirectTarget(ins[gate + 1]);
                const auto routes_failure = (null_branch.instruction.mnemonic == ZYDIS_MNEMONIC_JZ &&
                                                DirectTarget(null_branch) == failure_address) ||
                    (null_branch.instruction.mnemonic == ZYDIS_MNEMONIC_JNZ &&
                        ins[null_gate].address == failure_address && index(DirectTarget(null_branch)));
                if (!routes_failure || !OperatorNull(code, null_gate - 1, reference_register))
                    continue;
                for (std::size_t member = null_gate - 1; member > *retain + 3 && null_gate - member < 256;
                    --member) {
                    const auto& at = ins[member - 1];
                    for (unsigned operand = 0; operand < at.instruction.operand_count_visible; ++operand) {
                        const auto& source = at.operands[operand];
                        if (!member_operand(source) || !(source.actions & ZYDIS_OPERAND_ACTION_MASK_READ) ||
                            !OperatorPayload(
                                code, *retain, member - 1, holder_memory.mem.base, source.mem.base))
                            continue;
                        auto path =
                            Flow(code, member - 1, null_gate - 1, {source.mem.base}, {reference_register});
                        if (!path || !OperatorMember(*path, at.address) ||
                            std::none_of(path->code.instructions.begin(), path->code.instructions.end(),
                                [&](const auto& value) { return value.address == at.address; })) {
                            report("operator_selection_definition_flow_rejected", at.address,
                                source.mem.disp.value);
                            continue;
                        }
                        if (definition) {
                            report(
                                "operator_selection_definition_ambiguous", at.address, source.mem.disp.value);
                            return std::nullopt;
                        }
                        definition = OperatorNameDescriptor{std::move(*path),
                            static_cast<std::uint32_t>(source.mem.disp.value), code.begin,
                            RipTarget(ins[gate], 1)};
                    }
                }
            }
        }
        if (!definition) {
            report("operator_selection_definition_missing", branch.address, *retain);
            continue;
        }
        if (accepted) {
            report("operator_selection_consumer_ambiguous", branch.address, *retain);
            return std::nullopt;
        }
        accepted = OperatorSelectionDescriptor{std::move(*instance), std::move(definition->reference),
            *instance_field, definition->field, code.begin, definition->target_type};
    }
    report(accepted ? "operator_selection_bounded_accepted" : "operator_selection_bounded_rejected",
        code.begin, accepted ? accepted->instance_field : ins.size());
    return accepted;
}
}

std::optional<OperatorSelectionDescriptor> OperatorSelection(const Emulator::Program& code,
    std::span<const std::byte> bytes, std::uint32_t code_rva, std::uint64_t module,
    std::span<const FunctionRecord> functions, std::uint64_t missing_instance_string,
    const ValidationObserver& validation) {
    if (auto value =
            LegacyOperatorSelection(code, bytes, code_rva, module, functions, missing_instance_string))
        return value;
    return BoundedOperatorSelection(code, missing_instance_string, validation);
}

std::optional<OperatorSelectionDescriptor> DiscoverOperatorSelection(std::span<const std::byte> code,
    std::uint32_t code_rva, std::uint64_t module, std::span<const FunctionRecord> functions,
    std::span<const std::byte> rdata, std::uint32_t rdata_rva, const ValidationObserver& validation) {
    constexpr std::string_view label = "[LoadoutSelectionOperator] The characterInstance contained in the "
                                       "PRI is invalid for wanted operator. How is it possible ?";
    const auto needle = std::as_bytes(std::span(label.data(), label.size() + 1));
    const auto at = std::search(rdata.begin(), rdata.end(), needle.begin(), needle.end());
    if (at == rdata.end() ||
        std::search(at + needle.size(), rdata.end(), needle.begin(), needle.end()) != rdata.end()) {
        if (validation)
            validation("operator_selection_anchor_rejected", module + rdata_rva, rdata.size());
        return std::nullopt;
    }
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
        auto value = OperatorSelection(*decoded, code, code_rva, module, functions, target, validation);
        if (!value || result)
            return std::nullopt;
        result = std::move(value);
    }
    return result;
}

std::optional<OwnershipDescriptor> OwnerProfile(
    const Emulator::Program& wrapper, const ValidationObserver& validation) {
    const auto& ins = wrapper.instructions;
    const auto rejected = [&](std::string_view reason, std::uint64_t value = 0) {
        if (validation)
            validation(reason, wrapper.begin, value);
        return std::nullopt;
    };

    struct Gate {
        std::size_t begin, end;
        std::int64_t table;
        std::uint64_t failure;
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
            a.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || a.operands[0].size != 64 ||
            a.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || a.operands[1].size != 64 ||
            a.operands[1].mem.index != ZYDIS_REGISTER_NONE || a.operands[1].mem.disp.value != 0 ||
            b.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            b.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || b.operands[0].size != 64 ||
            b.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || b.operands[1].size != 64 ||
            b.operands[1].mem.index != ZYDIS_REGISTER_NONE ||
            b.operands[1].mem.base != a.operands[0].reg.value || b.operands[1].mem.disp.value < 0 ||
            b.operands[1].mem.disp.value >= 0x1000 || b.operands[1].mem.disp.value % 8 ||
            c.instruction.mnemonic != ZYDIS_MNEMONIC_MOVZX ||
            c.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || c.operands[1].size != 16 ||
            c.operands[1].mem.index != ZYDIS_REGISTER_NONE ||
            c.operands[1].mem.base != b.operands[0].reg.value || c.operands[1].mem.disp.value != 0x40 ||
            ins[j + 3].instruction.mnemonic != ZYDIS_MNEMONIC_CMP || !rip(ins[j + 3], 1) ||
            ins[j + 3].operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || ins[j + 3].operands[0].size != 16 ||
            ins[j + 3].operands[1].size != 16 ||
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
        if (upper <= j + 4 || upper + 3 >= ins.size() ||
            ins[upper].instruction.mnemonic != ZYDIS_MNEMONIC_MOVZX ||
            ins[upper].operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || ins[upper].operands[1].size != 16 ||
            ins[upper].operands[1].mem.index != ZYDIS_REGISTER_NONE ||
            ins[upper].operands[1].mem.base != b.operands[0].reg.value ||
            ins[upper].operands[1].mem.disp.value != 0x42 ||
            ins[upper + 1].instruction.mnemonic != ZYDIS_MNEMONIC_CMP ||
            ins[upper + 1].operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            ins[upper + 1].operands[0].size != 16 || ins[upper + 1].operands[1].size != 16 ||
            Dependency(ins[upper + 1].operands[0].reg.value) !=
                Dependency(ins[upper].operands[0].reg.value) ||
            rip(ins[upper + 1], 1) != rip(ins[j + 3], 1) + 2 ||
            (ins[upper + 2].instruction.mnemonic != ZYDIS_MNEMONIC_JNBE &&
                ins[upper + 2].instruction.mnemonic != ZYDIS_MNEMONIC_JBE))
            continue;
        const auto failure = ins[j + 4].instruction.mnemonic == ZYDIS_MNEMONIC_JB ? branch_target(ins[j + 4])
                                                                                  : ins[j + 5].address;
        const auto upper_failure = ins[upper + 2].instruction.mnemonic == ZYDIS_MNEMONIC_JNBE
            ? branch_target(ins[upper + 2])
            : ins[upper + 3].address;
        if (!failure || upper_failure != failure)
            continue;
        gates.push_back({j, upper + 2, b.operands[1].mem.disp.value, failure});
    }
    if (gates.size() != 2 || gates[1].begin <= gates[0].end + 2 || gates[0].table != gates[1].table)
        return rejected("owner_profile_type_gates", gates.size());
    const auto first = gates[0].begin, second = gates[1].begin;
    const auto owner_reg = ins[first].operands[1].mem.base;
    const auto profile_reg = ins[second].operands[1].mem.base;
    std::optional<std::size_t> profile_guard;
    for (std::size_t j = second; j > gates[0].end + 1 && second - j < 12; --j) {
        const auto guard = j - 1;
        if (ins[guard].instruction.mnemonic != ZYDIS_MNEMONIC_JZ ||
            branch_target(ins[guard]) != gates[1].failure || !guard)
            continue;
        const auto& tested = ins[guard - 1];
        const auto& target = tested.operands[0];
        if (target.type != ZYDIS_OPERAND_TYPE_REGISTER || target.size != 64 || !Dependency(target.reg.value))
            continue;
        const bool self_test = tested.instruction.mnemonic == ZYDIS_MNEMONIC_TEST &&
            tested.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && tested.operands[1].size == 64 &&
            tested.operands[1].reg.value == target.reg.value;
        if (!self_test && tested.instruction.mnemonic != ZYDIS_MNEMONIC_XOR &&
            tested.instruction.mnemonic != ZYDIS_MNEMONIC_ADD &&
            tested.instruction.mnemonic != ZYDIS_MNEMONIC_SUB)
            continue;
        std::array<unsigned, 16> identities{};
        for (unsigned n = 0; n < identities.size(); ++n)
            identities[n] = n + 1;
        const auto id = [](ZydisRegister reg) {
            return ZydisRegisterGetId(ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg));
        };
        unsigned next_identity = 17, zero_identity{};
        const auto begin = std::max(gates[0].end + 1, guard > 12 ? guard - 12 : 0);
        for (std::size_t n = begin; n < second; ++n) {
            const auto& d = ins[n];
            const auto before = identities;
            for (unsigned k = 0; k < d.instruction.operand_count; ++k) {
                const auto& o = d.operands[k];
                if (o.type != ZYDIS_OPERAND_TYPE_REGISTER || !Dependency(o.reg.value) ||
                    !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                    continue;
                auto identity = next_identity++;
                if (k == 0 && o.size == 64 &&
                    (d.instruction.mnemonic == ZYDIS_MNEMONIC_ROL ||
                        d.instruction.mnemonic == ZYDIS_MNEMONIC_ROR))
                    identity = before[id(o.reg.value)];
                if (k == 0 && o.size == 64 && d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[1].size == 64 &&
                    Dependency(d.operands[1].reg.value))
                    identity = before[id(d.operands[1].reg.value)];
                identities[id(o.reg.value)] = identity;
            }
            if (n == guard - 1)
                zero_identity = identities[id(target.reg.value)];
        }
        if (zero_identity && identities[id(profile_reg)] == zero_identity) {
            if (profile_guard)
                return std::nullopt;
            profile_guard = guard;
        }
    }
    if (!profile_guard)
        return rejected("owner_profile_null_guard");
    for (std::size_t j = gates[0].end + 1; j < second; ++j) {
        const auto category = ins[j].instruction.meta.category;
        if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_RET ||
            category == ZYDIS_CATEGORY_UNCOND_BR ||
            (category == ZYDIS_CATEGORY_COND_BR && j != *profile_guard))
            return rejected("owner_profile_control_flow", ins[j].address);
    }
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
    if (!mix)
        return rejected("owner_profile_owner_mix");

    auto owner = Slice(Simplify(wrapper), *mix, owner_reg);
    if (!owner || owner->inputs != Dependency(ZYDIS_REGISTER_RDX)) {
        for (std::size_t j = 0; j < *mix; ++j) {
            const auto category = ins[j].instruction.meta.category;
            if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_RET ||
                category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR)
                return rejected("owner_profile_caller_control_flow", ins[j].address);
        }
        const auto caller = CallerSlot(wrapper, *mix);
        if (!caller || *caller < 8)
            return rejected("owner_profile_caller_frame");
        auto normalized = wrapper;
        unsigned replacements{};
        for (std::size_t j = 0; j < *mix; ++j) {
            auto& d = normalized.instructions[j];
            if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || d.operands[0].size != 64 ||
                !LocalSlot(d.operands[1]) || d.operands[1].size != 64 ||
                d.operands[1].mem.segment != ZYDIS_REGISTER_SS || d.operands[1].mem.disp.value != *caller ||
                CallerSlot(wrapper, j) != caller)
                continue;
            d.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
            d.operands[1].imm.is_signed = false;
            d.operands[1].imm.is_relative = false;
            d.operands[1].imm.value.u = wrapper.begin;
            ++replacements;
        }
        if (replacements != 1)
            return rejected("owner_profile_caller_input", replacements);
        owner = Slice(Simplify(normalized, true), first, owner_reg);
    }
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
    const auto profile_end = ins[second - 1].instruction.mnemonic == ZYDIS_MNEMONIC_JZ ? second - 1 : second;
    profile_code.instructions.insert(
        profile_code.instructions.end(), ins.begin() + gates[0].end + 1, ins.begin() + profile_end);
    if (profile_code.instructions.empty())
        return std::nullopt;
    profile_code.begin = profile_code.instructions.front().address;
    profile_code.end = ins[profile_end].address;
    auto profile = Slice(Simplify(profile_code), profile_code.instructions.size(), profile_reg);
    if (!profile || profile->inputs != Dependency(owner_reg))
        profile = Slice(Simplify(profile_code, true), profile_code.instructions.size(), profile_reg);
    if (!profile || profile->inputs != Dependency(owner_reg)) {
        Emulator::Program expanded{};
        expanded.linear = true;
        for (unsigned j = 0; j < 16; ++j) {
            const auto reg = static_cast<ZydisRegister>(ZYDIS_REGISTER_RAX + j);
            if (reg == ZYDIS_REGISTER_RSP || reg == owner_reg)
                continue;
            const auto value = Slice(Simplify(wrapper, true), first, reg);
            if (value && !value->inputs)
                expanded.instructions.insert(expanded.instructions.end(), value->code.instructions.begin(),
                    value->code.instructions.end());
        }
        expanded.instructions.insert(
            expanded.instructions.end(), ins.begin() + first, ins.begin() + gates[0].end + 1);
        expanded.instructions.insert(
            expanded.instructions.end(), profile_code.instructions.begin(), profile_code.instructions.end());
        expanded.begin = expanded.instructions.front().address;
        expanded.end = profile_code.end;
        profile = Slice(Simplify(expanded, true), expanded.instructions.size(), profile_reg);
    }
    if (!owner || !profile || owner->inputs != Dependency(ZYDIS_REGISTER_RDX) ||
        profile->inputs != Dependency(owner_reg))
        return rejected("owner_profile_inputs",
            !owner         ? 0
                : !profile ? 1
                           : (static_cast<std::uint64_t>(owner->inputs) << 32) | profile->inputs);

    if (validation)
        validation("owner_profile_accepted", wrapper.begin, 1);

    return OwnershipDescriptor{
        std::move(*owner), std::move(*profile), rip(ins[first + 3], 1), rip(ins[second + 3], 1)};
}

static std::optional<UsernameDescriptor> Username(const Emulator::Program& wrapper,
    std::span<const std::byte> bytes, std::uint32_t code_rva, std::uint64_t module,
    std::span<const FunctionRecord> functions, const ValidationObserver& validation = {}) {

    const auto paths = OwnerProfile(wrapper, validation);
    if (!paths)
        return std::nullopt;
    const auto& ins = wrapper.instructions;
    std::optional<std::uint32_t> field;
    std::optional<std::size_t> profile_success;
    for (std::size_t j = 0; j + 1 < ins.size(); ++j) {
        const auto& d = ins[j];
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_CMP || d.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
            d.operands[1].mem.base != ZYDIS_REGISTER_RIP ||
            d.address + d.instruction.length + d.operands[1].mem.disp.value != paths->profile_type + 2)
            continue;
        const auto& branch = ins[j + 1];
        if (branch.instruction.mnemonic == ZYDIS_MNEMONIC_JNBE)
            profile_success = j + 2;
        else if (branch.instruction.mnemonic == ZYDIS_MNEMONIC_JBE &&
            branch.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && branch.operands[0].imm.is_relative) {
            const auto target = branch.address + branch.instruction.length + branch.operands[0].imm.value.s;
            const auto at = std::lower_bound(ins.begin(), ins.end(), target,
                [](const auto& d, auto address) { return d.address < address; });
            if (at != ins.end() && at->address == target)
                profile_success = static_cast<std::size_t>(at - ins.begin());
        }
    }
    if (!profile_success || *profile_success >= ins.size())
        return std::nullopt;
    for (const auto& call : ins) {
        if (call.instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
            call.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !call.operands[0].imm.is_relative)
            continue;
        const auto call_index = static_cast<std::size_t>(&call - ins.data());
        const bool direct = call_index == *profile_success && paths->profile.output == ZYDIS_REGISTER_RDX;
        if (!direct &&
            !Flow(wrapper, *profile_success, call_index, Location{paths->profile.output, 0, false},
                Location{ZYDIS_REGISTER_RDX, 0, false}))
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
    if (!field) {
        if (validation)
            validation("username_string_consumer", wrapper.begin, 0);
        return std::nullopt;
    }
    if (validation)
        validation("username_accepted", wrapper.begin, *field);
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
    std::span<const FunctionRecord> functions, const ValidationObserver& validation = {}) {
    const auto& instructions = source.instructions;
    const auto count = [&](ZydisMnemonic m) {
        return std::count_if(instructions.begin(), instructions.end(),
            [&](const auto& d) { return d.instruction.mnemonic == m; });
    };

    if (count(ZYDIS_MNEMONIC_CVTTSS2SI) < 2 || count(ZYDIS_MNEMONIC_MOVD) < 1) {
        if (validation)
            validation("health_scalar_conversions", source.begin, count(ZYDIS_MNEMONIC_CVTTSS2SI));
        return std::nullopt;
    }
    const auto tested = [&](std::size_t before, ZydisRegister reg) {
        for (unsigned remaining = 4; before && remaining; --remaining) {
            const auto& d = instructions[--before];
            if (d.instruction.mnemonic == ZYDIS_MNEMONIC_TEST)
                return d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[0].size == 32 &&
                    d.operands[1].size == 32 && d.operands[0].reg.value == reg &&
                    d.operands[1].reg.value == reg;
            if ((d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV &&
                    d.instruction.mnemonic != ZYDIS_MNEMONIC_LEA) ||
                d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                Dependency(d.operands[0].reg.value) == Dependency(reg))
                return false;
        }
        return false;
    };
    std::vector<std::optional<std::uint32_t>> zero_states(instructions.size());
    if (!instructions.empty())
        zero_states.front() = 0;
    std::vector<std::size_t> zero_pending{0};
    unsigned zero_steps{};
    while (!zero_pending.empty() && zero_steps++ < 16384) {
        const auto at = zero_pending.back();
        zero_pending.pop_back();
        if (at >= instructions.size())
            continue;
        const auto& d = instructions[at];
        const auto before = *zero_states[at];
        auto after = before;
        for (unsigned j = 0; j < d.instruction.operand_count; ++j) {
            const auto& o = d.operands[j];
            if (o.type != ZYDIS_OPERAND_TYPE_REGISTER || !Dependency(o.reg.value) ||
                !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                continue;
            const auto bit = Dependency(o.reg.value);
            const auto& value = d.operands[1];
            bool zero{};
            if (j == 0 && o.size >= 32) {
                zero = (d.instruction.mnemonic == ZYDIS_MNEMONIC_XOR ||
                           d.instruction.mnemonic == ZYDIS_MNEMONIC_SUB) &&
                    value.type == ZYDIS_OPERAND_TYPE_REGISTER && value.reg.value == o.reg.value;
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV)
                    zero = (value.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !value.imm.is_relative &&
                               !value.imm.value.u) ||
                        (value.type == ZYDIS_OPERAND_TYPE_REGISTER && value.size >= 32 &&
                            (before & Dependency(value.reg.value)));
                if (o.actions & ZYDIS_OPERAND_ACTION_CONDWRITE)
                    zero = (before & bit) && value.type == ZYDIS_OPERAND_TYPE_REGISTER && value.size >= 32 &&
                        (before & Dependency(value.reg.value));
            }
            after = zero ? after | bit : after & ~bit;
        }
        if (d.instruction.meta.category == ZYDIS_CATEGORY_CALL)
            after &= ~0xf07u;
        const auto append = [&](std::size_t target) {
            if (target >= zero_states.size())
                return;
            const auto merged = zero_states[target] ? *zero_states[target] & after : after;
            if (!zero_states[target] || *zero_states[target] != merged) {
                zero_states[target] = merged;
                zero_pending.push_back(target);
            }
        };
        const auto category = d.instruction.meta.category;
        if (category != ZYDIS_CATEGORY_RET && category != ZYDIS_CATEGORY_UNCOND_BR)
            append(at + 1);
        if ((category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.operands[0].imm.is_relative) {
            const auto target = d.address + d.instruction.length + d.operands[0].imm.value.s;
            const auto found = std::lower_bound(instructions.begin(), instructions.end(), target,
                [](const auto& instruction, auto address) { return instruction.address < address; });
            if (found != instructions.end() && found->address == target)
                append(static_cast<std::size_t>(found - instructions.begin()));
        }
    }
    if (zero_steps >= 16384) {
        if (validation)
            validation("health_zero_provenance_limit", source.begin, zero_steps);
        return std::nullopt;
    }
    std::optional<HealthDescriptor> result;
    for (std::size_t j = 1; j + 4 < instructions.size(); ++j) {
        const auto& first = instructions[j];
        if (first.instruction.mnemonic != ZYDIS_MNEMONIC_CMOVLE ||
            first.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || first.operands[0].size != 32 ||
            first.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER || first.operands[1].size != 32 ||
            !tested(j, first.operands[0].reg.value))
            continue;
        for (std::size_t k = j + 2; k <= j + 4; ++k) {
            const auto& second = instructions[k];
            const auto& following = instructions[k + 1];
            if (second.instruction.mnemonic != ZYDIS_MNEMONIC_CMOVNLE ||
                second.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || second.operands[0].size != 32 ||
                second.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER || second.operands[1].size != 32 ||
                second.operands[0].reg.value != first.operands[1].reg.value ||
                !tested(k, second.operands[1].reg.value))
                continue;
            if (!zero_states[j] || !zero_states[k] ||
                !(*zero_states[j] & Dependency(first.operands[1].reg.value)) ||
                !(*zero_states[k] & Dependency(second.operands[0].reg.value))) {
                if (validation)
                    validation("health_zero_provenance", first.address, 0);
                continue;
            }
            const auto arguments =
                HealthArguments(source, k + 1, first.operands[0].reg.value, second.operands[0].reg.value);
            if (!arguments) {
                if (validation)
                    validation("health_argument_provenance", first.address, 0);
                continue;
            }
            if (result) {
                if (validation)
                    validation("health_clamp_ambiguity", first.address, 0);
                return std::nullopt;
            }
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
    if (validation)
        validation(result ? "health_accepted" : "health_clamp_provenance", source.begin, result ? 1 : 0);
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
    std::map<std::uint64_t, std::optional<Emulator::Program>> callees;
    const NativeResolver resolve = [&](std::uint64_t target) -> std::optional<Emulator::Program> {
        if (const auto found = callees.find(target); found != callees.end())
            return found->second;
        std::optional<Emulator::Program> decoded;
        if (target >= module && target - module >= code_rva && target - module - code_rva < code.size()) {
            const auto offset = static_cast<std::size_t>(target - module - code_rva);
            decoded = Emulator::Decode(
                code.subspan(offset, std::min<std::size_t>(0x200, code.size() - offset)), target, true);
            if (decoded) {
                const auto end = std::find_if(decoded->instructions.begin(), decoded->instructions.end(),
                    [](const auto& d) { return d.instruction.meta.category == ZYDIS_CATEGORY_RET; });
                if (end == decoded->instructions.end())
                    decoded.reset();
                else {
                    decoded->end = end->address + end->instruction.length;
                    decoded->instructions.erase(end + 1, decoded->instructions.end());
                }
            }
        }
        callees.emplace(target, decoded);
        return decoded;
    };
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
        if (bytes.size() < 0x1000 && contains(prefix.first(std::min<std::size_t>(prefix.size(), 96)), 0x1c)) {
            if (checkpoint)
                checkpoint("defuser", index, f);
            auto decoded = Emulator::Decode(bytes, module + f.begin, true);
            unsigned accepted{};
            if (decoded)
                if (auto value = equipment::DefuserOwner(*decoded, validation)) {
                    ++defuser_candidates;
                    accepted = 1;
                    result.defuser = std::move(value);
                }
            if (observer)
                observer("defuser", f, bytes, decoded ? &*decoded : nullptr, accepted);
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
                if (auto value = Health(*decoded, code, code_rva, module, functions, validation))
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
                if (checkpoint)
                    checkpoint("owner profile", index, f);
                const auto owners = result.ownership.size();
                if (auto value = OwnerProfile(*decoded, validation))
                    result.ownership.push_back(std::move(*value));
                if (observer)
                    observer("owner profile", f, bytes, &*decoded, result.ownership.size() - owners);
                if (checkpoint)
                    checkpoint("name", index, f);
                const auto names = result.usernames.size();
                if (auto value = Username(*decoded, code, code_rva, module, functions, validation))
                    result.usernames.push_back(std::move(*value));
                if (observer)
                    observer("name", f, bytes, &*decoded, result.usernames.size() - names);
                if (checkpoint)
                    checkpoint("operator common asset", index, f);
                const auto operators = result.operator_names.size();
                if (auto value = OperatorName(*decoded))
                    result.operator_names.push_back(std::move(*value));
                if (observer)
                    observer("operator common asset", f, bytes, &*decoded,
                        result.operator_names.size() - operators);
            }
        bool array_anchor = false;
        if (bytes.size() > 32 && bytes.size() < 0x10000)
            for (std::size_t j = 0; j + 3 <= bytes.size(); ++j)
                if (bytes[j] == std::byte{0xc1} && (std::to_integer<unsigned>(bytes[j + 1]) & 0xf8) == 0xe0 &&
                    (bytes[j + 2] == std::byte{0x22} || bytes[j + 2] == std::byte{3})) {
                    array_anchor = true;
                    break;
                }
        array_anchor |= bytes.size() > 32 && bytes.size() < 0x10000 && contains(bytes, 0x3fffffff);
        if (array_anchor) {
            if (checkpoint)
                checkpoint("array", index, f);
            const auto before = result.arrays.size();
            auto decoded = Emulator::Decode(bytes, module + f.begin, true);
            if (decoded) {
                auto values = Arrays(*decoded, resolve, bytes, &result.managers);
                for (const auto& extraction : values)
                    for (const auto& d : extraction.code.instructions) {
                        const auto& member = d.operands[1];
                        if (member.type != ZYDIS_OPERAND_TYPE_MEMORY || member.size != 64 ||
                            member.mem.base != extraction.input || member.mem.index != ZYDIS_REGISTER_NONE ||
                            member.mem.disp.value <= 0 || !(member.actions & ZYDIS_OPERAND_ACTION_MASK_READ))
                            continue;
                        const auto found =
                            std::lower_bound(decoded->instructions.begin(), decoded->instructions.end(),
                                d.address, [](const auto& instruction, std::uint64_t at) {
                                    return instruction.address < at;
                                });
                        if (found != decoded->instructions.end() && found->address == d.address)
                            if (auto owner =
                                    Slice(*decoded, found - decoded->instructions.begin(), extraction.input);
                                owner && !owner->inputs)
                                result.managers.push_back(std::move(*owner));
                        break;
                    }
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
                    std::optional<std::uint64_t> context_target;
                    const auto& instructions = decoded->instructions;
                    for (std::size_t j = 0; j + 5 < instructions.size(); ++j) {
                        const auto& call = instructions[j];
                        const auto& test = instructions[j + 1];
                        auto branch_index = j + 2;
                        while (branch_index < instructions.size() && branch_index < j + 6) {
                            const auto& scheduled = instructions[branch_index];
                            if (scheduled.instruction.mnemonic == ZYDIS_MNEMONIC_JZ ||
                                scheduled.instruction.mnemonic == ZYDIS_MNEMONIC_JNZ)
                                break;
                            bool preserved = scheduled.instruction.mnemonic == ZYDIS_MNEMONIC_MOV ||
                                scheduled.instruction.mnemonic == ZYDIS_MNEMONIC_LEA;
                            if (const auto* flags = scheduled.instruction.cpu_flags)
                                preserved &=
                                    !(flags->modified | flags->set_0 | flags->set_1 | flags->undefined);
                            for (unsigned operand = 0; operand < scheduled.instruction.operand_count;
                                ++operand) {
                                const auto& scheduled_operand = scheduled.operands[operand];
                                if (!(scheduled_operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                                    continue;
                                if (scheduled_operand.type == ZYDIS_OPERAND_TYPE_REGISTER)
                                    preserved &= !(Dependency(scheduled_operand.reg.value) &
                                        Dependency(ZYDIS_REGISTER_AL));
                                if (scheduled_operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
                                    preserved &= LocalSlot(scheduled_operand);
                            }
                            if (!preserved)
                                break;
                            ++branch_index;
                        }
                        if (branch_index >= instructions.size())
                            continue;
                        const auto& branch = instructions[branch_index];
                        auto alternate_index = branch_index + 1;
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
                            alternate.instruction.mnemonic != ZYDIS_MNEMONIC_CALL)
                            continue;
                        const auto destination = [&](const auto& jump) -> std::optional<std::size_t> {
                            if (jump.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                                !jump.operands[0].imm.is_relative)
                                return std::nullopt;
                            const auto address =
                                jump.address + jump.instruction.length + jump.operands[0].imm.value.s;
                            const auto found = std::lower_bound(instructions.begin(), instructions.end(),
                                address, [](const auto& item, auto at) { return item.address < at; });
                            if (found == instructions.end() || found->address != address)
                                return std::nullopt;
                            return static_cast<std::size_t>(found - instructions.begin());
                        };
                        auto output_index = alternate_index + 1;
                        const bool shared =
                            instructions[output_index].instruction.mnemonic == ZYDIS_MNEMONIC_JMP;
                        if (shared) {
                            const auto joined = destination(instructions[output_index]);
                            if (!joined)
                                continue;
                            output_index = *joined;
                        }
                        const auto& output = instructions[output_index];
                        if (output.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
                            output.operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                            output.operands[1].reg.value != ZYDIS_REGISTER_RAX)
                            continue;
                        if (shared) {
                            const auto frame = CallerSlot(*decoded, output_index);
                            if (!LocalSlot(output.operands[0]) || output.operands[0].size != 64 ||
                                output.operands[1].size != 64 || output.operands[0].mem.disp.value < 0 ||
                                !frame || output.operands[0].mem.disp.value + 8 > *frame)
                                continue;
                        } else if (instructions[alternate_index + 2].instruction.mnemonic !=
                            ZYDIS_MNEMONIC_JMP) {
                            const auto join = alternate_index + 2;
                            if (output.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                                output.operands[0].size != 64 || output.operands[1].size != 64 ||
                                !Dependency(output.operands[0].reg.value) ||
                                (Dependency(output.operands[0].reg.value) &
                                    (Dependency(ZYDIS_REGISTER_RAX) | Dependency(ZYDIS_REGISTER_RSP))) ||
                                instructions[join].instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
                                instructions[join].operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                                !instructions[join].operands[0].imm.is_relative ||
                                join + 2 >= instructions.size() ||
                                instructions[join + 1].instruction.mnemonic != ZYDIS_MNEMONIC_TEST ||
                                instructions[join + 1].operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                                instructions[join + 1].operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                                instructions[join + 1].operands[0].reg.value != ZYDIS_REGISTER_AL ||
                                instructions[join + 1].operands[1].reg.value != ZYDIS_REGISTER_AL ||
                                (instructions[join + 2].instruction.mnemonic != ZYDIS_MNEMONIC_JZ &&
                                    instructions[join + 2].instruction.mnemonic != ZYDIS_MNEMONIC_JNZ) ||
                                !destination(instructions[join + 2]))
                                continue;
                            const auto common_target = instructions[join].address +
                                instructions[join].instruction.length +
                                instructions[join].operands[0].imm.value.s;
                            if (common_target < module + code_rva ||
                                common_target - module - code_rva >= code.size())
                                continue;
                            const auto zero_path = branch.instruction.mnemonic == ZYDIS_MNEMONIC_JZ
                                ? destination(branch)
                                : std::optional<std::size_t>(branch_index + 1);
                            if (!zero_path)
                                continue;
                            const auto wanted = Dependency(output.operands[0].reg.value);
                            std::vector<unsigned char> states(instructions.size() * 2);
                            bool jumped = false;
                            unsigned visited = 0;
                            const auto reaches = [&](auto&& self, std::size_t at, bool defined) -> bool {
                                if (at == join)
                                    return defined;
                                if (at >= instructions.size())
                                    return false;
                                auto& state = states[at * 2 + defined];
                                if (state)
                                    return state == 2;
                                if (++visited > 512)
                                    return false;
                                state = 1;
                                const auto& d = instructions[at];
                                bool valid = d.instruction.meta.category != ZYDIS_CATEGORY_CALL &&
                                    d.instruction.meta.category != ZYDIS_CATEGORY_RET;
                                for (unsigned k = 0; k < d.instruction.operand_count; ++k) {
                                    const auto& operand = d.operands[k];
                                    if (!(operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                                        continue;
                                    if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
                                        valid &= LocalSlot(operand);
                                    if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER)
                                        valid &=
                                            !(Dependency(operand.reg.value) & Dependency(ZYDIS_REGISTER_RSP));
                                    if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                        (Dependency(operand.reg.value) & wanted)) {
                                        const bool moved = d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                                            d.operands[0].size == 64;
                                        const bool cleared = d.instruction.mnemonic == ZYDIS_MNEMONIC_XOR &&
                                            (d.operands[0].size == 32 || d.operands[0].size == 64) &&
                                            d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                            d.operands[0].reg.value == d.operands[1].reg.value;
                                        valid &= moved || cleared;
                                        defined = true;
                                    }
                                }
                                const auto category = d.instruction.meta.category;
                                if (valid &&
                                    (category == ZYDIS_CATEGORY_COND_BR ||
                                        category == ZYDIS_CATEGORY_UNCOND_BR)) {
                                    const auto target = destination(d);
                                    if (target && *target == join)
                                        jumped = true;
                                    valid = target && self(self, *target, defined);
                                }
                                if (valid && category != ZYDIS_CATEGORY_UNCOND_BR)
                                    valid = self(self, at + 1, defined);
                                state = valid ? 2 : 3;
                                return valid;
                            };
                            if (!reaches(reaches, *zero_path, false) || !jumped)
                                continue;
                        }
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
                            const auto category = leaf->instructions[k].instruction.meta.category;
                            if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_COND_BR ||
                                category == ZYDIS_CATEGORY_UNCOND_BR) {
                                valid = false;
                                break;
                            }
                            if (leaf->instructions[k].instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
                                if (candidate) {
                                    valid = false;
                                    break;
                                }
                                candidate = Slice(*leaf, k, ZYDIS_REGISTER_EAX);
                                if (candidate && candidate->inputs)
                                    candidate = Slice(Simplify(*leaf), k, ZYDIS_REGISTER_EAX);
                                if (candidate && candidate->inputs)
                                    candidate = Slice(Simplify(*leaf, true), k, ZYDIS_REGISTER_EAX);
                            }
                        }
                        if (valid && candidate && !candidate->inputs) {
                            if (context) {
                                if (context_target == target)
                                    continue;
                                context.reset();
                                break;
                            }
                            context = std::move(candidate);
                            context_target = target;
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
    if (defuser_candidates != 1) {
        result.defuser.reset();
        if (checkpoint)
            checkpoint("defuser", functions.size(), {});
        if (validation)
            validation("defuser native candidate count rejected", module, defuser_candidates);
    }
    if (progress)
        progress(functions.size(), functions.size());
    return result;
}

std::vector<Expression> Manager(const Emulator::Program& code) {
    std::vector<Expression> result;
    std::optional<Emulator::Program> normalized;
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
            bool return_cancellation{};
            auto candidate = Trace(code, j + (compare ? 0 : 1), {d.operands[operand].reg.value}, std::nullopt,
                nullptr, &return_cancellation);
            if (!candidate && return_cancellation) {
                if (!normalized)
                    normalized = Simplify(code, true);
                candidate = Slice(*normalized, j + (compare ? 0 : 1), d.operands[operand].reg.value);
            }
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
    for (unsigned proof = 0; proof < 2 && result.empty(); ++proof) {
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
                    shift.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE ? shift.operands[1].imm.value.u
                                                                           : 0);
            if (!vector_load(a) || !vector_load(b) || a.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
                b.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || a.instruction.operand_count_visible != 2 ||
                b.instruction.operand_count_visible != 2 || a.instruction.address_width != 64 ||
                b.instruction.address_width != 64 || a.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                b.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || a.operands[0].size != 128 ||
                b.operands[0].size != 128 || a.operands[1].size != 128 || b.operands[1].size != 128 ||
                ZydisRegisterGetClass(a.operands[0].reg.value) != ZYDIS_REGCLASS_XMM ||
                ZydisRegisterGetClass(b.operands[0].reg.value) != ZYDIS_REGCLASS_XMM ||
                a.operands[1].mem.segment == ZYDIS_REGISTER_FS ||
                a.operands[1].mem.segment == ZYDIS_REGISTER_GS ||
                b.operands[1].mem.segment == ZYDIS_REGISTER_FS ||
                b.operands[1].mem.segment == ZYDIS_REGISTER_GS ||
                a.operands[1].mem.base != b.operands[1].mem.base ||
                a.operands[1].mem.index != b.operands[1].mem.index ||
                ZydisRegisterGetClass(a.operands[1].mem.base) != ZYDIS_REGCLASS_GPR64 ||
                ZydisRegisterGetClass(a.operands[1].mem.index) != ZYDIS_REGCLASS_GPR64 ||
                a.operands[1].mem.base == ZYDIS_REGISTER_RSP || !Dependency(a.operands[1].mem.base) ||
                !Dependency(a.operands[1].mem.index) || a.operands[1].mem.scale != 1 ||
                b.operands[1].mem.scale != 1 || a.operands[1].mem.disp.value != 0 ||
                b.operands[1].mem.disp.value != 16 || shift.instruction.mnemonic != ZYDIS_MNEMONIC_SHL ||
                shift.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || shift.operands[0].size != 64 ||
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
                        d.instruction.mnemonic != ZYDIS_MNEMONIC_TEST &&
                        d.instruction.mnemonic != ZYDIS_MNEMONIC_ADD &&
                        (!proof || d.instruction.mnemonic != ZYDIS_MNEMONIC_XOR)) ||
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
            if (instructions[flag].instruction.mnemonic == ZYDIS_MNEMONIC_ADD || proof) {
                const auto member =
                    instructions[flag]
                        .operands[instructions[flag].instruction.mnemonic == ZYDIS_MNEMONIC_TEST ? 0 : 1];
                for (std::size_t j = flag; j > 0 && a.address - instructions[j - 1].address < 0x800; --j) {
                    const auto& d = instructions[j - 1];
                    bool writes =
                        d.instruction.meta.category == ZYDIS_CATEGORY_CALL && (Dependency(asset) & 0xf07u);
                    for (unsigned k = 0; k < d.instruction.operand_count; ++k) {
                        const auto& o = d.operands[k];
                        writes |= o.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                            (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                            (Dependency(o.reg.value) & Dependency(asset));
                    }
                    if (writes)
                        break;
                    const auto& o = d.operands[d.instruction.mnemonic == ZYDIS_MNEMONIC_TEST ? 0 : 1];
                    const bool member_read = d.instruction.mnemonic == ZYDIS_MNEMONIC_ADD ||
                        (proof &&
                            (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV ||
                                d.instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX ||
                                d.instruction.mnemonic == ZYDIS_MNEMONIC_TEST ||
                                d.instruction.mnemonic == ZYDIS_MNEMONIC_XOR));
                    if (member_read && o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.size == member.size &&
                        o.mem.base == member.mem.base && o.mem.index == ZYDIS_REGISTER_NONE &&
                        o.mem.disp.value == member.mem.disp.value)
                        flag = j - 1;
                }
            }
            const bool xor_flag = instructions[flag].instruction.mnemonic == ZYDIS_MNEMONIC_XOR;
            auto buffer_begin = flag;
            if (xor_flag) {
                if (instructions[flag].operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
                    instructions[flag].operands[0].size != 8 || instructions[flag].operands[1].size != 8 ||
                    Dependency(instructions[flag].operands[0].reg.value) == Dependency(asset))
                    continue;
                for (std::size_t j = flag; j > 0 && a.address - instructions[j - 1].address < 0x800; --j) {
                    const auto& d = instructions[j - 1];
                    bool writes =
                        d.instruction.meta.category == ZYDIS_CATEGORY_CALL && (Dependency(asset) & 0xf07u);
                    for (unsigned operand = 0; operand < d.instruction.operand_count; ++operand) {
                        const auto& o = d.operands[operand];
                        writes |= o.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                            (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                            (Dependency(o.reg.value) & Dependency(asset));
                    }
                    if (!writes)
                        continue;
                    if (d.instruction.mnemonic == ZYDIS_MNEMONIC_XOR && d.operands[0].size == 64 &&
                        d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[1].size == 64)
                        buffer_begin = j;
                    break;
                }
                if (buffer_begin == flag)
                    continue;
            }
            auto buffer = Flow(code, buffer_begin, pair, {asset}, {a.operands[1].mem.base});

            if (!buffer) {
                failed(3, "pose buffer dataflow not proven", a.address);
                continue;
            }

            auto consume = flag;
            auto decoded_asset = asset;
            const bool encoded_flag = instructions[flag].instruction.mnemonic == ZYDIS_MNEMONIC_ADD;
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
                    test.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                    (test.operands[1].imm.value.u != 1 &&
                        (!xor_flag || !std::has_single_bit(test.operands[1].imm.value.u) ||
                            test.operands[1].imm.value.u > 0xffffffffu)) ||
                    conditional.instruction.meta.category != ZYDIS_CATEGORY_COND_BR)
                    continue;
                const auto other = target(conditional);
                if (other >= instructions.size() || other <= branch)
                    continue;
                auto join = instructions.size(), jump = join;
                for (std::size_t j = branch + 1; j < instructions.size() && j < branch + 192; ++j) {
                    if (instructions[j].instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
                        const auto to = target(instructions[j]);
                        if (to > other && (to < flag || (proof && to == flag))) {
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
                            if (to > branch && (to < flag || (proof && to == flag)) && to < other) {
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
                for (unsigned arm = 0; arm < 2; ++arm) {
                    const auto arm_begin = arm ? other : branch + 1;
                    for (std::size_t j = arm_begin; j < (arm ? second_end : first_end); ++j) {
                        const auto& d = instructions[j];
                        for (unsigned k = 0; k < d.instruction.operand_count_visible; ++k) {
                            const auto& o = d.operands[k];
                            if (o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.size == 64 &&
                                (o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) &&
                                o.mem.index == ZYDIS_REGISTER_NONE && o.mem.disp.value > 0 &&
                                Dependency(o.mem.base) && o.mem.base != ZYDIS_REGISTER_RSP) {
                                auto receiver = o.mem.base;
                                if (encoded_flag)
                                    for (std::size_t alias = j;
                                        alias > arm_begin && receiver != ZYDIS_REGISTER_NONE; --alias) {
                                        const auto& previous = instructions[alias - 1];
                                        bool writes =
                                            previous.instruction.meta.category == ZYDIS_CATEGORY_CALL &&
                                            (Dependency(receiver) & 0xf07u);
                                        for (unsigned operand = 0;
                                            operand < previous.instruction.operand_count; ++operand) {
                                            const auto& value = previous.operands[operand];
                                            writes |= value.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                                (value.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                                                (Dependency(value.reg.value) & Dependency(receiver));
                                        }
                                        if (!writes)
                                            continue;
                                        receiver = previous.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                                                previous.operands[0].size == 64 &&
                                                previous.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                                !(previous.operands[0].actions &
                                                    ZYDIS_OPERAND_ACTION_CONDWRITE)
                                            ? previous.operands[1].reg.value
                                            : ZYDIS_REGISTER_NONE;
                                    }
                                if (receiver != ZYDIS_REGISTER_NONE)
                                    fields[arm][receiver].push_back(o.mem.disp.value);
                            }
                        }
                    }
                }
                for (const auto& [receiver, offsets] : fields[0]) {
                    if (!fields[1].contains(receiver))
                        continue;
                    std::size_t start = branch;
                    Location input{receiver};
                    for (std::size_t j = branch - 1;
                        j > 0 && test.address - instructions[j - 1].address < 0x400; --j) {
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

                    const auto selector_end = proof ? buffer_begin : encoded_flag ? flag : consume;
                    const auto selector_output = proof || encoded_flag ? asset : decoded_asset;
                    auto selector = Flow(code, start, selector_end, input, {selector_output});
                    if (!selector && proof && input.stack)
                        selector = Flow(code, start, selector_end, {receiver}, {selector_output});
                    if (selector)
                        result.push_back({std::move(*selector), *buffer});
                }
            }
        }
    }
    if (validation && result.empty())
        validation(reason, reason_at, observed);
    return result;
}
}
