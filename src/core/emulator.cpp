#include "core/emulator.hpp"
#include <algorithm>
#include <bit>
#include <cstring>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace base {
namespace {
struct Fault {
    EmulationStatus status;
};

constexpr std::uint64_t cf = 1, pf = 4, af = 16, zf = 64, sf = 128, of = 2048;

std::uint64_t Mask(unsigned bits) {
    if (!bits || bits > 64)
        throw Fault{EmulationStatus::invalid_operand};
    return bits == 64 ? ~0ull : (1ull << bits) - 1;
}

struct RegisterPart {
    unsigned index, bits, shift;
};

RegisterPart Part(ZydisRegister reg) {
    const auto enclosing = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
    if (ZydisRegisterGetClass(enclosing) != ZYDIS_REGCLASS_GPR64)
        throw Fault{EmulationStatus::invalid_operand};
    const auto id = ZydisRegisterGetId(enclosing);
    const unsigned width = ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, reg);
    if (id < 0 || id >= 16 || !width || width > 64)
        throw Fault{EmulationStatus::invalid_operand};
    const unsigned shift = (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH ||
                               reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH)
        ? 8
        : 0;
    return {static_cast<unsigned>(id), width, shift};
}

bool Contains(std::uint64_t base, std::size_t size, std::uint64_t at, std::size_t bytes) {
    return at >= base && at - base <= size && bytes <= size - static_cast<std::size_t>(at - base);
}
}

std::optional<Emulator::Program> Emulator::Decode(
    std::span<const std::byte> bytes, std::uint64_t address, bool prefix) {
    if (bytes.empty() || bytes.size() > 0x10000 || address > ~0ull - bytes.size())
        return std::nullopt;
    ZydisDecoder decoder{};
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
        return std::nullopt;
    Program result{address, address + bytes.size(), {}};
    for (std::size_t offset = 0; offset < bytes.size();) {
        Decoded instruction{};
        instruction.address = address + offset;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes.data() + offset, bytes.size() - offset,
                &instruction.instruction, instruction.operands.data())) ||
            !instruction.instruction.length) {
            if (!prefix || result.instructions.empty())
                return std::nullopt;
            result.end = address + offset;
            break;
        }
        offset += instruction.instruction.length;
        result.instructions.push_back(instruction);
    }
    return result;
}

void Emulator::Reset(std::uint64_t teb) noexcept {
    registers_.fill(0);
    vectors_.fill({});
    stack_.fill(std::byte{});
    inputs_.clear();
    ip_ = next_ = current_ = 0;
    gs_ = teb;
    flags_ = 2;
    address_width_ = 64;
    registers_[4] = stack_base + 0x8000;
}

void Emulator::Set(ZydisRegister reg, std::uint64_t value) {
    if (ZydisRegisterGetClass(reg) == ZYDIS_REGCLASS_XMM) {
        vectors_.at(ZydisRegisterGetId(reg))[0] = value;
        return;
    }
    const auto r = Part(reg);
    value &= Mask(r.bits);
    auto& destination = registers_[r.index];
    if (r.bits >= 32)
        destination = value;
    else
        destination = (destination & ~(Mask(r.bits) << r.shift)) | (value << r.shift);
}

std::uint64_t Emulator::Get(ZydisRegister reg) const {
    if (ZydisRegisterGetClass(reg) == ZYDIS_REGCLASS_XMM)
        return vectors_.at(ZydisRegisterGetId(reg))[0];
    if (reg == ZYDIS_REGISTER_RIP)
        return next_;
    if (reg == ZYDIS_REGISTER_EIP)
        return static_cast<std::uint32_t>(next_);
    if (reg == ZYDIS_REGISTER_NONE)
        return 0;
    const auto r = Part(reg);
    return (registers_[r.index] >> r.shift) & Mask(r.bits);
}

void Emulator::Stack(std::uint32_t offset, std::uint64_t value) {
    Store(Get(ZYDIS_REGISTER_RSP) + offset, 64, value);
}

std::uint64_t Emulator::Stack(std::uint32_t offset) const {
    return Load(Get(ZYDIS_REGISTER_RSP) + offset, 64);
}

void Emulator::Input(std::uint64_t at, std::span<const std::byte> bytes) {
    if (bytes.empty() || at > ~0ull - bytes.size() ||
        (at < stack_base + stack_.size() && at + bytes.size() > stack_base))
        throw std::invalid_argument("invalid emulator input");
    for (const auto& r : inputs_)
        if (at < r.address + r.bytes.size() && r.address < at + bytes.size())
            throw std::invalid_argument("overlapping emulator input");
    inputs_.push_back({at, bytes});
}

std::uint64_t Emulator::Address(const ZydisDecodedOperand& operand, bool segment) const {
    if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY ||
        (operand.mem.type != ZYDIS_MEMOP_TYPE_MEM && (segment || operand.mem.type != ZYDIS_MEMOP_TYPE_AGEN)))
        throw Fault{EmulationStatus::invalid_operand};
    auto at = Get(operand.mem.base) + Get(operand.mem.index) * operand.mem.scale;
    if (operand.mem.disp.has_displacement)
        at += static_cast<std::uint64_t>(operand.mem.disp.value);
    at &= Mask(address_width_);
    if (segment) {
        if (operand.mem.segment == ZYDIS_REGISTER_GS)
            at += gs_;
        else if (operand.mem.segment == ZYDIS_REGISTER_FS)
            throw Fault{EmulationStatus::unsupported};
    }
    return at;
}

std::uint64_t Emulator::Load(std::uint64_t at, unsigned bits) const {
    if (bits % 8)
        throw Fault{EmulationStatus::invalid_operand};
    const auto bytes = bits / 8;
    Mask(bits);
    std::uint64_t result{};
    const auto report = [&](DWORD error, bool supplied = false, bool stack = false) {
        if (observer_.read)
            observer_.read(observer_.context, {current_, at, result, bits, error, supplied, stack});
    };
    if (Contains(stack_base, stack_.size(), at, bytes)) {
        std::memcpy(&result, stack_.data() + at - stack_base, bytes);
        report(ERROR_SUCCESS, false, true);
    } else {
        const auto found = std::find_if(inputs_.begin(), inputs_.end(),
            [&](const Region& r) { return Contains(r.address, r.bytes.size(), at, bytes); });
        if (found != inputs_.end()) {
            std::memcpy(&result, found->bytes.data() + at - found->address, bytes);
            report(ERROR_SUCCESS, true);
        } else {
            if (at <= 0x1000 || at >= 0x800000000000ull || bytes > 0x800000000000ull - at ||
                (at < stack_base + stack_.size() && at + bytes > stack_base)) {
                report(ERROR_INVALID_ADDRESS);
                throw Fault{EmulationStatus::read_failed};
            }
            const auto got = process_.ReadBytes(
                static_cast<std::uintptr_t>(at), std::as_writable_bytes(std::span(&result, 1)).first(bytes));
            report(got.error);
            if (!got.Complete())
                throw Fault{EmulationStatus::read_failed};
        }
    }
    return result;
}

void Emulator::Store(std::uint64_t at, unsigned bits, std::uint64_t value) {
    if (bits % 8)
        throw Fault{EmulationStatus::invalid_operand};
    const auto bytes = bits / 8;
    Mask(bits);
    if (!Contains(stack_base, stack_.size(), at, bytes))
        throw Fault{EmulationStatus::write_blocked};
    std::memcpy(stack_.data() + at - stack_base, &value, bytes);
}

std::uint64_t Emulator::Value(const ZydisDecodedOperand& operand) const {
    switch (operand.type) {
    case ZYDIS_OPERAND_TYPE_REGISTER:
        return Get(operand.reg.value);
    case ZYDIS_OPERAND_TYPE_MEMORY:
        return Load(Address(operand), operand.size);
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        if (operand.imm.is_relative)
            return next_ + static_cast<std::uint64_t>(operand.imm.value.s);
        return operand.imm.value.u;
    default:
        throw Fault{EmulationStatus::invalid_operand};
    }
}

void Emulator::Write(const ZydisDecodedOperand& operand, std::uint64_t value) {
    if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER)
        Set(operand.reg.value, value);
    else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
        Store(Address(operand), operand.size, value);
    else
        throw Fault{EmulationStatus::invalid_operand};
}

void Emulator::Logical(std::uint64_t result, unsigned bits) {
    result &= Mask(bits);
    flags_ &= ~(cf | of | sf | zf | pf | af);
    if (!result)
        flags_ |= zf;
    if (result & (1ull << (bits - 1)))
        flags_ |= sf;
    if ((std::popcount(static_cast<unsigned>(result & 0xff)) & 1) == 0)
        flags_ |= pf;
}

void Emulator::Arithmetic(
    std::uint64_t a, std::uint64_t b, std::uint64_t result, unsigned bits, bool subtract) {
    const auto limit = Mask(bits), sign = 1ull << (bits - 1);
    a &= limit;
    b &= limit;
    result &= limit;
    Logical(result, bits);
    if (subtract ? a < b : result < a)
        flags_ |= cf;
    if (((subtract ? (a ^ b) : ~(a ^ b)) & (a ^ result) & sign) != 0)
        flags_ |= of;
    if ((a ^ b ^ result) & 0x10)
        flags_ |= af;
}

std::optional<bool> Emulator::Condition(ZydisMnemonic m) const {
    const bool c = (flags_ & cf) != 0, z = (flags_ & zf) != 0, s = (flags_ & sf) != 0, o = (flags_ & of) != 0,
               p = (flags_ & pf) != 0;
    switch (m) {
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_CMOVB:
    case ZYDIS_MNEMONIC_SETB:
        return c;
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_CMOVBE:
    case ZYDIS_MNEMONIC_SETBE:
        return c || z;
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_CMOVNB:
    case ZYDIS_MNEMONIC_SETNB:
        return !c;
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_CMOVNBE:
    case ZYDIS_MNEMONIC_SETNBE:
        return !c && !z;
    case ZYDIS_MNEMONIC_JZ:
    case ZYDIS_MNEMONIC_CMOVZ:
    case ZYDIS_MNEMONIC_SETZ:
        return z;
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_CMOVNZ:
    case ZYDIS_MNEMONIC_SETNZ:
        return !z;
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_CMOVS:
    case ZYDIS_MNEMONIC_SETS:
        return s;
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_CMOVNS:
    case ZYDIS_MNEMONIC_SETNS:
        return !s;
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_CMOVO:
    case ZYDIS_MNEMONIC_SETO:
        return o;
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_CMOVNO:
    case ZYDIS_MNEMONIC_SETNO:
        return !o;
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_CMOVP:
    case ZYDIS_MNEMONIC_SETP:
        return p;
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_CMOVNP:
    case ZYDIS_MNEMONIC_SETNP:
        return !p;
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_CMOVL:
    case ZYDIS_MNEMONIC_SETL:
        return s != o;
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_CMOVNL:
    case ZYDIS_MNEMONIC_SETNL:
        return s == o;
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_CMOVLE:
    case ZYDIS_MNEMONIC_SETLE:
        return z || s != o;
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_CMOVNLE:
    case ZYDIS_MNEMONIC_SETNLE:
        return !z && s == o;
    default:
        return std::nullopt;
    }
}

void Emulator::Step(const Decoded& d) {
    const auto& i = d.instruction;
    const auto& x = d.operands[0];
    const auto& y = d.operands[1];
    const auto m = i.mnemonic;
    if (i.attributes &
        (ZYDIS_ATTRIB_HAS_LOCK | ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE))
        throw Fault{EmulationStatus::unsupported};
    if (const auto take = Condition(m)) {
        if (i.meta.category == ZYDIS_CATEGORY_COND_BR) {
            if (*take)
                ip_ = Value(x);
        } else if (i.meta.category == ZYDIS_CATEGORY_CMOV) {
            const auto source = Value(y);
            if (*take)
                Write(x, source);
            else if (x.type == ZYDIS_OPERAND_TYPE_REGISTER && x.size == 32)
                Write(x, Value(x));
        } else if (i.meta.category == ZYDIS_CATEGORY_SETCC)
            Write(x, *take ? 1 : 0);
        else
            throw Fault{EmulationStatus::unsupported};
        return;
    }
    switch (m) {
    case ZYDIS_MNEMONIC_XORPS: {
        if (x.type != ZYDIS_OPERAND_TYPE_REGISTER || ZydisRegisterGetClass(x.reg.value) != ZYDIS_REGCLASS_XMM)
            throw Fault{EmulationStatus::invalid_operand};
        auto& target = vectors_.at(ZydisRegisterGetId(x.reg.value));
        const auto source = y.type == ZYDIS_OPERAND_TYPE_REGISTER
            ? vectors_.at(ZydisRegisterGetId(y.reg.value))
            : std::array<std::uint64_t, 2>{Load(Address(y), 64), Load(Address(y) + 8, 64)};
        target[0] ^= source[0];
        target[1] ^= source[1];
        return;
    }
    case ZYDIS_MNEMONIC_MOVAPS:
    case ZYDIS_MNEMONIC_MOVUPS: {
        std::array<std::uint64_t, 2> data{};
        if (y.type == ZYDIS_OPERAND_TYPE_REGISTER && ZydisRegisterGetClass(y.reg.value) == ZYDIS_REGCLASS_XMM)
            data = vectors_.at(ZydisRegisterGetId(y.reg.value));
        else if (y.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            const auto at = Address(y);
            data = {Load(at, 64), Load(at + 8, 64)};
        } else
            throw Fault{EmulationStatus::invalid_operand};
        if (x.type == ZYDIS_OPERAND_TYPE_REGISTER && ZydisRegisterGetClass(x.reg.value) == ZYDIS_REGCLASS_XMM)
            vectors_.at(ZydisRegisterGetId(x.reg.value)) = data;
        else if (x.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            const auto at = Address(x);
            Store(at, 64, data[0]);
            Store(at + 8, 64, data[1]);
        } else
            throw Fault{EmulationStatus::invalid_operand};
        return;
    }
    case ZYDIS_MNEMONIC_MOVD:
    case ZYDIS_MNEMONIC_MOVSS: {
        const auto data = y.type == ZYDIS_OPERAND_TYPE_MEMORY ? Load(Address(y), 32) : Value(y) & 0xffffffffu;
        if (x.type == ZYDIS_OPERAND_TYPE_MEMORY)
            Store(Address(x), 32, data);
        else if (ZydisRegisterGetClass(x.reg.value) == ZYDIS_REGCLASS_XMM) {
            auto& v = vectors_.at(ZydisRegisterGetId(x.reg.value));
            if (m == ZYDIS_MNEMONIC_MOVD || y.type == ZYDIS_OPERAND_TYPE_MEMORY)
                v = {};
            v[0] = (v[0] & 0xffffffff00000000ull) | data;
        } else
            Write(x, data);
        return;
    }
    case ZYDIS_MNEMONIC_CVTSI2SS: {
        const auto integer = Value(y);
        const float f = y.size == 64 ? static_cast<float>(static_cast<std::int64_t>(integer))
                                     : static_cast<float>(static_cast<std::int32_t>(integer));
        auto& v = vectors_.at(ZydisRegisterGetId(x.reg.value))[0];
        v = (v & 0xffffffff00000000ull) | std::bit_cast<std::uint32_t>(f);
        return;
    }
    case ZYDIS_MNEMONIC_CVTTSS2SI: {
        const float f = std::bit_cast<float>(static_cast<std::uint32_t>(
            y.type == ZYDIS_OPERAND_TYPE_MEMORY ? Load(Address(y), 32) : Value(y)));
        const double limit = x.size == 64 ? 9223372036854775808.0 : 2147483648.0;
        Write(x,
            !std::isfinite(f) || f < -limit || f >= limit
                ? (x.size == 64 ? 0x8000000000000000ull : 0x80000000ull)
                : static_cast<std::uint64_t>(static_cast<std::int64_t>(std::trunc(f))));
        return;
    }
    case ZYDIS_MNEMONIC_MULSS:
    case ZYDIS_MNEMONIC_DIVSS:
    case ZYDIS_MNEMONIC_ADDSS:
    case ZYDIS_MNEMONIC_SUBSS: {
        const float a = std::bit_cast<float>(static_cast<std::uint32_t>(Value(x)));
        const float b = std::bit_cast<float>(static_cast<std::uint32_t>(
            y.type == ZYDIS_OPERAND_TYPE_MEMORY ? Load(Address(y), 32) : Value(y)));
        const float f = m == ZYDIS_MNEMONIC_MULSS ? a * b
            : m == ZYDIS_MNEMONIC_DIVSS           ? a / b
            : m == ZYDIS_MNEMONIC_ADDSS           ? a + b
                                                  : a - b;
        auto& v = vectors_.at(ZydisRegisterGetId(x.reg.value))[0];
        v = (v & 0xffffffff00000000ull) | std::bit_cast<std::uint32_t>(f);
        return;
    }
    case ZYDIS_MNEMONIC_NOP:
    case ZYDIS_MNEMONIC_PAUSE:
        return;
    case ZYDIS_MNEMONIC_MOV:
        Write(x, Value(y));
        return;
    case ZYDIS_MNEMONIC_MOVZX:
        Write(x, Value(y) & Mask(y.size));
        return;
    case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_MOVSXD: {
        const auto source = Value(y), sign = 1ull << (y.size - 1);
        Write(x, (source ^ sign) - sign);
        return;
    }
    case ZYDIS_MNEMONIC_LEA:
        Write(x, Address(y, false));
        return;
    case ZYDIS_MNEMONIC_PUSH: {
        const auto source = Value(x), sp = Get(ZYDIS_REGISTER_RSP) - (x.size == 16 ? 2 : 8);
        Store(sp, x.size == 16 ? 16 : 64, source);
        Set(ZYDIS_REGISTER_RSP, sp);
        return;
    }
    case ZYDIS_MNEMONIC_POP: {
        const auto sp = Get(ZYDIS_REGISTER_RSP);
        const unsigned bits = x.size == 16 ? 16 : 64;
        const auto source = Load(sp, bits);
        Set(ZYDIS_REGISTER_RSP, sp + bits / 8);
        Write(x, source);
        return;
    }
    case ZYDIS_MNEMONIC_JMP:
        ip_ = Value(x);
        return;
    case ZYDIS_MNEMONIC_CALL: {
        const auto target = Value(x), sp = Get(ZYDIS_REGISTER_RSP) - 8;
        Store(sp, 64, next_);
        Set(ZYDIS_REGISTER_RSP, sp);
        ip_ = target;
        return;
    }
    case ZYDIS_MNEMONIC_RET: {
        const auto sp = Get(ZYDIS_REGISTER_RSP);
        ip_ = Load(sp, 64);
        Set(ZYDIS_REGISTER_RSP, sp + 8 + (i.operand_count_visible ? Value(x) : 0));
        return;
    }
    case ZYDIS_MNEMONIC_JRCXZ:
        if (!Get(ZYDIS_REGISTER_RCX))
            ip_ = Value(x);
        return;
    case ZYDIS_MNEMONIC_JECXZ:
        if (!Get(ZYDIS_REGISTER_ECX))
            ip_ = Value(x);
        return;
    case ZYDIS_MNEMONIC_NOT:
        Write(x, ~Value(x));
        return;
    case ZYDIS_MNEMONIC_NEG: {
        const auto a = Value(x);
        Arithmetic(0, a, 0 - a, x.size, true);
        Write(x, 0 - a);
        return;
    }
    case ZYDIS_MNEMONIC_INC:
    case ZYDIS_MNEMONIC_DEC: {
        const auto a = Value(x), result = m == ZYDIS_MNEMONIC_INC ? a + 1 : a - 1, carry = flags_ & cf;
        Arithmetic(a, 1, result, x.size, m == ZYDIS_MNEMONIC_DEC);
        flags_ = (flags_ & ~cf) | carry;
        Write(x, result);
        return;
    }
    case ZYDIS_MNEMONIC_ADC:
    case ZYDIS_MNEMONIC_SBB: {
        const auto a = Value(x) & Mask(x.size), b = Value(y) & Mask(x.size), carry = flags_ & cf;
        const bool subtract = m == ZYDIS_MNEMONIC_SBB;
        const auto result = (subtract ? a - b - carry : a + b + carry) & Mask(x.size);
        Arithmetic(a, b, result, x.size, subtract);
        flags_ &= ~cf;
        if (subtract ? a < b || (carry && a == b) : result < a || (carry && result == a))
            flags_ |= cf;
        Write(x, result);
        return;
    }
    case ZYDIS_MNEMONIC_ADD:
    case ZYDIS_MNEMONIC_SUB:
    case ZYDIS_MNEMONIC_CMP: {
        const auto a = Value(x), b = Value(y);
        const bool subtract = m != ZYDIS_MNEMONIC_ADD;
        const auto result = subtract ? a - b : a + b;
        Arithmetic(a, b, result, x.size, subtract);
        if (m != ZYDIS_MNEMONIC_CMP)
            Write(x, result);
        return;
    }
    case ZYDIS_MNEMONIC_AND:
    case ZYDIS_MNEMONIC_OR:
    case ZYDIS_MNEMONIC_XOR:
    case ZYDIS_MNEMONIC_TEST: {
        const auto a = Value(x), b = Value(y),
                   result = m == ZYDIS_MNEMONIC_OR ? a | b
            : m == ZYDIS_MNEMONIC_XOR              ? a ^ b
                                                   : a & b;
        Logical(result, x.size);
        if (m != ZYDIS_MNEMONIC_TEST)
            Write(x, result);
        return;
    }
    case ZYDIS_MNEMONIC_IMUL: {
        if (i.operand_count_visible < 2 || i.operand_count_visible > 3)
            throw Fault{EmulationStatus::unsupported};
        const auto a = i.operand_count_visible == 3 ? Value(y) : Value(x),
                   b = i.operand_count_visible == 3 ? Value(d.operands[2]) : Value(y);
        Write(x, a * b);
        flags_ &= ~(cf | of);
        const auto sign = 1ull << (x.size - 1), limit = Mask(x.size);
        const auto magnitude = [&](std::uint64_t v) {
            v &= limit;
            return (v & sign) ? ((~v + 1) & limit) : v;
        };
        const auto aa = magnitude(a), bb = magnitude(b), maximum = ((a ^ b) & sign) ? sign : sign - 1;
        if (bb && aa > maximum / bb)
            flags_ |= cf | of;
        return;
    }
    case ZYDIS_MNEMONIC_SHL:
    case ZYDIS_MNEMONIC_SHR:
    case ZYDIS_MNEMONIC_SAR:
    case ZYDIS_MNEMONIC_ROL:
    case ZYDIS_MNEMONIC_ROR: {
        const unsigned bits = x.size;
        const auto limit = Mask(bits), a = Value(x) & limit;
        auto count = static_cast<unsigned>(Value(y) & (bits == 64 ? 63 : 31));
        const bool rotate = m == ZYDIS_MNEMONIC_ROL || m == ZYDIS_MNEMONIC_ROR;
        if (rotate)
            count %= bits;
        if (!count)
            return;
        std::uint64_t result{}, carry{};
        const auto old_sign = (a >> (bits - 1)) & 1;
        if (rotate) {
            result = m == ZYDIS_MNEMONIC_ROL ? ((a << count) | (a >> (bits - count)))
                                             : ((a >> count) | (a << (bits - count)));
            result &= limit;
            carry = m == ZYDIS_MNEMONIC_ROL ? result & 1 : (result >> (bits - 1)) & 1;
            flags_ = (flags_ & ~cf) | (carry ? cf : 0);
        } else {
            if (count > bits)
                throw Fault{EmulationStatus::unsupported};
            if (m == ZYDIS_MNEMONIC_SHL) {
                carry = (a >> (bits - count)) & 1;
                result = count == 64 ? 0 : a << count;
            } else {
                carry = (a >> (count - 1)) & 1;
                result = count == 64 ? 0 : a >> count;
                if (m == ZYDIS_MNEMONIC_SAR && old_sign)
                    result |= limit ^ (count >= bits ? 0 : Mask(bits - count));
            }
            Logical(result, bits);
            if (carry)
                flags_ |= cf;
        }
        if (count == 1) {
            bool overflow{};
            if (m == ZYDIS_MNEMONIC_SHR)
                overflow = old_sign != 0;
            else if (m == ZYDIS_MNEMONIC_ROL || m == ZYDIS_MNEMONIC_SHL)
                overflow = ((result >> (bits - 1)) & 1) != carry;
            else if (m == ZYDIS_MNEMONIC_ROR)
                overflow = (((result >> (bits - 1)) ^ (result >> (bits - 2))) & 1) != 0;
            flags_ = (flags_ & ~of) | (overflow ? of : 0);
        }
        Write(x, result);
        return;
    }
    default:
        throw Fault{EmulationStatus::unsupported};
    }
}

EmulationResult Emulator::Run(const Program& code, std::size_t budget) {
    if (code.linear) {
        EmulationResult result{EmulationStatus::complete, code.begin, ZYDIS_MNEMONIC_INVALID, 0};
        for (const auto& instruction : code.instructions) {
            result.address = instruction.address;
            result.mnemonic = instruction.instruction.mnemonic;
            if (result.steps >= budget) {
                result.status = EmulationStatus::budget_exhausted;
                return result;
            }
            next_ = instruction.address + instruction.instruction.length;
            current_ = instruction.address;
            ip_ = next_;
            address_width_ = instruction.instruction.address_width;
            ++result.steps;
            try {
                Step(instruction);
            } catch (Fault f) {
                result.status = f.status;
                return result;
            }
            if (ip_ != next_) {
                result.status = EmulationStatus::control_flow;
                return result;
            }
        }
        result.address = code.end;
        return result;
    }
    ip_ = code.begin;
    EmulationResult result{EmulationStatus::complete, ip_, ZYDIS_MNEMONIC_INVALID, 0};
    while (ip_ != code.end) {
        result.address = ip_;
        if (result.steps >= budget) {
            result.status = EmulationStatus::budget_exhausted;
            return result;
        }
        const auto found = std::lower_bound(code.instructions.begin(), code.instructions.end(), ip_,
            [](const Decoded& d, std::uint64_t at) { return d.address < at; });
        if (found == code.instructions.end() || found->address != ip_) {
            result.status = EmulationStatus::control_flow;
            return result;
        }
        result.mnemonic = found->instruction.mnemonic;
        next_ = ip_ + found->instruction.length;
        current_ = found->address;
        ip_ = next_;
        address_width_ = found->instruction.address_width;
        ++result.steps;
        try {
            Step(*found);
        } catch (Fault f) {
            result.status = f.status;
            return result;
        }
        if (code.sparse && ip_ != code.end) {
            const auto next = std::lower_bound(code.instructions.begin(), code.instructions.end(), ip_,
                [](const Decoded& d, std::uint64_t at) { return d.address < at; });
            if (next == code.instructions.end()) {
                result.status = EmulationStatus::control_flow;
                return result;
            }
            ip_ = next->address;
        }
    }
    result.address = ip_;
    return result;
}
}
