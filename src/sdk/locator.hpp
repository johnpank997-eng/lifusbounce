#pragma once
#include <Zydis/Zydis.h>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <stop_token>
#include "core/emulator.hpp"
#include "sdk/equipment.hpp"

namespace base::sdk::locators {
struct Expression {
    Emulator::Program code;
    ZydisRegister output = ZYDIS_REGISTER_NONE;
    std::uint32_t inputs{};
};

struct Location {
    ZydisRegister reg = ZYDIS_REGISTER_NONE;
    std::int64_t slot{};
    bool stack{};
};

struct Seed {
    Location target;
    Expression value;
};

struct PointerDescriptor {
    Emulator::Program code;
    Location input, output;
    std::vector<Seed> seeds;
};

[[nodiscard]] std::optional<PointerDescriptor> Flow(
    const Emulator::Program& code, std::size_t begin, std::size_t end, Location input, Location output);
[[nodiscard]] std::optional<Expression> Slice(
    const Emulator::Program& code, std::size_t before, ZydisRegister output);
[[nodiscard]] std::optional<equipment::ResourcePath> WeaponResource(const Emulator::Program& code);

struct SerializedMember {
    Expression data, descriptor;
    std::uint64_t dispatcher{};
};

[[nodiscard]] std::vector<SerializedMember> SerializedMembers(const Emulator::Program& code);
[[nodiscard]] std::optional<std::uint32_t> SerializationCodecField(const Emulator::Program& code);
[[nodiscard]] std::optional<std::uint64_t> InlineNameCodec(const Emulator::Program& code);
[[nodiscard]] bool InlineStringCodec(const Emulator::Program& code);

struct MetadataDescriptor {
    Expression decode;
    std::uint32_t table_field{}, hash_field{};
};

[[nodiscard]] std::optional<MetadataDescriptor> Metadata(const Emulator::Program& code);
[[nodiscard]] std::optional<Expression> Root(const Emulator::Program& code);
[[nodiscard]] std::optional<Expression> Camera(const Emulator::Program& code);
[[nodiscard]] std::vector<Expression> Manager(const Emulator::Program& code);

struct FunctionRecord {
    std::uint32_t begin{}, end{}, unwind{};
};

struct ArrayDescriptor {
    Emulator::Program code;
    ZydisRegister input = ZYDIS_REGISTER_NONE, array = ZYDIS_REGISTER_NONE, count = ZYDIS_REGISTER_NONE;
};

struct PoseDescriptor {
    PointerDescriptor asset, buffer;
};

struct UsernameDescriptor {
    Expression owner, profile;
    std::uint64_t owner_type{}, profile_type{};
    std::uint32_t string_field{};
};

struct HealthDescriptor {
    Emulator::Program code;
    ZydisRegister maximum{}, current{};
};

struct OperatorSelectionDescriptor {
    PointerDescriptor instance, definition;
    std::uint32_t instance_field{}, definition_field{};
    std::uint64_t consumer{}, definition_type{};
};

struct OperatorNameDescriptor {
    PointerDescriptor reference;
    std::uint32_t field{};
    std::uint64_t consumer{}, target_type{};
};

[[nodiscard]] std::optional<OperatorSelectionDescriptor> OperatorSelection(const Emulator::Program& consumer,
    std::span<const std::byte> code, std::uint32_t code_rva, std::uint64_t module,
    std::span<const FunctionRecord> functions, std::uint64_t missing_instance_string);
[[nodiscard]] std::optional<OperatorNameDescriptor> OperatorName(const Emulator::Program& getter);

struct AffiliationDescriptor {
    Expression object;
    ZydisRegister profile = ZYDIS_REGISTER_NONE;
    std::uint32_t field{};
    std::uint64_t null_value{};
    bool pointer_identity = true;
};

[[nodiscard]] std::vector<ArrayDescriptor> Arrays(const Emulator::Program& code);
[[nodiscard]] std::vector<PoseDescriptor> Poses(const Emulator::Program& code);

struct NativeDescriptor {
    std::vector<FunctionRecord> functions;
    std::vector<Expression> roots, cameras, managers, contexts, rigs;
    std::vector<MetadataDescriptor> metadata;
    std::vector<ArrayDescriptor> arrays;
    std::vector<PoseDescriptor> poses;
    std::vector<UsernameDescriptor> usernames;
    std::vector<HealthDescriptor> health;
    std::vector<AffiliationDescriptor> affiliations;
    std::optional<std::uint32_t> local_profile_field;
    std::optional<equipment::OwnershipPath> defuser;
    std::vector<OperatorNameDescriptor> operator_names;
    std::optional<OperatorSelectionDescriptor> selected_operator;
};

[[nodiscard]] std::optional<OperatorSelectionDescriptor> DiscoverOperatorSelection(
    std::span<const std::byte> code, std::uint32_t code_rva, std::uint64_t module,
    std::span<const FunctionRecord> functions, std::span<const std::byte> rdata, std::uint32_t rdata_rva);

[[nodiscard]] NativeDescriptor Discover(std::span<const std::byte> code, std::uint32_t code_rva,
    std::uint64_t module, std::span<const FunctionRecord> functions, std::stop_token stop,
    const std::function<void(std::size_t, std::size_t)>& progress = {});

}
