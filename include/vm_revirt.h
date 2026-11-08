#pragma once
// NovaProtect — revirtualization ("secondary virtualization") on-disk contract
// ==========================================================================
// EnableRevirtualization turns the single-level wire VM into a two-level one:
//
//   outer stage stream   one keystreamed bytecode block per *stage*, each with
//                        its own key, its own region salt and its own opcode
//                        permutation (Themida: RelocateStages / MergeStages).
//   inner guest stages   the instruction semantics themselves are lifted out of
//                        the stage stream into second-level blocks that carry
//                        an extra register permutation and are executed by a
//                        second dispatcher with its own handler table
//                        (Themida: EnableRevirtualization / UsingMicroRegs).
//
// Everything below is a byte layout that MUST stay in sync with
// runtime/prot64.c. The runtime is freestanding C and cannot include this
// header, so the layouts are duplicated there with the same offsets.
//
// ---------------------------------------------------------------- stage table
// One entry per outer stage, 24 bytes, little endian, emitted into the NPP1
// payload data area at the offset the region record stores at +28:
//
//   +0  u32 bc_off    payload-relative offset of the stage's bytecode
//   +4  u32 bc_len
//   +8  u32 rev_off   payload-relative offset of this stage's 256-byte reverse
//                     table (every stage permutes opcodes independently)
//   +12 u64 key       this stage's keystream key
//   +20 u32 rva       region salt folded into the keystream
//
// A stage boundary is only ever placed where no branch crosses it, so an outer
// stage is a self-contained instruction range with no external edges.
//
// ------------------------------------------------------- guest stage descriptor
// One entry per inner block, 32 bytes, emitted immediately after the region
// record table:
//
//   +0  u32 bc_off        payload-relative offset of the guest bytecode
//   +4  u32 bc_len
//   +8  u32 rev_off       payload-relative offset of the guest reverse table
//   +12 u32 reg_perm_off  payload-relative offset of this block's 16-byte
//                         register permutation (kept for offline tooling; the
//                         operands inside bc_off are already permuted)
//   +16 u64 key           independent guest keystream key
//   +24 u32 rva           independent guest keystream salt
//   +28 u32 flags         bit0        = block is live
//                         bits 8..23  = writeMask: the outer registers the
//                                       block assigns, copied back on return
//                         bits 24..27 = nesting level: 1 for a block lifted
//                                       out of an outer stage, 2 for one lifted
//                                       out of such a block, and so on
//
// The outer stream reaches a guest block with WIRE_GSTAGE <index>, whose
// operand is the 0-based index into this table. A guest block reaches its own
// children through the same instruction and the same table, so the whole
// nested tree is one flat index-addressed array: the level belongs to a
// descriptor, not to a separate table per level.
//
// ------------------------------------------------------------- region record
// The 32-byte record the packer has always emitted stays byte compatible. The
// two formerly reserved words carry the extension:
//
//   +24 u32 stage_count   0 = legacy single-stage region (key and RVA live in
//                         the trailer behind the reverse table, exactly as
//                         before); >= 1 = stage table at +28 is authoritative
//   +28 u32 stage_table_off
//
// --------------------------------------------------------------- header field
// The high half of the old reserved2 word (+92) holds the guest block count.

#include <cstdint>
#include <cstddef>
#include <vector>

namespace np {

// Outer stage table entry.
struct VmStageEntry {
    uint32_t bc_off = 0;
    uint32_t bc_len = 0;
    uint32_t rev_off = 0;
    uint64_t key = 0;
    uint32_t rva = 0;
};
constexpr size_t kVmStageEntrySize = 24;

// Inner (guest) block descriptor.
struct VmGuestStage {
    uint32_t bc_off = 0;
    uint32_t bc_len = 0;
    uint32_t rev_off = 0;
    uint32_t reg_perm_off = 0;
    uint64_t key = 0;
    uint32_t rva = 0;
    uint32_t flags = 0;
};
constexpr size_t kVmGuestStageSize = 32;
constexpr uint32_t kVmGuestFlagLive = 1u;
// Descriptor flag layout shared with runtime/prot64.c.
constexpr uint32_t kVmGuestWriteMaskShift = 8;
constexpr uint32_t kVmGuestWriteMaskBits  = 16;
constexpr uint32_t kVmGuestLevelShift     = 24;
constexpr uint32_t kVmGuestLevelBits      = 4;
constexpr uint32_t kVmGuestLevelMask =
    ((1u << kVmGuestLevelBits) - 1u) << kVmGuestLevelShift;

inline uint32_t vmGuestPackFlags(uint32_t writeMask, uint32_t level) {
    const uint32_t mask = writeMask & ((1u << kVmGuestWriteMaskBits) - 1u);
    const uint32_t lvl = (level << kVmGuestLevelShift) & kVmGuestLevelMask;
    return kVmGuestFlagLive | (mask << kVmGuestWriteMaskShift) | lvl;
}
inline uint32_t vmGuestWriteMaskOf(uint32_t flags) {
    return (flags >> kVmGuestWriteMaskShift) & ((1u << kVmGuestWriteMaskBits) - 1u);
}
inline uint32_t vmGuestLevelOf(uint32_t flags) {
    return (flags & kVmGuestLevelMask) >> kVmGuestLevelShift;
}

// Region record extension offsets (inside the 32-byte record).
constexpr size_t kRegionStageCountOff = 24;
constexpr size_t kRegionStageTableOff = 28;

// NPP1 header slot for the guest block count.
constexpr size_t kNppGuestCountOff = 92;
constexpr size_t kNppVmCountOff = 88;
constexpr size_t kNppVmDescOff = 20;

// A stage or guest block must hold at least this much bytecode; below it the
// per-stage overhead (key, reverse table, salt) costs more than it hides.
constexpr uint32_t kMinStageBytes = 24;

// Hard ceiling that matches NP_VM_GUEST_MAX / NP_VM_GUEST_DEPTH in
// runtime/prot64.c. The runtime refuses to descend past the depth limit, so the
// packer must never emit a level above it.
constexpr uint32_t kMaxGuestStages = 96;
constexpr uint32_t kMaxStagesPerRegion = 32;
constexpr uint32_t kMaxGuestDepth = 8;

// ------------------------------------------------------------ packer-side types
// One outer stage produced by vmSplitStages(). `bc` is already encoded with
// `mapping` (logical -> physical) so the same bytes the runtime decodes are the
// bytes that were analysed; `reverse` is the matching physical -> logical table
// the runtime is handed. Branch targets inside `bc` are stage-relative.
struct VmStage {
    std::vector<uint8_t> bc;
    uint8_t mapping[256] = {0};
    uint8_t reverse[256] = {0};
    uint64_t key = 0;
    uint32_t rva = 0;      // stage-relative salt (stage base offset)
    uint32_t base = 0;     // stream offset the stage starts at, for diagnostics
};

// One inner block produced by vmLiftGuestBlocks(). Operands are already
// permuted through `regPerm`; `bc` ends with its own WIRE_HALT. `level` is 1 for
// a block lifted out of an outer stage and increments for every further nesting
// level, so one flat guest table can describe the whole tree.
struct VmGuestBlock {
    std::vector<uint8_t> bc;
    uint8_t mapping[256] = {0};
    uint8_t reverse[256] = {0};
    uint8_t regPerm[16] = {0};
    uint64_t key = 0;
    uint32_t rva = 0;
    uint32_t flags = 0;
    uint32_t level = 1;
    // Outer registers the block assigns, as a bitmask. The runtime copies only
    // these back after the guest run, so a block cannot clobber a register its
    // own instructions never mention.
    uint32_t writeMask = 0;
    size_t firstInsn = 0;   // index into the stage's instruction stream
    size_t lastInsn = 0;    // exclusive
};

// Cut `bc` into stage streams that no branch crosses. Returns false (leaving
// `out` empty) when the program is too short or contains a branch target that
// does not land on an instruction boundary; the caller then keeps the legacy
// single-stage form.
bool vmSplitStages(const std::vector<uint8_t>& bc,
                   const uint8_t* reverse,
                   const uint8_t* mapping,
                   uint64_t seed,
                   uint32_t targetStageBytes,
                   std::vector<VmStage>& out);

// Lift the arithmetic runs of one stage into second-level blocks and replace
// them in `stage.bc` with WIRE_GSTAGE <index> calls (branch targets are rebased
// as needed, so `stage.bc` is a valid program on return). `firstGuestIndex` is
// the descriptor index the first produced block will occupy in the packer's
// global guest table; `level` is written into every produced block (1 for the
// blocks of an outer stage). Returns false when the stage has no run long
// enough to be worth a guest descriptor; `stage` is then untouched.
bool vmLiftGuestBlocks(VmStage& stage,
                       uint64_t seed,
                       uint32_t maxBlocks,
                       uint32_t firstGuestIndex,
                       uint32_t level,
                       std::vector<VmGuestBlock>& out);

// Recursive form of the transform, used when revirtualization_level > 1.
//
// Splits `bc` into stages, lifts each stage's arithmetic runs into level-1 guest
// blocks, then lifts runs out of those blocks into level-2 blocks, and so on up
// to `levels` (clamped to kMaxGuestDepth). The result is one flat guest table
// where a descriptor's level says how deep it sits, plus the rewritten stage
// streams that reference it. Nothing is written to `bc`; the caller passes the
// streams it should emit.
//
// Returns the number of levels actually reached, 0 when no split was possible
// (the caller then keeps the region's original single-level form).
uint32_t vmRevirtualize(std::vector<uint8_t>& bc,
                        const uint8_t* reverse,
                        const uint8_t* mapping,
                        uint64_t seed,
                        uint32_t targetStageBytes,
                        uint32_t levels,
                        uint32_t maxBlocks,
                        std::vector<VmStage>& stages,
                        std::vector<VmGuestBlock>& guests);

} // namespace np
