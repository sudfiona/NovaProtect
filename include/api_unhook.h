#pragma once
// NovaProtect API unhooking.
//
// The threat model: an AV/EDR user-mode agent has written inline hooks into
// ntdll/kernel32 by overwriting the first bytes of a function with a jump to
// its own shim. Any call the protected image makes then runs the agent's code,
// which can log the arguments or simply refuse to forward.
//
// The defence is to rebuild the pristine bytes from the copy on disk and put
// them back, so the syscall path is the one Microsoft shipped. Two artefacts
// are produced here:
//
//   * UnhookPlan -- a compact restoration table (module, RVA, bytes),
//   * emitRuntimeSource() -- the freestanding C driver that applies it.
//
// Note on what this is not: restoring the on-disk text does not defeat a
// kernel-mode agent that reports from a callback registered inside the kernel.
// It only removes the user-mode trampolines.

#include <cstdint>
#include <string>
#include <vector>

namespace np {

struct ModulePatch {
    uint32_t rva = 0;
    std::vector<uint8_t> bytes;
};

struct UnhookPlan {
    std::string module = "ntdll.dll";
    uint32_t source_size = 0;          // size of the clean image the table came from
    std::vector<ModulePatch> patches;

    uint32_t totalBytes() const;
    std::vector<uint8_t> encode() const;
    static bool decode(const std::vector<uint8_t>& blob, UnhookPlan& out, std::string& error);
};

struct HookShape {
    // File offset inside the buffer that was scanned. `text_offset` is a file
    // offset, not an RVA, so callers compare it against dump offsets.
    uint32_t offset = 0;
    std::string kind;                  // "jmp-rel32", "jmp-iat", "mov-jmp", "push-ret", "jmp-rel8"
    uint64_t target = 0;               // resolved absolute target where computable
};

class UnhookEngine {
public:
    // Compare the clean on-disk image with the live (or dumped) copy and emit
    // one patch per differing run. Runs separated by fewer than `join_gap`
    // identical bytes are merged so a hook plus its padding is one entry.
    static bool diffClean(const std::vector<uint8_t>& clean,
                          const std::vector<uint8_t>& live,
                          uint32_t max_runs, uint32_t join_gap,
                          UnhookPlan& out, std::string& error);

    // Puts the patches back. Returns how many entries were applied; entries
    // that run past the end of the image are skipped, never partially copied.
    static uint32_t applyPlan(std::vector<uint8_t>& image, const UnhookPlan& plan);

    // Shape scan, useful on its own: reports which functions a live agent has
    // redirected without needing a clean image to diff against.
    static std::vector<HookShape> findInlineHooks(const std::vector<uint8_t>& live,
                                                  uint32_t text_offset, uint32_t text_size,
                                                  uint64_t image_base);

    static std::string emitRuntimeSource(const UnhookPlan& plan, const std::string& symbol);
};

} // namespace np
