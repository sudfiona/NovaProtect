// NovaProtect API unhooking - implementation.
#include "api_unhook.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace np {
namespace {

constexpr uint32_t kMagic = 0x4855504Eu;  // 'NPUH'
constexpr uint16_t kVersion = 1;

void put16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>(v >> 8));
}

void put32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; i++) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

uint16_t get16(const std::vector<uint8_t>& in, size_t pos) {
    return static_cast<uint16_t>(in[pos] | (in[pos + 1] << 8));
}

uint32_t get32(const std::vector<uint8_t>& in, size_t pos) {
    return static_cast<uint32_t>(in[pos]) | (static_cast<uint32_t>(in[pos + 1]) << 8) |
           (static_cast<uint32_t>(in[pos + 2]) << 16) | (static_cast<uint32_t>(in[pos + 3]) << 24);
}

} // namespace

uint32_t UnhookPlan::totalBytes() const {
    uint32_t total = 0;
    for (const auto& patch : patches) total += static_cast<uint32_t>(patch.bytes.size());
    return total;
}

std::vector<uint8_t> UnhookPlan::encode() const {
    std::vector<uint8_t> out;
    put32(out, kMagic);
    put16(out, kVersion);
    put16(out, static_cast<uint16_t>(module.size()));
    out.insert(out.end(), module.begin(), module.end());
    put32(out, source_size);
    put32(out, static_cast<uint32_t>(patches.size()));
    for (const auto& patch : patches) {
        put32(out, patch.rva);
        put16(out, static_cast<uint16_t>(patch.bytes.size()));
        out.insert(out.end(), patch.bytes.begin(), patch.bytes.end());
    }
    return out;
}

bool UnhookPlan::decode(const std::vector<uint8_t>& blob, UnhookPlan& out, std::string& error) {
    if (blob.size() < 12) { error = "unhook table truncated"; return false; }
    if (get32(blob, 0) != kMagic) { error = "bad unhook magic"; return false; }
    if (get16(blob, 4) != kVersion) { error = "unsupported unhook version"; return false; }
    const uint16_t name_len = get16(blob, 6);
    size_t pos = 8;
    if (pos + name_len + 8 > blob.size()) { error = "unhook table truncated (name)"; return false; }
    out.module.assign(blob.begin() + pos, blob.begin() + pos + name_len);
    pos += name_len;
    out.source_size = get32(blob, pos); pos += 4;
    const uint32_t count = get32(blob, pos); pos += 4;
    out.patches.clear();
    out.patches.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        if (pos + 6 > blob.size()) { error = "unhook table truncated (entry)"; return false; }
        ModulePatch patch;
        patch.rva = get32(blob, pos); pos += 4;
        const uint16_t len = get16(blob, pos); pos += 2;
        if (pos + len > blob.size()) { error = "unhook table truncated (bytes)"; return false; }
        patch.bytes.assign(blob.begin() + pos, blob.begin() + pos + len);
        pos += len;
        out.patches.push_back(std::move(patch));
    }
    return true;
}

bool UnhookEngine::diffClean(const std::vector<uint8_t>& clean,
                             const std::vector<uint8_t>& live,
                             uint32_t max_runs, uint32_t join_gap,
                             UnhookPlan& out, std::string& error) {
    if (clean.empty() || live.empty()) { error = "empty image"; return false; }
    const size_t limit = std::min(clean.size(), live.size());
    out.patches.clear();

    size_t i = 0;
    while (i < limit) {
        if (clean[i] == live[i]) { i++; continue; }
        // Start a run; extend it while differences keep recurring inside the
        // join window, so a hook stub and the padding behind it stay one entry.
        size_t start = i;
        size_t end = i;
        size_t gap = 0;
        while (i < limit) {
            if (clean[i] != live[i]) { end = i + 1; gap = 0; }
            else {
                if (++gap > join_gap) break;
            }
            i++;
        }
        ModulePatch patch;
        patch.rva = static_cast<uint32_t>(start);
        patch.bytes.assign(clean.begin() + start, clean.begin() + end);
        out.patches.push_back(std::move(patch));
        if (out.patches.size() > max_runs) {
            error = "clean/live diff exceeds " + std::to_string(max_runs) +
                    " runs; the images are probably not the same build";
            out.patches.clear();
            return false;
        }
    }
    out.source_size = static_cast<uint32_t>(clean.size());
    if (out.patches.empty()) error = "no differences: the live image is already clean";
    return !out.patches.empty();
}

uint32_t UnhookEngine::applyPlan(std::vector<uint8_t>& image, const UnhookPlan& plan) {
    uint32_t applied = 0;
    for (const auto& patch : plan.patches) {
        if (patch.bytes.empty()) continue;
        if (static_cast<size_t>(patch.rva) + patch.bytes.size() > image.size()) continue;
        std::memcpy(image.data() + patch.rva, patch.bytes.data(), patch.bytes.size());
        applied++;
    }
    return applied;
}

std::vector<HookShape> UnhookEngine::findInlineHooks(const std::vector<uint8_t>& live,
                                                     uint32_t text_offset, uint32_t text_size,
                                                     uint64_t image_base) {
    std::vector<HookShape> shapes;
    const size_t begin = text_offset;
    const size_t end = std::min<size_t>(static_cast<size_t>(text_offset) + text_size, live.size());
    if (begin >= end) return shapes;

    auto add = [&](size_t at, const char* kind, uint64_t target) {
        HookShape shape;
        shape.offset = static_cast<uint32_t>(at);
        shape.kind = kind;
        shape.target = target;
        shapes.push_back(shape);
    };

    for (size_t i = begin; i + 5 <= end; i++) {
        // E9 rel32 -- the most common inline trampoline.
        if (live[i] == 0xE9) {
            const int32_t rel = static_cast<int32_t>(get32(live, i + 1));
            add(i, "jmp-rel32", static_cast<uint64_t>(static_cast<int64_t>(image_base + i + 5 + rel)));
            continue;
        }
        // FF 25 disp32 -- jump through a pointer (IAT-style detour).
        if (live[i] == 0xFF && live[i + 1] == 0x25) {
            const int32_t disp = static_cast<int32_t>(get32(live, i + 2));
            add(i, "jmp-iat", static_cast<uint64_t>(static_cast<int64_t>(image_base + i + 6 + disp)));
            continue;
        }
        // 48 B8 imm64 FF E0 -- mov rax, <handler>; jmp rax (12 bytes).
        if (live[i] == 0x48 && live[i + 1] == 0xB8 && i + 12 <= end &&
            live[i + 10] == 0xFF && live[i + 11] == 0xE0) {
            uint64_t target = 0;
            std::memcpy(&target, live.data() + i + 2, 8);
            add(i, "mov-jmp", target);
            i += 11;
            continue;
        }
        // 68 imm32 C3 -- push handler; ret.
        if (live[i] == 0x68 && i + 6 <= end && live[i + 5] == 0xC3) {
            add(i, "push-ret", get32(live, i + 1));
            i += 5;
            continue;
        }
        // EB rel8 -- short jump into a pad followed by the real stub.
        if (live[i] == 0xEB && i + 2 <= end) {
            const int8_t rel = static_cast<int8_t>(live[i + 1]);
            add(i, "jmp-rel8", static_cast<uint64_t>(static_cast<int64_t>(image_base + i + 2 + rel)));
        }
    }
    return shapes;
}

std::string UnhookEngine::emitRuntimeSource(const UnhookPlan& plan, const std::string& symbol) {
    std::ostringstream os;
    os << "// Generated by NovaProtect: API restoration table for " << plan.module << "\n";
    os << "// " << plan.patches.size() << " patch(es), " << plan.totalBytes() << " bytes.\n";
    os << "// ABI: uint32_t " << symbol << "(void* module_base);  0 = restored, 1 = failed.\n";
    os << "// Restore order is ascending RVA; each patch is applied with\n";
    os << "// VirtualProtect(PAGE_EXECUTE_READWRITE) -> memcpy -> VirtualProtect(original).\n\n";
    os << "static const unsigned char k" << symbol << "Blob[] = {\n";
    const std::vector<uint8_t> blob = plan.encode();
    for (size_t i = 0; i < blob.size(); i++) {
        if (i % 16 == 0) os << "    ";
        char buf[8];
        std::snprintf(buf, sizeof(buf), "0x%02x,", blob[i]);
        os << buf;
        if (i % 16 == 15) os << "\n";
        else os << " ";
    }
    if (blob.size() % 16) os << "\n";
    os << "};\n\n";
    os << "// The driver walks the table above: 4-byte magic, 2-byte version,\n";
    os << "// 2-byte name length, module name, source size, entry count, then\n";
    os << "// { u32 rva, u16 length, bytes } records.\n";
    return os.str();
}

} // namespace np
