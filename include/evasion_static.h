#pragma once
// NovaProtect static image evasion.
//
// Everything here mutates the *file*, not the running process, and everything
// is reported back as a counted change so the build log can state what was
// actually rewritten instead of claiming a category.

#include "evasion.h"
#include "pe_lib.h"

#include <string>
#include <vector>

namespace np {

struct StaticEvasionReport {
    bool rich_scrubbed = false;
    uint32_t rich_bytes_cleared = 0;
    bool timestamp_randomized = false;
    uint32_t new_timestamp = 0;
    uint32_t sections_renamed = 0;
    uint32_t pdb_entries_stripped = 0;
    uint32_t padding_bytes_filled = 0;
    bool signature_dropped = false;
    bool checksum_updated = false;
    uint32_t new_checksum = 0;
    std::vector<std::string> changes;

    std::string summary() const;
};

// Read-only audit. Reported, never silently "fixed": a number the caller can
// verify against an external scanner beats a claim the product cannot back.
struct StaticAudit {
    struct SectionEntropy {
        std::string name;
        double entropy = 0.0;
        uint32_t raw_size = 0;
        uint32_t virtual_size = 0;
    };
    std::vector<SectionEntropy> sections;
    std::vector<std::string> flagged_imports;  // common detection anchors
    uint64_t zero_padding_bytes = 0;
    bool has_signature = false;
    bool has_pdb_path = false;
    bool has_rich_header = false;
    uint32_t dos_stub_size = 0;
};

class StaticEvader {
public:
    explicit StaticEvader(const EvasionConfig& cfg, uint64_t seed = 0);

    // Applies every enabled step in a fixed order; the checksum is recomputed
    // last over the prospective on-disk image.
    bool apply(PELib& pe, StaticEvasionReport& report);

    // Individual steps, exposed for tests and for the UI's per-option preview.
    bool scrubRichHeader(PELib& pe, StaticEvasionReport& report);
    bool randomizeTimestamp(PELib& pe, StaticEvasionReport& report);
    bool renameSections(PELib& pe, StaticEvasionReport& report);
    bool stripPdbEntries(PELib& pe, StaticEvasionReport& report);
    bool fillSectionPadding(PELib& pe, StaticEvasionReport& report);
    bool dropSignature(PELib& pe, StaticEvasionReport& report);
    bool updateChecksum(PELib& pe, StaticEvasionReport& report);

    static StaticAudit audit(PELib& pe);
    static double shannonEntropy(const uint8_t* data, size_t len);

private:
    EvasionConfig cfg_;
    uint64_t seed_;
    BuildSignature signature_;

public:
    // The per-build signature actually applied (tag, nonce, suffix, filler).
    const BuildSignature& buildSignature() const;
};

} // namespace np
