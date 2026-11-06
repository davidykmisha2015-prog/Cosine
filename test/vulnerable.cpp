// ==============================================================================
// Test File: vulnerable.cpp
// Purpose: Intentionally vulnerable C++ code for Static Analysis (SAST) testing
// ==============================================================================

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>

// Vulnerability 1: Hardcoded credentials (CWE-798)
const char* ADMIN_API_TOKEN = "sec_live_98a7fbc123456789abcdef0123456789";

// Vulnerability 2: Classic Buffer Overflow (CWE-120)
// Uses unsafe strcpy into fixed-size buffer without bounds checking
void process_username(const char* input) {
    char buffer[64];
    // Flaw: If input exceeds 63 characters, it overwrites adjacent stack memory
    strcpy(buffer, input);
    std::cout << "[+] Registered user: " << buffer << std::endl;
}

// Vulnerability 3: Format String Vulnerability (CWE-134)
// Directly passing user input as the format string to printf
void log_user_message(const char* user_msg) {
    // Flaw: An input with format specifiers (e.g. "%x %x %n") reads/writes arbitrary stack memory
    printf(user_msg);
    printf("\n");
}

// Vulnerability 4: Command / Shell Injection (CWE-78)
// Direct string concatenation into system() execution
void ping_server(const std::string& host) {
    // Flaw: If host contains shell metacharacters (e.g. "; ls -la", "| id"),
    // the shell executes arbitrary commands with process privileges
    std::string cmd = "ping -c 1 " + host;
    system(cmd.c_str());
}

// Vulnerability 5: Insecure Temporary File / Path Traversal (CWE-377 / CWE-22)
void save_user_profile(const std::string& filename, const std::string& data) {
    // Flaw: No path sanitization against directory traversal sequences ("../")
    std::string path = "/tmp/profiles/" + filename;
    FILE* f = fopen(path.c_str(), "w");
    if (f) {
        fputs(data.c_str(), f);
        fclose(f);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: ./vulnerable <user_input>\n";
        return 1;
    }

    std::cout << "=== Running Security Test Routines ===\n";
    process_username(argv[1]);
    log_user_message(argv[1]);
    ping_server(argv[1]);

    return 0;
}
