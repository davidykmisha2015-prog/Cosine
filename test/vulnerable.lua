-- ==============================================================================
-- Test File: vulnerable.lua
-- Purpose: Intentionally vulnerable Lua code for testing the Cosine SAST engine
-- ==============================================================================

-- Vulnerability 1: Hardcoded Secret / API Token (CWE-798)
local AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY_1234567890"

-- Vulnerability 2: Insecure Shell / Command Injection (CWE-78)
-- Directly concatenating external input into os.execute without sanitization
local function ping_host(host)
    local cmd = "ping -c 1 " .. host
    os.execute(cmd)
end

-- Vulnerability 3: Dynamic Code Execution (CWE-94 / CWE-95)
-- Evaluating untrusted user strings via loadstring without sandboxing
local function run_user_script(script_text)
    local chunk, err = loadstring(script_text)
    if chunk then
        chunk()
    else
        print("Compile error: " .. tostring(err))
    end
end

-- Vulnerability 4: Path Traversal & Arbitrary File Overwrite (CWE-22)
-- Using user-supplied filename directly with io.open without checking for "../"
local function save_note(filename, content)
    local path = "/tmp/notes/" .. filename
    local file = io.open(path, "w")
    if file then
        file:write(content)
        file:close()
    end
end

-- Vulnerability 5: Unsafe Subprocess Execution via io.popen (CWE-78)
local function search_logs(pattern)
    local p = io.popen("grep " .. pattern .. " /var/log/app.log")
    if p then
        local result = p:read("*a")
        p:close()
        return result
    end
end

-- Entry point with CLI arguments
local action = arg[1]
local input_val = arg[2] or "localhost"

if action == "ping" then
    ping_host(input_val)
elseif action == "eval" then
    run_user_script(input_val)
elseif action == "save" then
    save_note(input_val, arg[3] or "empty")
elseif action == "search" then
    search_logs(input_val)
end
