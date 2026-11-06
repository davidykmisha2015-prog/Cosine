#!/usr/bin/env lua
-- ==============================================================================
-- Application: Cosine CLI
-- Description: Multi-Provider SAST for Lua Codebases
-- ==============================================================================

local script_dir = debug.getinfo(1, "S").source:match("^@?(.*/)") or "./"
package.path = script_dir .. "?.lua;" .. script_dir .. "?/init.lua;" .. package.path

local auditor  = require("auditor")
local reporter = require("reporter")

local VERSION = "0.2.0"

--- Display usage banner and CLI options.
local function print_help()
    io.stdout:write([[
Cosine - Multi-Provider Static Application Security Testing (SAST) Engine for Lua

Usage:
  cosine <path/to/file.lua>            Audit a single Lua source file
  cosine check <path/to/file.lua>      Audit a single Lua source file
  cosine check_project [directory]     Recursively find & audit all Lua files in project

Provider & Model Options:
  -p, --provider <name>  LLM Provider (default: auto-detected from environment)
                         Supported: gemini | claude | qwen | openai | openrouter | deepseek | custom
  -k, --api-key <key>    Specify API key directly (overrides environment variables)
  -m, --model <name>     Specify model ID (defaults to provider's recommended model)
  --base-url <url>       Specify custom API base URL (for Ollama, vLLM, or custom proxies)

Output & Formatting Options:
  -o, --output <path>    Specify output JSON destination (default: results.json)
  --no-color             Disable ANSI terminal colors
  -s, --silent           Suppress progress logging and show only findings
  -v, --version          Show version information
  -h, --help             Display this help message

Supported Environment Variables:
  GEMINI_API_KEY         Google Gemini API Key
  ANTHROPIC_API_KEY      Anthropic Claude API Key (or CLAUDE_API_KEY)
  QWEN_API_KEY           Alibaba Qwen / DashScope API Key (or DASHSCOPE_API_KEY)
  OPENAI_API_KEY         OpenAI API Key
  OPENROUTER_API_KEY     OpenRouter API Key
  DEEPSEEK_API_KEY       DeepSeek API Key
  COSINE_API_KEY         Universal fallback API Key
  OPENAI_BASE_URL        Base URL for custom/local endpoints
  NO_COLOR               Disable ANSI terminal colors
]])
end

--- Scan directory recursively for all .lua files excluding hidden / build directories.
-- @param dir string
-- @return table List of file paths
local function find_lua_files(dir)
    dir = dir or "."
    local files = {}
    local cmd = string.format("find %s -type f -name '*.lua' -not -path '*/.*' 2>/dev/null", auditor.sh_quote(dir))
    local p = io.popen(cmd)
    if p then
        for line in p:lines() do
            if line and line:match("%S") then
                table.insert(files, line)
            end
        end
        p:close()
    end
    return files
end

--- Parse CLI arguments into options table.
local function parse_args(args)
    local opts = {
        command   = nil,
        targets   = {},
        provider  = nil,
        api_key   = nil,
        model     = nil,
        base_url  = nil,
        output    = auditor.DEFAULT_OUTPUT,
        color     = true,
        silent    = false,
    }

    if not args or #args == 0 then
        return opts
    end

    local i = 1
    while i <= #args do
        local a = args[i]
        if a == "-h" or a == "--help" then
            opts.show_help = true
            return opts
        elseif a == "-v" or a == "--version" then
            opts.show_version = true
            return opts
        elseif a == "--no-color" then
            opts.color = false
        elseif a == "-s" or a == "--silent" then
            opts.silent = true
        elseif a == "-o" or a == "--output" then
            i = i + 1
            opts.output = args[i] or auditor.DEFAULT_OUTPUT
        elseif a == "-p" or a == "--provider" then
            i = i + 1
            opts.provider = args[i]
        elseif a == "-k" or a == "--api-key" then
            i = i + 1
            opts.api_key = args[i]
        elseif a == "-m" or a == "--model" then
            i = i + 1
            opts.model = args[i]
        elseif a == "--base-url" then
            i = i + 1
            opts.base_url = args[i]
        elseif a == "check" then
            opts.command = "check"
        elseif a == "check_project" then
            opts.command = "check_project"
        else
            table.insert(opts.targets, a)
        end
        i = i + 1
    end

    return opts
end

--- Merge two findings arrays into the first.
local function merge_findings(dest, source)
    for _, item in ipairs(source) do
        table.insert(dest, item)
    end
end

--- Main CLI entry point.
local function main()
    local opts = parse_args(arg)

    if opts.show_help then
        print_help()
        os.exit(0)
    end

    if opts.show_version then
        print("cosine " .. VERSION)
        os.exit(0)
    end

    -- Determine provider
    local provider_id = auditor.detect_provider(opts)
    local prov = auditor.PROVIDERS[provider_id]
    if not prov then
        io.stderr:write(string.format("[!] Error: Unknown provider '%s'.\n", tostring(opts.provider)))
        io.stderr:write("    Supported: gemini, claude, qwen, openai, openrouter, deepseek, custom\n")
        os.exit(1)
    end

    -- Resolve API Key
    local api_key = auditor.resolve_api_key(provider_id, opts.api_key)
    if provider_id ~= "custom" and (not api_key or api_key:match("^%s*$")) then
        local env_hint = table.concat(prov.env_keys, " or ")
        io.stderr:write(string.format("[!] Error: No API key found for %s.\n", prov.name))
        io.stderr:write(string.format("    Set environment variable: export %s=\"your_key\"\n", env_hint))
        io.stderr:write("    Or pass via command-line: --api-key <key>\n")
        os.exit(1)
    end
    api_key = api_key or ""

    local active_model = opts.model or prov.default_model

    -- Handle check_project command
    if opts.command == "check_project" or (opts.targets[1] and opts.targets[1]:match("/$")) then
        local target_dir = opts.targets[1] or "."
        if not opts.silent then
            print(string.format("[+] Provider: %s (model: %s)", prov.name, active_model))
            print(string.format("[+] Scanning directory '%s' for Lua files...", target_dir))
        end

        local lua_files = find_lua_files(target_dir)
        if #lua_files == 0 then
            if not opts.silent then
                print("[-] No .lua source files discovered in target path.")
            end
            reporter.report("[]", { color = opts.color })
            auditor.save_results(opts.output, "[]")
            os.exit(0)
        end

        if not opts.silent then
            print(string.format("[+] Found %d Lua source file(s) to analyze.\n", #lua_files))
        end

        local all_findings = {}
        for idx, file_path in ipairs(lua_files) do
            if not opts.silent then
                print(string.format("[%d/%d] Auditing: %s", idx, #lua_files, file_path))
            end

            local source_code, read_err = auditor.read_target_file(file_path)
            if source_code then
                local findings_json, used_model, used_prov, audit_err = auditor.execute_audit(
                    provider_id, api_key, opts.model, file_path, source_code,
                    { verbose = not opts.silent, base_url = opts.base_url }
                )
                if findings_json then
                    local ok, parsed = pcall(reporter.parse_json, findings_json)
                    if ok and type(parsed) == "table" then
                        merge_findings(all_findings, parsed)
                    end
                else
                    io.stderr:write(string.format("[!] Audit warning for %s: %s\n", file_path, tostring(audit_err)))
                end
            else
                if not opts.silent then
                    print(string.format("    [-] Skipped: %s", read_err))
                end
            end
        end

        -- Serialize aggregated findings
        local aggregated_json = "[]"
        if #all_findings > 0 then
            local ok_format, json_dump = pcall(function()
                local parts = { "[\n" }
                for i, item in ipairs(all_findings) do
                    local entry = string.format(
                        '  {\n' ..
                        '    "file": "%s",\n' ..
                        '    "line": %s,\n' ..
                        '    "severity": "%s",\n' ..
                        '    "vuln_type": "%s",\n' ..
                        '    "description": "%s",\n' ..
                        '    "exploit_scenario": "%s",\n' ..
                        '    "remediation": "%s"\n' ..
                        '  }',
                        auditor.json_escape(item.file or ""),
                        item.line and tostring(item.line) or "null",
                        auditor.json_escape(item.severity or "INFO"),
                        auditor.json_escape(item.vuln_type or ""),
                        auditor.json_escape(item.description or ""),
                        auditor.json_escape(item.exploit_scenario or item.exploit_vector or ""),
                        auditor.json_escape(item.remediation or "")
                    )
                    table.insert(parts, entry)
                    if i < #all_findings then
                        table.insert(parts, ",\n")
                    else
                        table.insert(parts, "\n")
                    end
                end
                table.insert(parts, "]")
                return table.concat(parts)
            end)
            if ok_format and json_dump then
                aggregated_json = json_dump
            end
        end

        auditor.save_results(opts.output, aggregated_json)
        if not opts.silent then
            print(string.format("\n[+] Saved aggregated findings to %s\n", opts.output))
        end
        reporter.report(all_findings, { color = opts.color })
        os.exit(0)
    end

    -- Single target file check
    local target_path = opts.targets[1]
    if not target_path or target_path == "" then
        print_help()
        os.exit(1)
    end

    if not opts.silent then
        print(string.format("[+] Provider: %s (model: %s)", prov.name, active_model))
        print(string.format("[+] Reading target file: %s", target_path))
    end

    local source_code, read_err = auditor.read_target_file(target_path)
    if not source_code then
        io.stderr:write(string.format("[!] File Error: %s\n", read_err))
        os.exit(1)
    end

    if not opts.silent then
        print(string.format("[+] Verified plaintext source (%d bytes)", #source_code))
        print("[+] Building security audit payload...")
    end

    local findings_json, used_model, used_prov, audit_err = auditor.execute_audit(
        provider_id, api_key, opts.model, target_path, source_code,
        { verbose = not opts.silent, base_url = opts.base_url }
    )

    if not findings_json then
        io.stderr:write(string.format("[!] Audit Error: %s\n", audit_err))
        os.exit(1)
    end

    if not opts.silent then
        print(string.format("[+] Audit completed successfully via %s (%s).", used_prov, used_model))
    end

    local save_ok, save_err = auditor.save_results(opts.output, findings_json)
    if not save_ok then
        io.stderr:write(string.format("[!] I/O Error: %s\n", save_err))
        os.exit(1)
    end

    if not opts.silent then
        print(string.format("[+] Successfully saved findings to %s\n", opts.output))
    end

    reporter.report(findings_json, { color = opts.color })
end

main()
