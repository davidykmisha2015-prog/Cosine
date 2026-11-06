#!/usr/bin/env lua
-- ==============================================================================
-- Module: reporter
-- Description: Terminal ANSI pretty-printer for SAST security audit findings
-- Compatibility: Lua 5.1+, 5.4, and LuaJIT (Zero external dependencies)
-- ==============================================================================

local reporter = {}

--- Lightweight pure-Lua JSON parser for findings arrays and objects.
-- @param str string Raw JSON string
-- @return table|nil Parsed Lua data structure
local function parse_json(str)
    local pos = 1
    local len = #str
    local parse_value, parse_string, parse_number, parse_array, parse_object

    local function skip_whitespace()
        while pos <= len and str:sub(pos, pos):match("%s") do
            pos = pos + 1
        end
    end

    function parse_value()
        skip_whitespace()
        if pos > len then return nil end
        local c = str:sub(pos, pos)

        if c == "{" then
            return parse_object()
        elseif c == "[" then
            return parse_array()
        elseif c == '"' then
            return parse_string()
        elseif c:match("[%d%-]") then
            return parse_number()
        elseif str:sub(pos, pos + 3) == "true" then
            pos = pos + 4
            return true
        elseif str:sub(pos, pos + 4) == "false" then
            pos = pos + 5
            return false
        elseif str:sub(pos, pos + 3) == "null" then
            pos = pos + 4
            return nil
        else
            error("Unexpected character at position " .. pos .. ": " .. c)
        end
    end

    function parse_string()
        pos = pos + 1
        local buf = {}
        local escapes = {
            ['"']  = '"',
            ['\\'] = '\\',
            ['/']  = '/',
            ['b']  = '\b',
            ['f']  = '\f',
            ['n']  = '\n',
            ['r']  = '\r',
            ['t']  = '\t'
        }
        while pos <= len do
            local c = str:sub(pos, pos)
            if c == '"' then
                pos = pos + 1
                return table.concat(buf)
            elseif c == "\\" then
                pos = pos + 1
                local esc = str:sub(pos, pos)
                if esc == "u" then
                    local hex = str:sub(pos + 1, pos + 4)
                    local code = tonumber(hex, 16) or 0
                    pos = pos + 5
                    if code < 0x80 then
                        table.insert(buf, string.char(code))
                    elseif code < 0x800 then
                        table.insert(buf, string.char(0xC0 + math.floor(code / 64), 0x80 + (code % 64)))
                    else
                        table.insert(buf, string.char(
                            0xE0 + math.floor(code / 4096),
                            0x80 + (math.floor(code / 64) % 64),
                            0x80 + (code % 64)
                        ))
                    end
                else
                    table.insert(buf, escapes[esc] or esc)
                    pos = pos + 1
                end
            else
                table.insert(buf, c)
                pos = pos + 1
            end
        end
        error("Unterminated string literal in JSON")
    end

    function parse_number()
        local s, e = str:find("^%-?%d+%.?%d*[eE]?[%+%-]?%d*", pos)
        if s then
            pos = e + 1
            return tonumber(str:sub(s, e))
        end
        error("Invalid number literal at position " .. pos)
    end

    function parse_array()
        pos = pos + 1
        local arr = {}
        skip_whitespace()
        if pos <= len and str:sub(pos, pos) == "]" then
            pos = pos + 1
            return arr
        end
        while pos <= len do
            table.insert(arr, parse_value())
            skip_whitespace()
            local c = str:sub(pos, pos)
            if c == "]" then
                pos = pos + 1
                return arr
            elseif c == "," then
                pos = pos + 1
            else
                error("Expected ',' or ']' at position " .. pos)
            end
        end
        error("Unterminated JSON array")
    end

    function parse_object()
        pos = pos + 1
        local obj = {}
        skip_whitespace()
        if pos <= len and str:sub(pos, pos) == "}" then
            pos = pos + 1
            return obj
        end
        while pos <= len do
            skip_whitespace()
            if str:sub(pos, pos) ~= '"' then
                error("Expected string key in object at position " .. pos)
            end
            local key = parse_string()
            skip_whitespace()
            if str:sub(pos, pos) ~= ":" then
                error("Expected ':' after key at position " .. pos)
            end
            pos = pos + 1
            local val = parse_value()
            obj[key] = val
            skip_whitespace()
            local c = str:sub(pos, pos)
            if c == "}" then
                pos = pos + 1
                return obj
            elseif c == "," then
                pos = pos + 1
            else
                error("Expected ',' or '}' in object at position " .. pos)
            end
        end
        error("Unterminated JSON object")
    end

    return parse_value()
end

reporter.parse_json = parse_json

--- Build color escape table based on terminal support.
-- @param options table|nil Configuration options (e.g., { color = true/false })
-- @return table Palette of styling codes
local function build_palette(options)
    options = options or {}
    local use_color = true

    if options.color ~= nil then
        use_color = options.color
    else
        local no_color = os.getenv("NO_COLOR")
        local term = os.getenv("TERM") or ""
        if (no_color and no_color ~= "") or term == "dumb" then
            use_color = false
        end
    end

    if not use_color then
        return {
            reset        = "",
            bold         = "",
            dim          = "",
            underline    = "",
            gray         = "",
            red          = "",
            green        = "",
            yellow       = "",
            cyan         = "",
            white        = "",
            badge_crit   = "[CRITICAL]",
            badge_high   = "[HIGH]",
            badge_med    = "[MEDIUM]",
            badge_low    = "[LOW]",
            badge_info   = "[INFO]",
            check_icon   = "✔",
            label_style  = ""
        }
    end

    local ESC = string.char(27) .. "["
    return {
        reset        = ESC .. "0m",
        bold         = ESC .. "1m",
        dim          = ESC .. "2m",
        underline    = ESC .. "4m",
        gray         = ESC .. "90m",
        red          = ESC .. "1;31m",
        green        = ESC .. "1;32m",
        yellow       = ESC .. "1;33m",
        cyan         = ESC .. "1;36m",
        white        = ESC .. "1;37m",
        badge_crit   = ESC .. "1;97;41m CRITICAL " .. ESC .. "0m",
        badge_high   = ESC .. "1;31m[HIGH]" .. ESC .. "0m",
        badge_med    = ESC .. "1;33m[MEDIUM]" .. ESC .. "0m",
        badge_low    = ESC .. "1;36m[LOW]" .. ESC .. "0m",
        badge_info   = ESC .. "1;37m[INFO]" .. ESC .. "0m",
        check_icon   = ESC .. "1;32m✔" .. ESC .. "0m",
        label_style  = ESC .. "1;90m"
    }
end

--- Pretty-print the audit findings table or raw JSON findings string.
-- @param findings_or_json table|string List of findings objects or raw JSON string
-- @param options table|nil Optional formatting settings ({ color = boolean, output = file_handle })
-- @return boolean Success status
function reporter.report(findings_or_json, options)
    options = options or {}
    local out = options.output or io.stdout
    local c = build_palette(options)

    local findings = findings_or_json
    if type(findings) == "string" then
        local ok, parsed = pcall(parse_json, findings)
        if not ok or type(parsed) ~= "table" then
            io.stderr:write("reporter: failed to parse findings JSON: " .. tostring(parsed) .. "\n")
            return false
        end
        findings = parsed
    end

    if type(findings) ~= "table" then
        io.stderr:write("reporter: invalid input, expected array table or valid JSON string\n")
        return false
    end

    local banner_divider = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local card_divider   = "  ─────────────────────────────────────────────────────────────────────────"

    -- Edge case: Empty findings (Clean codebase)
    if #findings == 0 then
        out:write(c.gray .. banner_divider .. c.reset .. "\n")
        out:write(string.format("  %s %s[CLEAN] No vulnerabilities detected!%s (0 findings)\n", c.check_icon, c.green, c.reset))
        out:write(c.gray .. banner_divider .. c.reset .. "\n")
        return true
    end

    -- Aggregate counts by severity
    local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, OTHER = 0 }
    for _, item in ipairs(findings) do
        local sev = (item.severity or "OTHER"):upper()
        if counts[sev] ~= nil then
            counts[sev] = counts[sev] + 1
        else
            counts.OTHER = counts.OTHER + 1
        end
    end

    -- Header Banner
    out:write(c.gray .. banner_divider .. c.reset .. "\n")
    out:write(string.format("  %sCOSINE SAST AUDIT REPORT%s\n", c.bold, c.reset))
    out:write(string.format(
        "  Total Findings: %s%d%s  (%sCRITICAL: %d%s | %sHIGH: %d%s | %sMEDIUM: %d%s | %sLOW: %d%s)\n",
        c.bold, #findings, c.reset,
        c.red, counts.CRITICAL, c.reset,
        c.red, counts.HIGH, c.reset,
        c.yellow, counts.MEDIUM, c.reset,
        c.cyan, counts.LOW, c.reset
    ))
    out:write(c.gray .. banner_divider .. c.reset .. "\n\n")

    -- Render each vulnerability card
    for i, item in ipairs(findings) do
        local sev = (item.severity or "INFO"):upper()
        local badge = c.badge_info
        local type_color = c.white

        if sev == "CRITICAL" then
            badge = c.badge_crit
            type_color = c.red
        elseif sev == "HIGH" then
            badge = c.badge_high
            type_color = c.red
        elseif sev == "MEDIUM" then
            badge = c.badge_med
            type_color = c.yellow
        elseif sev == "LOW" then
            badge = c.badge_low
            type_color = c.cyan
        end

        local vuln_type = item.vuln_type or "Security Vulnerability"
        local file_path = item.file or "unknown"
        local line_str  = (item.line ~= nil and tostring(item.line)) or "unknown"
        local location  = string.format("%s:%s", file_path, line_str)

        local desc    = item.description or "No description available."
        local exploit = item.exploit_scenario or item.exploit_vector or "No exploit vector provided."
        local remed   = item.remediation or "No remediation pattern provided."

        local indent = "\n                "
        local formatted_desc    = desc:gsub("\n", indent)
        local formatted_exploit = exploit:gsub("\n", indent)
        local formatted_remed   = remed:gsub("\n", indent)

        -- Line 1: [SEVERITY BADGE] Vulnerability Type
        out:write(string.format("  %s  %s%s%s\n", badge, type_color, vuln_type, c.reset))

        -- Line 2: Location: <file_path>:<line_number>
        out:write(string.format("  %sLocation:%s       %s%s%s%s\n", c.label_style, c.reset, c.gray, c.underline, location, c.reset))

        -- Line 3: Description: Concise explanation
        out:write(string.format("  %sDescription:%s    %s\n", c.label_style, c.reset, formatted_desc))

        -- Line 4: Exploit Vector: How it can be triggered
        out:write(string.format("  %sExploit Vector:%s %s\n", c.label_style, c.reset, formatted_exploit))

        -- Line 5: Remediation: Suggested fix / pattern
        out:write(string.format("  %sRemediation:%s    %s%s%s\n", c.label_style, c.reset, c.cyan, formatted_remed, c.reset))

        -- Separator between cards
        if i < #findings then
            out:write("\n" .. c.gray .. card_divider .. c.reset .. "\n\n")
        end
    end

    out:write("\n" .. c.gray .. banner_divider .. c.reset .. "\n")
    return true
end

-- CLI Runner support: allows executing directly via `lua reporter.lua [results.json]`
if arg and arg[0] and arg[0]:match("reporter%.lua$") then
    local target_json = arg[1] or "results.json"
    local file, err = io.open(target_json, "r")
    if not file then
        io.stderr:write(string.format("Error: Cannot read findings from '%s': %s\n", target_json, tostring(err)))
        os.exit(1)
    end
    local raw_json = file:read("*a")
    file:close()
    reporter.report(raw_json)
end

return reporter
