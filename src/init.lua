-- ==============================================================================
-- Module: cosine
-- Description: Static Application Security Testing (SAST) Engine for Lua
-- ==============================================================================

local script_dir = debug.getinfo(1, "S").source:match("^@?(.*/)") or "./"
package.path = script_dir .. "?.lua;" .. script_dir .. "?/init.lua;" .. package.path

local auditor  = require("auditor")
local reporter = require("reporter")

local cosine = {
    _VERSION  = "0.1.0",
    auditor   = auditor,
    reporter  = reporter,
}

--- Perform audit on a single Lua source file.
-- @param filepath string Path to Lua source file
-- @param options table|nil Optional parameters ({ model = string, output = string, color = boolean })
-- @return table|nil findings, string|nil error_message
function cosine.audit(filepath, options)
    options = options or {}
    local api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or api_key:match("^%s*$") then
        return nil, "GEMINI_API_KEY environment variable is not set."
    end

    local model = options.model or os.getenv("GEMINI_MODEL") or auditor.DEFAULT_MODEL
    local source, read_err = auditor.read_target_file(filepath)
    if not source then
        return nil, read_err
    end

    local payload = auditor.build_payload(filepath, source)
    local findings_json, used_model, audit_err = auditor.execute_audit(api_key, model, payload, options)
    if not findings_json then
        return nil, audit_err
    end

    if options.output then
        local save_ok, save_err = auditor.save_results(options.output, findings_json)
        if not save_ok then
            return nil, save_err
        end
    end

    return findings_json, nil
end

return cosine
