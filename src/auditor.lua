-- ==============================================================================
-- Module: auditor
-- Description: Core SAST engine for auditing Lua codebases via Gemini API
-- Compatibility: Lua 5.1+, 5.4, and LuaJIT (Zero external dependencies)
-- ==============================================================================

local auditor = {}

auditor.MAX_FILE_SIZE   = 200 * 1024  -- 200 KB threshold
auditor.DEFAULT_MODEL   = "gemini-3.8-flash"
auditor.FALLBACK_MODELS = { "gemini-3.8-flash", "gemini-3-flash-preview", "gemini-3.1-flash-lite" }
auditor.DEFAULT_OUTPUT  = "results.json"

--- Safely escape arbitrary strings for POSIX shell single-quote boundaries.
-- @param str string
-- @return string
local function sh_quote(str)
    return "'" .. (str:gsub("'", "'\\''")) .. "'"
end

auditor.sh_quote = sh_quote

--- Encode a string into a JSON string literal.
-- @param str string
-- @return string
local function json_escape(str)
    local escape_map = {
        ['"']  = '\\"',
        ['\\'] = '\\\\',
        ['\b'] = '\\b',
        ['\f'] = '\\f',
        ['\n'] = '\\n',
        ['\r'] = '\\r',
        ['\t'] = '\\t'
    }
    return (str:gsub('[\1-\31"\\]', function(c)
        return escape_map[c] or string.format("\\u%04x", string.byte(c))
    end))
end

auditor.json_escape = json_escape

--- Scan and extract an escaped JSON string value by key without external dependencies.
-- @param json_text string
-- @param key string
-- @return string|nil
local function extract_json_string(json_text, key)
    local pattern = '"' .. key .. '"%s*:%s*"'
    local s, e = json_text:find(pattern)
    if not s then return nil end

    local i = e + 1
    local len = #json_text
    local buffer = {}

    while i <= len do
        local char = json_text:sub(i, i)
        if char == "\\" then
            table.insert(buffer, json_text:sub(i, i + 1))
            i = i + 2
        elseif char == '"' then
            return table.concat(buffer)
        else
            table.insert(buffer, char)
            i = i + 1
        end
    end
    return nil
end

--- Decode JSON escape sequences into raw string characters.
-- @param str string
-- @return string
local function unescape_json(str)
    local escapes = {
        ['\\"'] = '"',
        ['\\\\'] = '\\',
        ['\\/'] = '/',
        ['\\b'] = '\b',
        ['\\f'] = '\f',
        ['\\n'] = '\n',
        ['\\r'] = '\r',
        ['\\t'] = '\t'
    }

    local decoded = str:gsub("\\u([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F])", function(hex)
        local code = tonumber(hex, 16)
        if code < 0x80 then
            return string.char(code)
        elseif code < 0x800 then
            return string.char(0xC0 + math.floor(code / 64), 0x80 + (code % 64))
        else
            return string.char(
                0xE0 + math.floor(code / 4096),
                0x80 + (math.floor(code / 64) % 64),
                0x80 + (code % 64)
            )
        end
    end)

    return (decoded:gsub("\\.", escapes))
end

--- Read and validate target file properties (existence, size, plaintext check).
-- @param filepath string
-- @return string|nil, string|nil (content, err_msg)
function auditor.read_target_file(filepath)
    local handle, open_err = io.open(filepath, "rb")
    if not handle then
        return nil, string.format("Cannot open target file '%s': %s", filepath, tostring(open_err))
    end

    local file_size = handle:seek("end")
    if not file_size then
        handle:close()
        return nil, string.format("Unable to determine size of '%s'", filepath)
    end

    if file_size > auditor.MAX_FILE_SIZE then
        handle:close()
        return nil, string.format(
            "File '%s' exceeds maximum allowed size (%d bytes > %d bytes limit)",
            filepath, file_size, auditor.MAX_FILE_SIZE
        )
    end

    handle:seek("set", 0)
    local contents = handle:read("*a")
    handle:close()

    if not contents then
        return nil, string.format("Failed to read file content from '%s'", filepath)
    end

    if contents:sub(1, 4) == "\27Lua" or contents:find("\0", 1, true) then
        return nil, string.format("Rejected '%s': binary or compiled bytecode file detected", filepath)
    end

    return contents, nil
end

--- Construct the REST API request JSON payload.
-- @param filepath string
-- @param source_code string
-- @return string
function auditor.build_payload(filepath, source_code)
    local system_prompt = "You are the elite Static Application Security Testing (SAST) engine for Lua codebases (Lua 5.1-5.4 & LuaJIT).\n" ..
        "Your primary mandate is ZERO FALSE POSITIVES. In production and enterprise open-source, false positives erode developer trust and waste critical engineering resources. You must think critically, exercise intellectual honesty, and reject theoretical, unexploitable, or hallucinated claims.\n\n" ..
        "### CORE OPERATIONAL DIRECTIVES (ANTI-FALSE-POSITIVE PRINCIPLES):\n" ..
        "1. CRITICAL THINKING & INTELLECTUAL HONESTY:\n" ..
        "   - Have your own professional skepticism. Do NOT invent problems to look thorough.\n" ..
        "   - A clean report '[]' is the BEST and most valuable result when no genuine exploit exists.\n" ..
        "   - Functional typos, suboptimal idioms, or harmless bugs are NOT security vulnerabilities. Never flag code smells as security risks.\n\n" ..
        "2. REALISTIC THREAT MODEL (CLI vs SERVER CONTEXT):\n" ..
        "   - In CLI tools: The user running the tool already owns their own process, terminal, and user account.\n" ..
        "   - Self-exploitation is NOT a vulnerability: If an 'exploit' requires the user to modify their own $HOME, $USER, or system environment variables to attack themselves, it is NOT a vulnerability.\n" ..
        "   - Accessing $HOME, standard system paths, or localized directories (e.g. 'Documents', 'Документи') is normal, expected behavior. DO NOT flag this.\n\n" ..
        "3. COMPLETE SOURCE-TO-SINK TRACEABILITY:\n" ..
        "   - Every reported issue MUST prove a complete, unbroken data-flow path: [Untrusted External Source] -> [Missing/Flawed Validation] -> [Dangerous Sink].\n" ..
        "   - You MUST inspect surrounding lines for validation. If the code checks for traversal patterns (e.g. 'find(\"/\")', 'find(\"%.%.\")', allowlists, pattern matching), respect it! If input is neutralized, DO NOT flag it.\n" ..
        "   - Do NOT hallucinate interpolation: Verify whether variables are actually formatted into command strings. For instance, 'string.format' without '%s' specifiers does NOT interpolate variables.\n\n" ..
        "4. TARGET VULNERABILITY CRITERIA:\n" ..
        "   - Insecure Shell Execution: Actual, verifiable command injection where external untrusted input reaches 'os.execute' or 'io.popen' without sanitization.\n" ..
        "   - Dynamic Code Execution: Untrusted external strings executed via 'load' or 'loadstring'.\n" ..
        "   - Arbitrary File Overwrite/Traversal: Untrusted input directly used to escape intended root directories to read/write sensitive files outside the application boundary.\n" ..
        "   - Real Leaked Credentials: Live production API keys, private tokens, or secret credentials (not example tokens or config placeholders).\n" ..
        "   - Global Namespace Poisoning: Dangerous unintentional overrides of critical '_G' primitives in libraries.\n\n" ..
        "### RESPONSE FORMAT:\n" ..
        "Return strictly a raw JSON array of objects with the schema:\n" ..
        "[\n" ..
        "  {\n" ..
        '    "file": "<path_to_file>",\n' ..
        '    "line": <line_number_or_null>,\n' ..
        '    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",\n' ..
        '    "vuln_type": "<standard_category_name>",\n' ..
        '    "description": "<concise, grounded explanation of the verified vulnerability>",\n' ..
        '    "exploit_scenario": "<step-by-step mechanism showing how untrusted input reaches the sink and triggers unauthorized execution>",\n' ..
        '    "remediation": "<exact, safe Lua code replacement>"\n' ..
        "  }\n" ..
        "]\n\n" ..
        "If no verifiable, real-world vulnerabilities exist, you MUST return exactly:\n" ..
        "[]"

    local user_prompt = string.format("Target File: %s\n\nSource Code:\n```lua\n%s\n```", filepath, source_code)

    return string.format(
        '{\n' ..
        '  "system_instruction": {\n' ..
        '    "parts": [{"text": "%s"}]\n' ..
        '  },\n' ..
        '  "contents": [{\n' ..
        '    "role": "user",\n' ..
        '    "parts": [{"text": "%s"}]\n' ..
        '  }],\n' ..
        '  "generationConfig": {\n' ..
        '    "response_mime_type": "application/json",\n' ..
        '    "responseMimeType": "application/json"\n' ..
        '  }\n' ..
        '}',
        json_escape(system_prompt),
        json_escape(user_prompt)
    )
end

--- Dispatch the payload to Gemini REST API via curl subprocess.
-- @param api_key string
-- @param model string
-- @param payload string
-- @return string|nil, string|nil
function auditor.query_gemini_api(api_key, model, payload)
    local endpoint = string.format("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", model)
    local temp_request_path = os.tmpname()

    local temp_file, temp_err = io.open(temp_request_path, "w")
    if not temp_file then
        return nil, string.format("Failed to create temporary request file: %s", tostring(temp_err))
    end
    temp_file:write(payload)
    temp_file:close()

    local cmd = string.format(
        "curl -s -S --max-time 20 -X POST %s -H %s -H %s -d @%s 2>&1",
        sh_quote(endpoint),
        sh_quote("Content-Type: application/json"),
        sh_quote("x-goog-api-key: " .. api_key),
        sh_quote(temp_request_path)
    )

    local pipe = io.popen(cmd, "r")
    if not pipe then
        os.remove(temp_request_path)
        return nil, "Failed to spawn curl subprocess"
    end

    local raw_output = pipe:read("*a")
    local success, exit_type, code = pipe:close()
    os.remove(temp_request_path)

    local failed = false
    if success == nil or success == false then
        failed = true
    elseif type(success) == "number" and success ~= 0 then
        failed = true
    end

    if failed or (raw_output and raw_output:match("^curl:%s*%(")) then
        return nil, string.format("curl error: %s", (raw_output or ""):gsub("%s+$", ""))
    end

    if not raw_output or raw_output:match("^%s*$") then
        return nil, "curl executed but returned an empty response"
    end

    return raw_output, nil
end

--- Extract the raw JSON findings array from the Gemini API response.
-- @param response string
-- @return string|nil, string|nil
function auditor.parse_audit_response(response)
    local error_msg = response:match('"message"%s*:%s*"([^"]+)"')
    if error_msg then
        return nil, string.format("API Error returned by server: %s", error_msg)
    end

    local direct_array = response:match("^%s*(%[.*%])%s*$")
    if direct_array then
        return direct_array, nil
    end

    local raw_text = extract_json_string(response, "text")
    if raw_text then
        local unescaped = unescape_json(raw_text)
        local cleaned = unescaped:match("^%s*```%w*%s*(.-)%s*```%s*$") or unescaped:match("^%s*(.-)%s*$")
        if cleaned and #cleaned > 0 then
            return cleaned, nil
        end
    end

    local fallback_array = response:match("(%[.-%])")
    if fallback_array then
        return fallback_array, nil
    end

    return nil, "Could not extract a valid JSON findings array from the response"
end

--- Check if an API error message indicates temporary high demand, timeout, or rate limits.
-- @param err_msg string
-- @return boolean
function auditor.is_temporary_error(err_msg)
    if not err_msg then return false end
    local lower = err_msg:lower()
    return lower:find("high demand", 1, true) ~= nil
        or lower:find("temporary", 1, true) ~= nil
        or lower:find("timed out", 1, true) ~= nil
        or lower:find("timeout", 1, true) ~= nil
        or lower:find("operation timed out", 1, true) ~= nil
        or lower:find("curl error", 1, true) ~= nil
        or lower:find("resource has been exhausted", 1, true) ~= nil
        or lower:find("temporarily unavailable", 1, true) ~= nil
        or lower:find("try again later", 1, true) ~= nil
        or lower:find("quota exceeded", 1, true) ~= nil
        or lower:find("could not extract a valid json", 1, true) ~= nil
        or lower:find("429", 1, true) ~= nil
        or lower:find("503", 1, true) ~= nil
end

--- Execute audit with retry on temporary errors and fallback models if overloaded.
-- @param api_key string
-- @param preferred_model string
-- @param payload string
-- @param options table|nil ({ verbose = boolean })
-- @return string|nil findings_json, string model_used, string|nil err_msg
function auditor.execute_audit(api_key, preferred_model, payload, options)
    options = options or {}
    local verbose = (options.verbose ~= false)

    local models_to_try = { preferred_model }
    for _, fallback in ipairs(auditor.FALLBACK_MODELS) do
        if fallback ~= preferred_model then
            table.insert(models_to_try, fallback)
        end
    end

    local last_err = nil
    for model_idx, model_name in ipairs(models_to_try) do
        local max_retries = 2
        for attempt = 1, max_retries do
            if attempt > 1 then
                if verbose then
                    print(string.format("[-] Model '%s' busy, retrying in 2s (attempt %d/%d)...", model_name, attempt, max_retries))
                end
                os.execute("sleep 2")
            else
                if verbose then
                    print(string.format("[+] Querying auditor via Gemini API (%s)...", model_name))
                end
            end

            local raw_response, query_err = auditor.query_gemini_api(api_key, model_name, payload)
            if raw_response then
                local findings_json, parse_err = auditor.parse_audit_response(raw_response)
                if findings_json then
                    return findings_json, model_name, nil
                end

                last_err = parse_err
                if not auditor.is_temporary_error(parse_err) then
                    return nil, model_name, parse_err
                end
            else
                last_err = query_err
                if not auditor.is_temporary_error(query_err) then
                    return nil, model_name, query_err
                end
            end
        end

        if model_idx < #models_to_try then
            if verbose then
                print(string.format("[!] '%s' is experiencing high demand. Falling back to '%s'...", model_name, models_to_try[model_idx + 1]))
            end
        end
    end

    return nil, preferred_model, last_err
end

--- Save findings directly to results.json with robust error handling.
-- @param filepath string
-- @param json_data string
-- @return boolean, string|nil
function auditor.save_results(filepath, json_data)
    local file, err = io.open(filepath, "w")
    if not file then
        return false, string.format("Cannot open '%s' for writing: %s", filepath, tostring(err))
    end

    local write_ok, write_err = file:write(json_data, "\n")
    file:close()

    if not write_ok then
        return false, string.format("Failed to write findings to '%s': %s", filepath, tostring(write_err))
    end

    return true, nil
end

return auditor
