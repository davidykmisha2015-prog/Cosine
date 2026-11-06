-- ==============================================================================
-- Module: auditor
-- Description: Multi-Provider SAST engine for auditing Lua codebases
-- Supported Providers: Google Gemini, Anthropic Claude, Alibaba Qwen, OpenAI,
--                      OpenRouter, DeepSeek, and Local/Custom (Ollama / vLLM)
-- Compatibility: Lua 5.1+, 5.4, and LuaJIT (Zero external dependencies)
-- ==============================================================================

local script_dir = debug.getinfo(1, "S").source:match("^@?(.*/)") or "./"
package.path = script_dir .. "?.lua;" .. script_dir .. "?/init.lua;" .. package.path

local reporter = require("reporter")

local auditor = {}

auditor.MAX_FILE_SIZE   = 200 * 1024  -- 200 KB threshold
auditor.DEFAULT_OUTPUT  = "results.json"

--- Safely escape arbitrary strings for POSIX shell single-quote boundaries.
-- @param str string
-- @return string
function auditor.sh_quote(str)
    return "'" .. (str:gsub("'", "'\\''")) .. "'"
end

--- Encode a string into a JSON string literal.
-- @param str string
-- @return string
function auditor.json_escape(str)
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

--- Build the strict Zero-False-Positive system prompt for Lua.
-- @return string
function auditor.get_lua_system_prompt()
    return "You are the elite Static Application Security Testing (SAST) engine for Lua codebases (Lua 5.1-5.4 & LuaJIT).\n" ..
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
end

--- Build the strict Zero-False-Positive system prompt for Python.
-- @return string
function auditor.get_python_system_prompt()
    return "You are the elite Static Application Security Testing (SAST) engine for Python codebases (Python 3.x).\n" ..
        "Your primary mandate is ZERO FALSE POSITIVES. In production and enterprise open-source, false positives erode developer trust and waste critical engineering resources. You must think critically, exercise intellectual honesty, and reject theoretical, unexploitable, or hallucinated claims.\n\n" ..
        "### CORE OPERATIONAL DIRECTIVES (ANTI-FALSE-POSITIVE PRINCIPLES):\n" ..
        "1. CRITICAL THINKING & INTELLECTUAL HONESTY:\n" ..
        "   - Have your own professional skepticism. Do NOT invent problems to look thorough.\n" ..
        "   - A clean report '[]' is the BEST and most valuable result when no genuine exploit exists.\n" ..
        "   - Functional typos, suboptimal idioms, or harmless bugs are NOT security vulnerabilities. Never flag code smells as security risks.\n\n" ..
        "2. REALISTIC THREAT MODEL (CLI vs SERVER CONTEXT):\n" ..
        "   - In CLI tools: The user running the script already owns their process and execution environment.\n" ..
        "   - Self-exploitation is NOT a vulnerability: Modifying their own environment variables (e.g. $HOME, $USER) or local config files is NOT an exploit.\n" ..
        "   - Parameterized queries ('cursor.execute(sql, (param,))') are completely safe. Do NOT flag parameterized database calls.\n" ..
        "   - Subprocess execution with an argument list ('subprocess.run([cmd, arg], shell=False)') is safe against shell injection.\n\n" ..
        "3. COMPLETE SOURCE-TO-SINK TRACEABILITY:\n" ..
        "   - Every reported issue MUST prove a complete, unbroken data-flow path: [Untrusted External Source] -> [Missing/Flawed Validation] -> [Dangerous Sink].\n" ..
        "   - Inspect surrounding validation: If input is sanitized (e.g. 'shlex.quote', 'os.path.basename', regex, allowlists), DO NOT flag it.\n\n" ..
        "4. TARGET VULNERABILITY CRITERIA FOR PYTHON:\n" ..
        "   - Insecure Shell/Command Execution: Direct string formatting/concatenation into 'os.system', 'os.popen', or 'subprocess.*(..., shell=True)'.\n" ..
        "   - Insecure Deserialization & Dynamic Execution: Untrusted input to 'eval()', 'exec()', 'pickle.loads()', 'marshal.loads()', or 'yaml.load(..., Loader=yaml.Loader)'.\n" ..
        "   - Path Traversal & File System Exposure: Unsanitized input into 'open()', 'os.remove()', or archive extraction without boundary validation (ZipSlip).\n" ..
        "   - SQL / Template Injection: Unescaped string formatting in database queries or template engines (e.g. Jinja2 'render_template_string(user_input)').\n" ..
        "   - Server-Side Request Forgery (SSRF): Untrusted URLs directly fetched via 'requests.get()' or 'urllib' without allowlisting.\n" ..
        "   - Real Leaked Credentials: Hardcoded active API keys, private tokens, or production secrets.\n\n" ..
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
        '    "remediation": "<exact, safe Python code replacement>"\n' ..
        "  }\n" ..
        "]\n\n" ..
        "If no verifiable, real-world vulnerabilities exist, you MUST return exactly:\n" ..
        "[]"
end

--- Detect programming language based on file extension.
-- @param filepath string
-- @return string "lua"|"python"
function auditor.detect_language(filepath)
    if not filepath then return "lua" end
    local lower = filepath:lower()
    if lower:match("%.pyw?$") then
        return "python"
    end
    return "lua"
end

--- Get system prompt tailored to target language.
-- @param language string|nil "lua"|"python"
-- @return string
function auditor.get_system_prompt(language)
    if language == "python" then
        return auditor.get_python_system_prompt()
    end
    return auditor.get_lua_system_prompt()
end

--- Provider Specifications and Builders
auditor.PROVIDERS = {
    gemini = {
        id = "gemini",
        name = "Google Gemini",
        env_keys = { "GEMINI_API_KEY" },
        default_model = "gemini-3.8-flash",
        fallback_models = { "gemini-3.8-flash", "gemini-3-flash-preview", "gemini-3.1-flash-lite" },
        build_request = function(api_key, model, system_prompt, user_prompt, options)
            local endpoint = string.format("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", model)
            local payload = string.format(
                '{\n' ..
                '  "system_instruction": {"parts": [{"text": "%s"}]},\n' ..
                '  "contents": [{"role": "user", "parts": [{"text": "%s"}]}],\n' ..
                '  "generationConfig": {"response_mime_type": "application/json", "responseMimeType": "application/json"}\n' ..
                '}',
                auditor.json_escape(system_prompt),
                auditor.json_escape(user_prompt)
            )
            local headers = {
                "Content-Type: application/json",
                "x-goog-api-key: " .. api_key
            }
            return endpoint, headers, payload
        end
    },
    claude = {
        id = "claude",
        name = "Anthropic Claude",
        env_keys = { "ANTHROPIC_API_KEY", "CLAUDE_API_KEY" },
        default_model = "claude-3-5-haiku-20241022",
        fallback_models = { "claude-3-5-haiku-20241022", "claude-3-5-sonnet-20241022" },
        build_request = function(api_key, model, system_prompt, user_prompt, options)
            local endpoint = options.base_url or "https://api.anthropic.com/v1/messages"
            local payload = string.format(
                '{\n' ..
                '  "model": "%s",\n' ..
                '  "max_tokens": 4096,\n' ..
                '  "system": "%s",\n' ..
                '  "messages": [{"role": "user", "content": "%s"}]\n' ..
                '}',
                auditor.json_escape(model),
                auditor.json_escape(system_prompt),
                auditor.json_escape(user_prompt)
            )
            local headers = {
                "Content-Type: application/json",
                "x-api-key: " .. api_key,
                "anthropic-version: 2023-06-01"
            }
            return endpoint, headers, payload
        end
    },
    qwen = {
        id = "qwen",
        name = "Alibaba Qwen (DashScope)",
        env_keys = { "QWEN_API_KEY", "DASHSCOPE_API_KEY" },
        default_model = "qwen-plus",
        fallback_models = { "qwen-plus", "qwen-turbo" },
        build_request = function(api_key, model, system_prompt, user_prompt, options)
            local endpoint = options.base_url or "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
            local payload = string.format(
                '{\n' ..
                '  "model": "%s",\n' ..
                '  "temperature": 0.0,\n' ..
                '  "messages": [\n' ..
                '    {"role": "system", "content": "%s"},\n' ..
                '    {"role": "user", "content": "%s"}\n' ..
                '  ]\n' ..
                '}',
                auditor.json_escape(model),
                auditor.json_escape(system_prompt),
                auditor.json_escape(user_prompt)
            )
            local headers = {
                "Content-Type: application/json",
                "Authorization: Bearer " .. api_key
            }
            return endpoint, headers, payload
        end
    },
    openai = {
        id = "openai",
        name = "OpenAI",
        env_keys = { "OPENAI_API_KEY" },
        default_model = "gpt-4o-mini",
        fallback_models = { "gpt-4o-mini", "gpt-4o" },
        build_request = function(api_key, model, system_prompt, user_prompt, options)
            local endpoint = options.base_url or "https://api.openai.com/v1/chat/completions"
            local payload = string.format(
                '{\n' ..
                '  "model": "%s",\n' ..
                '  "temperature": 0.0,\n' ..
                '  "messages": [\n' ..
                '    {"role": "system", "content": "%s"},\n' ..
                '    {"role": "user", "content": "%s"}\n' ..
                '  ]\n' ..
                '}',
                auditor.json_escape(model),
                auditor.json_escape(system_prompt),
                auditor.json_escape(user_prompt)
            )
            local headers = {
                "Content-Type: application/json",
                "Authorization: Bearer " .. api_key
            }
            return endpoint, headers, payload
        end
    },
    openrouter = {
        id = "openrouter",
        name = "OpenRouter",
        env_keys = { "OPENROUTER_API_KEY" },
        default_model = "qwen/qwen-2.5-coder-32b-instruct",
        fallback_models = { "qwen/qwen-2.5-coder-32b-instruct", "google/gemini-2.5-flash" },
        build_request = function(api_key, model, system_prompt, user_prompt, options)
            local endpoint = options.base_url or "https://openrouter.ai/api/v1/chat/completions"
            local payload = string.format(
                '{\n' ..
                '  "model": "%s",\n' ..
                '  "temperature": 0.0,\n' ..
                '  "messages": [\n' ..
                '    {"role": "system", "content": "%s"},\n' ..
                '    {"role": "user", "content": "%s"}\n' ..
                '  ]\n' ..
                '}',
                auditor.json_escape(model),
                auditor.json_escape(system_prompt),
                auditor.json_escape(user_prompt)
            )
            local headers = {
                "Content-Type: application/json",
                "Authorization: Bearer " .. api_key
            }
            return endpoint, headers, payload
        end
    },
    deepseek = {
        id = "deepseek",
        name = "DeepSeek",
        env_keys = { "DEEPSEEK_API_KEY" },
        default_model = "deepseek-chat",
        fallback_models = { "deepseek-chat" },
        build_request = function(api_key, model, system_prompt, user_prompt, options)
            local endpoint = options.base_url or "https://api.deepseek.com/v1/chat/completions"
            local payload = string.format(
                '{\n' ..
                '  "model": "%s",\n' ..
                '  "temperature": 0.0,\n' ..
                '  "messages": [\n' ..
                '    {"role": "system", "content": "%s"},\n' ..
                '    {"role": "user", "content": "%s"}\n' ..
                '  ]\n' ..
                '}',
                auditor.json_escape(model),
                auditor.json_escape(system_prompt),
                auditor.json_escape(user_prompt)
            )
            local headers = {
                "Content-Type: application/json",
                "Authorization: Bearer " .. api_key
            }
            return endpoint, headers, payload
        end
    },
    custom = {
        id = "custom",
        name = "OpenAI-Compatible / Local (Ollama, vLLM, etc.)",
        env_keys = { "COSINE_API_KEY", "OPENAI_API_KEY" },
        default_model = "default",
        fallback_models = {},
        build_request = function(api_key, model, system_prompt, user_prompt, options)
            local endpoint = options.base_url or os.getenv("OPENAI_BASE_URL") or os.getenv("COSINE_API_BASE") or "http://localhost:11434/v1/chat/completions"
            local payload = string.format(
                '{\n' ..
                '  "model": "%s",\n' ..
                '  "temperature": 0.0,\n' ..
                '  "messages": [\n' ..
                '    {"role": "system", "content": "%s"},\n' ..
                '    {"role": "user", "content": "%s"}\n' ..
                '  ]\n' ..
                '}',
                auditor.json_escape(model),
                auditor.json_escape(system_prompt),
                auditor.json_escape(user_prompt)
            )
            local headers = {
                "Content-Type: application/json"
            }
            if api_key and #api_key > 0 then
                table.insert(headers, "Authorization: Bearer " .. api_key)
            end
            return endpoint, headers, payload
        end
    }
}

--- Detect provider automatically from options or environment variables.
-- @param options table|nil
-- @return string provider_id
function auditor.detect_provider(options)
    options = options or {}
    if options.provider and options.provider ~= "" then
        local p = options.provider:lower()
        if p == "anthropic" then p = "claude" end
        if p == "dashscope" then p = "qwen" end
        if p == "ollama" or p == "vllm" then p = "custom" end
        if auditor.PROVIDERS[p] then
            return p
        end
    end

    -- Automatic detection based on available environment variables
    if os.getenv("GEMINI_API_KEY") then return "gemini" end
    if os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY") then return "claude" end
    if os.getenv("QWEN_API_KEY") or os.getenv("DASHSCOPE_API_KEY") then return "qwen" end
    if os.getenv("OPENROUTER_API_KEY") then return "openrouter" end
    if os.getenv("DEEPSEEK_API_KEY") then return "deepseek" end
    if os.getenv("OPENAI_API_KEY") then return "openai" end
    if os.getenv("OPENAI_BASE_URL") or os.getenv("COSINE_API_BASE") then return "custom" end

    return "gemini"
end

--- Resolve API key for a given provider.
-- @param provider_id string
-- @param cli_key string|nil Explicit CLI key
-- @return string|nil
function auditor.resolve_api_key(provider_id, cli_key)
    if cli_key and cli_key ~= "" then
        return cli_key
    end
    local prov = auditor.PROVIDERS[provider_id]
    if not prov then return nil end
    for _, env_var in ipairs(prov.env_keys) do
        local val = os.getenv(env_var)
        if val and val:match("%S") then
            return val
        end
    end
    return os.getenv("COSINE_API_KEY")
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

--- Dispatch HTTP POST request via curl subprocess.
-- @param endpoint string
-- @param headers table List of header strings
-- @param payload string Request body
-- @return string|nil raw_response, string|nil err_msg
function auditor.query_api(endpoint, headers, payload)
    local temp_request_path = os.tmpname()
    local temp_file, temp_err = io.open(temp_request_path, "w")
    if not temp_file then
        return nil, string.format("Failed to create temporary request file: %s", tostring(temp_err))
    end
    temp_file:write(payload)
    temp_file:close()

    local header_flags = {}
    for _, h in ipairs(headers) do
        table.insert(header_flags, "-H " .. auditor.sh_quote(h))
    end

    local cmd = string.format(
        "curl -s -S --max-time 35 -X POST %s %s -d @%s 2>&1",
        auditor.sh_quote(endpoint),
        table.concat(header_flags, " "),
        auditor.sh_quote(temp_request_path)
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

--- Parse model output from provider response into clean JSON array findings.
-- @param raw_response string
-- @return string|nil findings_json, string|nil err_msg
function auditor.parse_audit_response(raw_response)
    if not raw_response or raw_response == "" then
        return nil, "Received empty response from server"
    end

    -- Direct array check
    local direct_array = raw_response:match("^%s*(%[.*%])%s*$")
    if direct_array then
        return direct_array, nil
    end

    local ok, parsed = pcall(reporter.parse_json, raw_response)
    if not ok or type(parsed) ~= "table" then
        return nil, "Failed to parse API response as JSON: " .. tostring(parsed)
    end

    -- Check for provider-level errors
    if parsed.error then
        local msg = parsed.error.message or parsed.error.type or tostring(parsed.error)
        return nil, "API Error: " .. msg
    end

    local text_content = nil
    -- Gemini format
    if parsed.candidates and parsed.candidates[1] and parsed.candidates[1].content and parsed.candidates[1].content.parts then
        text_content = parsed.candidates[1].content.parts[1].text
    -- Claude format
    elseif parsed.content and parsed.content[1] and parsed.content[1].text then
        text_content = parsed.content[1].text
    -- OpenAI / Qwen / OpenRouter format
    elseif parsed.choices and parsed.choices[1] and parsed.choices[1].message then
        text_content = parsed.choices[1].message.content
    -- Generic
    elseif parsed.text then
        text_content = parsed.text
    end

    if not text_content then
        local bracketed = raw_response:match("(%[.-%])")
        if bracketed then return bracketed, nil end
        return nil, "Could not extract findings from response payload"
    end

    -- Strip markdown code block wrappers (```json ... ```)
    local cleaned = text_content:match("^%s*```%w*%s*(.-)%s*```%s*$") or text_content:match("^%s*(.-)%s*$")
    if cleaned and #cleaned > 0 then
        return cleaned, nil
    end

    return nil, "Empty findings text returned by model"
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
        or lower:find("could not extract", 1, true) ~= nil
        or lower:find("429", 1, true) ~= nil
        or lower:find("503", 1, true) ~= nil
        or lower:find("504", 1, true) ~= nil
end

--- Execute audit across models with retry on temporary errors and model fallbacks.
-- @param provider_id string
-- @param api_key string
-- @param preferred_model string|nil
-- @param filepath string
-- @param source_code string
-- @param options table|nil
-- @return string|nil findings_json, string model_used, string provider_name, string|nil err_msg
function auditor.execute_audit(provider_id, api_key, preferred_model, filepath, source_code, options)
    options = options or {}
    local verbose = (options.verbose ~= false)

    local prov = auditor.PROVIDERS[provider_id] or auditor.PROVIDERS["gemini"]
    local model = preferred_model or prov.default_model

    local lang = options.language or auditor.detect_language(filepath)
    local system_prompt = auditor.get_system_prompt(lang)
    local user_prompt = string.format("Target File: %s\nLanguage: %s\n\n```%s\n%s\n```", filepath, lang, lang, source_code)

    local models_to_try = { model }
    if prov.fallback_models then
        for _, fallback in ipairs(prov.fallback_models) do
            if fallback ~= model then
                table.insert(models_to_try, fallback)
            end
        end
    end

    local last_err = nil
    for model_idx, current_model in ipairs(models_to_try) do
        local max_retries = 2
        for attempt = 1, max_retries do
            if attempt > 1 then
                if verbose then
                    print(string.format("[-] [%s] Model '%s' busy, retrying in 2s (attempt %d/%d)...", prov.name, current_model, attempt, max_retries))
                end
                os.execute("sleep 2")
            else
                if verbose then
                    print(string.format("[+] Querying auditor via %s (%s)...", prov.name, current_model))
                end
            end

            local endpoint, headers, payload = prov.build_request(api_key, current_model, system_prompt, user_prompt, options)
            local raw_response, query_err = auditor.query_api(endpoint, headers, payload)

            if raw_response then
                local findings_json, parse_err = auditor.parse_audit_response(raw_response)
                if findings_json then
                    return findings_json, current_model, prov.name, nil
                end

                last_err = parse_err
                if not auditor.is_temporary_error(parse_err) then
                    return nil, current_model, prov.name, parse_err
                end
            else
                last_err = query_err
                if not auditor.is_temporary_error(query_err) then
                    return nil, current_model, prov.name, query_err
                end
            end
        end

        if model_idx < #models_to_try then
            if verbose then
                print(string.format("[!] [%s] '%s' is overloaded. Falling back to '%s'...", prov.name, current_model, models_to_try[model_idx + 1]))
            end
        end
    end

    return nil, model, prov.name, last_err
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
