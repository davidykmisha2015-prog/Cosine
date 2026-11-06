#!/usr/bin/env lua
-- ==============================================================================
-- Entry forwarder to src/main.lua for backward compatibility
-- ==============================================================================

local script_dir = debug.getinfo(1, "S").source:match("^@?(.*/)") or "./"
package.path = script_dir .. "src/?.lua;" .. script_dir .. "src/?/init.lua;" .. package.path
dofile(script_dir .. "src/main.lua")
