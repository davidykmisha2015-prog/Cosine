package = "cosine"
version = "dev-1"
source = {
   url = "git+https://github.com/davidykmisha2015-prog/cosine.git"
}
description = {
   summary = "Static Application Security Testing (SAST) Engine for Lua codebases",
   detailed = [[
      Cosine is a specialized static application security testing engine for Lua 5.1-5.4
      and LuaJIT. It audits source files for command injection, insecure file system access,
      dynamic code execution, global pollution, and credential leaks.
   ]],
   homepage = "https://github.com/davidykmisha2015-prog/cosine",
   license = "GPL-3.0"
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "builtin",
   modules = {
      ["cosine"] = "src/init.lua",
      ["cosine.auditor"] = "src/auditor.lua",
      ["cosine.reporter"] = "src/reporter.lua",
   },
   install = {
      bin = {
         ["cosine"] = "bin/cosine"
      }
   }
}
