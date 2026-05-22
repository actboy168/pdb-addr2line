local lm = require "luamake"

lm:conf {
    cxx = "c++17",
}

lm:source_set "raw_pdb" {
    defines = "_CRT_SECURE_NO_WARNINGS",
    includes = "third_party/raw_pdb/src",
    sources = "third_party/raw_pdb/src/*.cpp",
}

lm:exe "pdb-addr2line" {
    deps = "raw_pdb",
    defines = "_CRT_SECURE_NO_WARNINGS",
    includes = {
        "src",
        "third_party/raw_pdb/src",
    },
    sources =  "src/*.cpp",
}
