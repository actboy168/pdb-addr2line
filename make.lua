local lm = require "luamake"

lm:conf {
    cxx = "c++17",
}

lm:source_set "raw_pdb" {
    includes = "third_party/raw_pdb/src",
    defines = {
        "NOMINMAX",
        "WIN32_LEAN_AND_MEAN",
        "_CRT_SECURE_NO_WARNINGS",
    },
    sources = {
        "third_party/raw_pdb/src/*.cpp",
    },
}

lm:exe "pdb-addr2line" {
    deps = "raw_pdb",
    includes = {
        "src",
        "third_party/raw_pdb/src",
    },
    defines = {
        "NOMINMAX",
        "WIN32_LEAN_AND_MEAN",
        "_CRT_SECURE_NO_WARNINGS",
    },
    sources = {
        "src/*.cpp",
    },
}
