# Go symbol check

For a vulnerability in a Go module or the standard library, the Go vulnerability database lists the vulnerable functions. bomcensus asks the probe whether those functions are linked into the Go executables where the component was found, and uses the answer as the finding's reachability:

- `symbol_present`: an executable links a vulnerable function. The finding ranks first within its exposure.
- `symbol_absent`: every executable is known to link none of them. The exposure is lowered to installed. The finding is not hidden, not marked not affected and not added to VEX.
- no value: not known (no function list, no answer yet, or "not checked").

The trust rules are in [SECURITY.md](SECURITY.md) 6.1. This document covers what the reader in `internal/collect/gosymbol` supports and how it was tested.

## Supported executables

| | Supported |
|---|---|
| Formats | ELF, PE. Mach-O is not read. |
| Go versions | 1.18 and later (pclntab magic `0xfffffff0` for 1.18 and 1.19, `0xfffffff1` for 1.20 and later). Older binaries give "not checked". |
| Function table | `.gopclntab` section (ELF), `runtime.pclntab` symbol (PE), otherwise found by scanning data sections for a valid header. |
| Inline trees | Read through `go:func.*` (`go.func.*` before Go 1.20). Without a symbol table the address is taken from the runtime's module data; in a position-independent ELF file its pointers are read from the `R_*_RELATIVE` relocations. |

Without the inline trees, a function that was only inlined leaves no trace in the table, so a name missing from the table is "not checked", never "absent".

The layouts read, per Go version:

| Go | `_func` size | `inlinedCall` size, name offset at | `gofunc` field of `moduledata` (pointer words) |
|---|---|---|---|
| 1.18, 1.19 | 40 | 20, 12 | 38 |
| 1.20 and later | 44 | 16, 4 | 40 |

## Known limits

- A call that is inlined and then folded to a constant (for example `f(2)` where `f` only does arithmetic) leaves no instruction, so the function is reported absent. `govulncheck` in binary mode has the same limit.
- Only amd64 builds were tested. arm64 and other 64-bit targets use the same layouts and relocation handling but were not built in the tests below.

## Tests

`go test ./internal/collect/gosymbol/` builds a small program with the local toolchain and checks a non-inlined function, an inlined-only function, a method with a pointer receiver (`T.Method` and `(*T).Method`), a generic function, a closure, a function removed as dead code, and names that do not exist. Each build variant must report the inline trees as known.

Build variants, all `GOARCH=amd64`:

| GOOS | Build mode | Linker flags |
|---|---|---|
| linux | exe | none |
| linux | exe | `-s -w` |
| linux | pie | none |
| linux | pie | `-s -w` |
| windows | exe | none |
| windows | exe | `-s -w` |
| windows | pie | `-s -w` |

Other toolchains are added with `GOSYMBOL_TOOLCHAINS`, which the go command downloads:

```sh
GOSYMBOL_TOOLCHAINS="go1.18.10 go1.19.13 go1.21.13" go test ./internal/collect/gosymbol/ -run TestLookup
```

Results as of 2026-11-24: all 7 variants pass with Go 1.18.10, 1.19.13, 1.21.13 and 1.26.3. Go 1.20 was not built; it uses the same layout as 1.21. The `go` and `compile` binaries of Go 1.26.3 were also read and compared with `go tool nm`; each took about 0.1 seconds.

`internal/probe` tests the query itself: a hash mismatch, a file that is not a Go executable, a missing file, a container that is not running, and requests over the limits.

Fuzz targets:

```sh
go test ./internal/collect/gosymbol/ -run '^$' -fuzz FuzzOpen  -fuzztime 1m
go test ./internal/collect/gosymbol/ -run '^$' -fuzz FuzzTable -fuzztime 1m
```

`FuzzOpen` feeds whole files. `FuzzTable` feeds the function table and inline tree reader directly.
