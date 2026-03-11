# Semantic Shellcode Injection — Extension
## Formal Definition & Applicability Conditions

**Author:** Student at 42 Lyon Auvergne Rhône Alpes, 1 year of C experience  
**Tags:** `SSI` `formal-definition` `language-theory` `JIT` `interpreter` `attack-surface`

---

## Preface

The original write-up documented SSI as a C technique. During the extension of the research to JavaScript/V8 and Lua, a deeper question emerged: is SSI specific to C, or does it describe a more general attack class?

This extension answers that question by formalizing SSI and deriving the conditions under which it applies — or does not apply — to any language runtime.

---

## Formal Definition

> **Semantic Shellcode Injection (SSI)** is a technique in which an attacker chooses source-level constructs — constants, expressions, loop bounds, comparisons — whose binary encoding by the compiler or JIT constitutes valid executable code (shellcode or gadgets), causing the runtime to place that code in an executable memory region as an unavoidable side effect of normal language semantics.

Three properties distinguish SSI from classical injection techniques:

**Property 1 — Semantic legitimacy**  
The source code is syntactically and semantically valid in the target language. No memory write, no buffer overflow, no explicit shellcode buffer. The compiler or JIT acts in full conformance with the language specification.

**Property 2 — Compiler-forced placement**  
The attacker does not write bytes to memory. The toolchain writes them, because the language requires it. The placement is a necessary consequence of compilation semantics, not a side effect of a vulnerability.

**Property 3 — Executable region**  
The bytes land in a region the CPU can directly execute: the `.text` segment in compiled languages, or the JIT code region in JIT languages. No `mprotect`, no `mmap`, no W^X bypass required.

---

## The Necessary Condition — The Source-to-Executable Boundary

The research across C, JavaScript/V8, and Lua identified a single necessary condition for SSI. We call it the **source-to-executable boundary**:

> **SSI requires that a path exists from a source-level construct to a byte sequence in a CPU-executable memory region, such that the byte sequence is determined by the value of the construct.**

This boundary exists in two forms:

### Direct boundary — compiled languages

```
Source constant  →  compiler encodes as x86 immediate  →  lands in .text
```

The path is deterministic and unconditional. Every C assignment of the form `x = 0xdeadbeef` causes the compiler to write those bytes into `.text`. SSI is trivially applicable.

Languages: C, C++, Rust, Zig, Go, assembly.

### Indirect boundary — JIT languages

```
Source constant  →  JIT compiler  →  speculative native code  →  JIT region
```

The path exists but depends on JIT heuristics: the function must be hot enough to be compiled, the type feedback must be stable enough for the JIT to specialize, and the constant must survive optimizations such as constant folding or blinding.

The research on V8/TurboFan confirmed this boundary exists for JavaScript:

```javascript
// 4-byte injection via loop bound (cmpl imm32)
for (let i = 0; i < 0x1000bead; i++) { ... }
// TurboFan emits: 81 f9 ad be 00 10 in the JIT region

// 8-byte injection via BigUint64Array store
view[0] = 0xdeadbeefdeadbeefn;
// TurboFan emits: REX.W movq reg, 0xdeadbeefdeadbeef in the JIT region
```

Languages: JavaScript (V8, SpiderMonkey), LuaJIT, Java (JVM JIT), C# (.NET RyuJIT), PyPy.

### No boundary — pure interpreters

```
Source constant  →  interpreter heap  →  never becomes CPU instructions
```

In a pure interpreter, constants are stored as data objects on the VM heap. The VM executes them through a C `switch/case` dispatch loop — the constants are operands, never instructions. No byte written from source code ever reaches an executable region.

Languages: Lua (standard), CPython, Ruby MRI, most embedded scripting engines.

**SSI in the x86 sense is impossible in pure interpreters.** This is not a protection — it is an architectural consequence of the interpretation model.

---

## Language Classification

| Runtime | Type | Boundary | SSI applicable | Direct syscall |
|---|---|---|---|---|
| C / C++ / Rust / Zig | Compiled | Direct (.text) | ✓ trivial | ✓ |
| JavaScript / V8 | JIT (TurboFan) | Indirect (JIT region) | ◑ injection yes, execution blocked | ✗ sandboxed |
| LuaJIT | JIT (trace-based) | Indirect (JIT region) | ◑ likely achievable | ◑ context-dependent |
| Java / .NET | JIT (JVM / RyuJIT) | Indirect (JIT region) | ◑ context-dependent | ◑ context-dependent |
| Lua (standard) | Pure interpreter | None | ✗ impossible | ✗ |
| CPython / Ruby MRI | Pure interpreter | None | ✗ impossible | ✗ |

---

## SSI-VM — The Bytecode Variant for Pure Interpreters

Even when the direct x86 boundary is absent, a weaker analog applies to languages that expose their own bytecode at runtime. We call this **SSI-VM**.

> **SSI-VM** is a variant in which the injected payload consists of VM opcodes rather than x86 instructions, exploiting the language's own bytecode loading mechanism as the execution vector.

In Lua, this is exposed natively:

```lua
-- string.dump() serializes a function to its raw bytecode
local bytecode = string.dump(function()
    local x = 0xdeadbeef  -- this constant appears verbatim in the bytecode
end)

-- The bytecode bytes can be modified directly
local patched = bytecode:sub(1, offset - 1) .. payload_opcodes .. bytecode:sub(offset + n)

-- load() compiles and executes arbitrary bytecode
load(patched)()
```

The capabilities of SSI-VM are bounded by what the VM itself permits. If the host application has removed `os`, `io`, and `debug` from the environment (as Roblox, CS2, and WoW do), SSI-VM can only operate within those constraints. There is no path to a direct syscall.

SSI-VM is relevant for: Roblox/Luau, WoW addons, CS2 server plugins, any embedded Lua/Python context where the bytecode API is accessible.

---

## The Two-Phase Model of SSI

The JavaScript research revealed that SSI decomposes naturally into two independent problems:

```
Phase 1 — Injection
  Can attacker-controlled bytes appear in an executable region?
  Depends on: boundary existence, JIT heuristics, constant survival

Phase 2 — Execution
  Can execution be redirected to those bytes?
  Depends on: address leakage, memory write primitive, sandbox model
```

In C, both phases are trivial — the compiler places the bytes at a known offset, and stack manipulation redirects execution.

In JavaScript/V8, Phase 1 is confirmed achievable. Phase 2 is blocked by three independent architectural barriers:

- **Pointer compression** — heap pointers are 32-bit offsets, not usable addresses.
- **JIT region isolation** — no JS API exposes addresses in the JIT code region.
- **No arbitrary memory read** — a type confusion primitive (addrof) requires an unpatched CVE.

The conclusion for SSI-JS: the injection exists, but V8 prevents its traversal from JavaScript by design, not by accident.

---

## Attack Surface Summary

| Category | Byte injection | Address leak | Execution redirect | Syscall |
|---|---|---|---|---|
| Compiled (C/Rust…) | ✓ trivial | ✓ native | ✓ stack/ptr | ✓ |
| JIT — browser JS (V8) | ✓ confirmed | ✗ sandboxed | ✗ blocked | ✗ |
| JIT — embedded engines | ✓ likely | ◑ less protected | ◑ possible | ◑ |
| JIT — LuaJIT | ✓ likely | ◑ exposed by -jdump | ◑ no browser sandbox | ◑ |
| Pure interpreter | ✗ impossible | N/A | N/A | ✗ |
| SSI-VM (bytecode) | VM opcodes only | N/A | ✓ via load() | ✗ |

---

## Conclusion

SSI is not a C-specific technique. It is a general attack class defined by a single necessary condition: the existence of a source-to-executable boundary in the target runtime.

This boundary is unconditional in compiled languages, conditional in JIT languages, and structurally absent in pure interpreters. The strength of the attack is then bounded by the attacker's ability to locate and redirect execution to the injected bytes — a problem that is trivial in C, blocked by the V8 sandbox in browsers, and potentially solvable in less-protected JIT contexts such as embedded engines or LuaJIT.

The decomposition into injection phase and execution phase is the key insight: a runtime can be partially vulnerable — injectable but not exploitable — if only Phase 1 is achievable. V8 is precisely in this state.

> **SSI applicability law:** A language runtime is susceptible to SSI if and only if a source-level construct determines byte content in a CPU-executable memory region. The exploitability of that susceptibility is bounded by the attacker's ability to complete the execution phase.

---

## Open Research Directions

- **WebAssembly as execution bridge** — WASM's linear memory model and less aggressive constant blinding may offer a path to completing Phase 2 in a browser context.
- **Non-V8 JS engines** — QuickJS, Duktape, Hermes (React Native) lack pointer compression and browser sandbox. Complete SSI may be achievable.
- **LuaJIT in game engines** — used in contexts (Roblox, nginx/OpenResty) where the sandbox model is application-defined and potentially weaker than V8.
- **Spectre/timing side-channel** — `SharedArrayBuffer` + high-resolution timer can leak arbitrary memory addresses, potentially providing the address primitive needed for Phase 2 without a CVE.

---

*This work was carried out in a purely educational and personal research context.*
