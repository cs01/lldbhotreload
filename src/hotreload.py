#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import lldb
except ImportError:
    pass

_FUNCTION_INFO: Dict[str, Dict[str, Any]] = {}
_PATCHED_FILE_HASHES: Dict[str, str] = {}
_HOTRELOADED_FUNCTIONS: Set[str] = set()
_ORIGINAL_BINARY_MODULE: Optional[str] = None


def breakpoint_callback(frame: Any, bp_loc: Any, dict: Dict[str, Any]) -> bool:
    global _HOTRELOADED_FUNCTIONS, _ORIGINAL_BINARY_MODULE

    if not _HOTRELOADED_FUNCTIONS:
        return True

    address = bp_loc.GetAddress()
    if not address.IsValid():
        return True

    symbol = address.GetSymbol()
    if not symbol.IsValid():
        return True

    func_name = symbol.GetName()

    if func_name not in _HOTRELOADED_FUNCTIONS:
        return True

    module = address.GetModule()
    if not module.IsValid():
        return True

    module_name = module.GetFileSpec().GetFilename()

    # If this breakpoint is in a hotreload module, allow it (stop execution)
    if module_name.startswith("hotreload_"):
        return False  # Stop here - this is the new code we want to debug

    # If this breakpoint is in the original binary (the trampoline), skip it
    # Return True to continue execution - we don't want to stop at the trampoline!
    return True  # Continue - don't stop at old code/trampoline


class FileHotReload:
    def __init__(self, debugger: Any, result: Any) -> None:
        self.debugger: Any = debugger
        self.result: Any = result
        self.target: Any = debugger.GetSelectedTarget()
        self.process: Any = self.target.GetProcess() if self.target.IsValid() else None
        self.cache_dir: Path = Path(tempfile.gettempdir()) / "lldb_hotreload"
        self.cache_dir.mkdir(exist_ok=True)
        self.loaded_libs: Dict[str, Any] = {}
        self.patched_functions: Dict[str, Dict[str, Any]] = {}

    def log(self, message: str) -> None:
        self.result.AppendMessage(message)

    def load_compile_commands(self, source_file: str | Path) -> Optional[List[str]]:
        source_name: str = Path(source_file).resolve().name
        current: Path = Path.cwd()

        for _ in range(5):
            compile_commands: Path = current / "compile_commands.json"
            if compile_commands.exists():
                try:
                    with open(compile_commands) as f:
                        for entry in json.load(f):
                            if Path(entry.get("file", "")).name == source_name:
                                # Prefer "arguments" (array, more precise) over "command" (string)
                                if "arguments" in entry:
                                    parts: List[str] = entry["arguments"]
                                    if parts:
                                        return parts
                                # Fall back to "command" if "arguments" not present
                                # Use shlex.split() to properly handle shell quoting
                                command_str: str = entry.get("command", "")
                                if command_str:
                                    parts: List[str] = shlex.split(command_str)
                                    if parts:
                                        return parts
                except (json.JSONDecodeError, KeyError, IOError):
                    pass
            parent: Path = current.parent
            if parent == current:
                break
            current = parent
        return None

    def find_functions_from_dwarf(
        self, source_file: str | Path
    ) -> List[Dict[str, Any]]:
        source_filename: str = Path(source_file).name
        functions: List[Dict[str, Any]] = []

        all_symbols: List[tuple[int, int, str]] = []

        for module in self.target.module_iter():
            module_name: str = module.GetFileSpec().GetFilename()
            if module_name.startswith("hotreload_"):
                continue

            for sym_idx in range(module.GetNumSymbols()):
                symbol: Any = module.GetSymbolAtIndex(sym_idx)
                if symbol.GetType() != lldb.eSymbolTypeCode:
                    continue

                start_addr: Any = symbol.GetStartAddress()
                if not start_addr.IsValid():
                    continue

                load_addr: int = start_addr.GetLoadAddress(self.target)
                if load_addr == lldb.LLDB_INVALID_ADDRESS:
                    continue

                end_addr: Any = symbol.GetEndAddress()
                end_load_addr: int = (
                    end_addr.GetLoadAddress(self.target) if end_addr.IsValid() else 0
                )

                all_symbols.append((load_addr, end_load_addr, symbol.GetName()))

        all_symbols.sort(key=lambda x: x[0])

        for module in self.target.module_iter():
            module_name: str = module.GetFileSpec().GetFilename()
            if module_name.startswith("hotreload_"):
                continue

            for sym_idx in range(module.GetNumSymbols()):
                symbol: Any = module.GetSymbolAtIndex(sym_idx)
                if symbol.GetType() != lldb.eSymbolTypeCode:
                    continue

                start_addr: Any = symbol.GetStartAddress()
                if not start_addr.IsValid():
                    continue

                line_entry: Any = start_addr.GetLineEntry()
                if not line_entry.IsValid():
                    continue

                if line_entry.GetFileSpec().GetFilename() != source_filename:
                    continue

                func_name: str = symbol.GetName()
                load_addr: int = start_addr.GetLoadAddress(self.target)
                line_num: int = line_entry.GetLine()

                if (
                    load_addr == lldb.LLDB_INVALID_ADDRESS
                    or func_name == "main"
                    or func_name.startswith(
                        ("__cxx_global_var_init", "_GLOBAL__sub_I_")
                    )
                    or line_num == 0
                ):
                    continue

                end_load_addr: int = 0
                for i, (sym_start, sym_end, sym_name) in enumerate(all_symbols):
                    if sym_start == load_addr:
                        if i + 1 < len(all_symbols):
                            end_load_addr = all_symbols[i + 1][0]
                        break

                if end_load_addr == 0:
                    end_addr: Any = symbol.GetEndAddress()
                    end_load_addr = (
                        end_addr.GetLoadAddress(self.target)
                        if end_addr.IsValid()
                        else 0
                    )

                functions.append(
                    {
                        "name": func_name,
                        "mangled": symbol.GetMangledName(),
                        "addr": load_addr,
                        "end_addr": end_load_addr,
                        "line": line_num,
                    }
                )

        return functions

    def find_all_functions_in_file(self, source_file: str | Path) -> List[str]:
        """
        Find all functions in a source file that can be hot reloaded.
        Uses clang AST dump for accurate, bulletproof parsing.
        Requires clang++ compiler - will error if not available.
        """
        source_path = Path(source_file).resolve()

        # Get compiler flags
        compile_flags = self.load_compile_commands(source_path)
        if not compile_flags:
            raise RuntimeError(
                f"No compile_commands.json found for {source_path}. AST analysis requires compilation database."
            )

        # Extract the real compiler from compilation database
        # Some build systems use wrapper scripts that pass the real compiler via --cc=
        compiler = None
        for i, flag in enumerate(compile_flags):
            if flag.startswith("--cc="):
                compiler = flag.split("=", 1)[1]
                break

        if not compiler:
            compiler = compile_flags[0]

        # Require clang++ compiler
        if not compiler.endswith("clang++"):
            raise RuntimeError(
                f"Compiler must be clang++, but got: {compiler}. Hot reloading requires clang for AST parsing."
            )

        # Build minimal AST dump command (TEXT format, not JSON)
        # Text format is much faster and doesn't have the 592MB JSON parsing issues
        cmd = [compiler, "-Xclang", "-ast-dump", "-fsyntax-only"]

        # Extract only essential flags from compile_commands
        for flag in compile_flags[1:]:
            # Keep include paths and defines
            if (
                flag.startswith("-I")
                or flag.startswith("-D")
                or flag.startswith("-std=")
            ):
                cmd.append(flag)
            # Keep system paths
            elif flag.startswith("-idirafter") or flag.startswith("-isystem"):
                cmd.append(flag)
            # Skip argsfiles - they can hang or reference build-time-only paths
            elif flag.startswith("@"):
                continue

        cmd.append(str(source_path))

        self.log(f"  Getting clang AST...")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15, cwd=Path.cwd()
            )

            # Combine stdout and stderr (AST dump goes to stdout, errors to stderr)
            output = result.stdout + result.stderr

            # Parse the text AST dump to find function declarations
            functions = []
            source_filename = source_path.name

            for line in output.split("\n"):
                # Look for top-level FunctionDecl lines from the main source file
                # (top-level = starts with "|-FunctionDecl", not nested in templates)
                #
                # We use AST attributes to filter robustly:
                # ✓ Accept: |-FunctionDecl ... <line:X:Y, ...> line:A:B (real function in main file)
                # ✗ Reject: nested FunctionDecl (template instantiations, nested classes)
                # ✗ Reject: <scratch space> (macro-generated function)
                # ✗ Reject: functions marked 'static' (internal linkage)
                # ✗ Reject: functions marked 'inline' (may not exist as symbols)
                # ✗ Reject: ALL_UPPERCASE names (macros like BENCHMARK)
                # ✗ Reject: template instantiations (< in signature)
                # ✗ Reject: destructors (start with ~)
                # ✗ Reject: class methods (:: in name before paren)
                #
                # Accept top-level functions (start with |- or `- in AST tree notation)
                if not (
                    line.startswith("|-FunctionDecl")
                    or line.startswith("`-FunctionDecl")
                ):
                    continue

                # Only accept functions from the main source file
                # Accept both <file.cpp:L:C> and <line:L:C> formats
                if " line:" not in line:
                    continue

                # Reject functions from header files
                if ".h:" in line:
                    continue

                # Reject macro-generated functions (identified by <scratch space>)
                if "<scratch space>" in line:
                    continue

                # Reject static functions (internal linkage - can't reliably patch)
                if " static" in line:
                    continue

                # Reject inline functions (may not exist as real symbols in binary)
                if " inline" in line:
                    continue

                # Extract function name and signature
                # Format: |-FunctionDecl ... line:X:Y [used] funcname 'signature' [static|inline]
                match = re.search(r" (\w+) '([^']+)'", line)
                if not match:
                    continue

                func_name = match.group(1)
                signature = match.group(2)

                # Skip main function (can't be hot reloaded)
                if func_name == "main":
                    continue

                # Skip macros (usually all uppercase like BENCHMARK, DEFINE_FACTORY, etc.)
                if func_name.isupper() and len(func_name) > 2:
                    continue

                # Skip destructors (identified by ~ prefix)
                if func_name.startswith("~"):
                    continue

                # Skip internal/compiler functions (__ prefix)
                if func_name.startswith("__"):
                    continue

                # Skip template instantiations (have < in signature)
                if "<" in signature:
                    continue

                # Skip class methods (have :: in name)
                # Extract the part before first paren (if any)
                name_part = func_name.split("(")[0] if "(" in func_name else func_name
                if "::" in name_part:
                    continue

                # This function passes all filters - add it
                if func_name not in functions:
                    functions.append(func_name)

            self.log(f"  AST found {len(functions)} hotreloadable functions")
            return functions

        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Clang AST dump timed out after 15 seconds for {source_path}"
            )
        except FileNotFoundError as e:
            raise RuntimeError(
                f"Clang compiler not found: {compiler}. Ensure clang++ is installed and in PATH."
            ) from e
        except Exception as e:
            raise RuntimeError(f"AST parsing failed for {source_path}: {str(e)}") from e

    def compile_file_to_shared_lib(
        self,
        source_file: str | Path,
        compile_flags: Optional[List[str]] = None,
        functions_to_compile: Optional[List[str]] = None,
    ) -> Optional[Tuple[Path, Dict[str, int]]]:

        if compile_flags is None:
            compile_flags = self.load_compile_commands(source_file)
            if compile_flags is None:
                raise RuntimeError(
                    f"No compile_commands.json found for {source_file}. Hot reloading requires a compilation database."
                )

        source_path: Path = Path(source_file).resolve()
        with open(source_path, "rb") as f:
            content_hash: str = hashlib.md5(f.read()).hexdigest()[:8]

        lib_name: str = f"hotreload_{source_path.stem}_{content_hash}"
        temp_so: Path = self.cache_dir / f"{lib_name}.so"

        with open(source_path) as f:
            original_content: str = f.read()

        # Use provided functions list or discover them via AST
        if functions_to_compile is None:
            functions: List[str] = self.find_all_functions_in_file(source_path)
        else:
            functions: List[str] = functions_to_compile

        modified_content = original_content
        for func_name in functions:
            pattern: str = (
                rf"\b(\w+(?:\s*<[^>]+>)?(?:\s*::\s*\w+)*)\s+({re.escape(func_name)})\s*\(([^)]*)\)\s*({{)"
            )

            def rename_func(match):
                return_type = match.group(1)
                old_name = match.group(2)
                params = match.group(3)
                opening_brace = match.group(4)
                new_name = f"{old_name}_hotreload_{content_hash}"
                return f"{return_type} {new_name}({params}) {opening_brace}"

            modified_content = re.sub(pattern, rename_func, modified_content)

        temp_modified_cpp: Path = self.cache_dir / f"{lib_name}.cpp"

        function_line_map: Dict[str, int] = {}
        current_line = 1

        with open(temp_modified_cpp, "w") as f:
            f.write(f"// AUTO-GENERATED by lldbhotreload\n")
            f.write(f"// Source: {source_path}\n")
            f.write(f"// \n")
            f.write(
                f"// This file is generated for hot-reloading. To modify and hot reload again,\n"
            )
            f.write(f"// edit the original file: {source_path.name}\n")
            f.write(f"// \n")
            f.write(
                f"// NOTE: This file contains ALL code from the original source (including main,\n"
            )
            f.write(
                f"// globals, etc.) to preserve dependencies. Only the hot-reloaded functions\n"
            )
            f.write(
                f"// are actually used - they're extracted via dlsym() at runtime.\n"
            )
            f.write(f"// \n\n")
            current_line += 11

            f.write("// Forward declarations for renamed functions\n")
            current_line += 1
            for func_name in functions:
                pattern_for_sig = rf"\b(\w+(?:\s*<[^>]+>)?(?:\s*::\s*\w+)*)\s+({re.escape(func_name)})\s*\(([^)]*)\)\s*{{"
                match = re.search(pattern_for_sig, original_content)
                if match:
                    return_type = match.group(1)
                    params = match.group(3)
                    f.write(
                        f"{return_type} {func_name}_hotreload_{content_hash}({params});\n"
                    )
                    current_line += 1

            f.write("\n")
            current_line += 1

            f.write("// Inline wrappers for original function names\n")
            current_line += 1
            for func_name in functions:
                pattern_for_sig = rf"\b(\w+(?:\s*<[^>]+>)?(?:\s*::\s*\w+)*)\s+({re.escape(func_name)})\s*\(([^)]*)\)\s*{{"
                match = re.search(pattern_for_sig, original_content)
                if match:
                    return_type = match.group(1)
                    params = match.group(3)

                    if params.strip():
                        param_names = [
                            re.split(r"\s+", p.strip())[-1].rstrip("*&[]")
                            for p in params.split(",")
                        ]
                        param_call = ", ".join(param_names)
                    else:
                        param_call = ""

                    f.write(f"inline {return_type} {func_name}({params}) {{\n")
                    f.write(
                        f"    return {func_name}_hotreload_{content_hash}({param_call});\n"
                    )
                    f.write("}\n\n")
                    current_line += 4

            f.write(f'#line 1 "{source_path}"\n')
            current_line += 1

            for line in modified_content.split("\n"):
                f.write(line + "\n")

                for func_name in functions:
                    renamed_func = f"{func_name}_hotreload_{content_hash}"
                    if renamed_func in line and "(" in line and "{" in line:
                        function_line_map[func_name] = current_line + 1

                current_line += 1

            # Add extern "C" wrappers at the END that we can lookup with dlsym
            f.write('\n\nextern "C" {\n')
            for func_name in functions:
                f.write(f"void* __{func_name}_hotreload_{content_hash}_ptr() {{\n")
                f.write(f"    return (void*)&{func_name}_hotreload_{content_hash};\n")
                f.write("}\n")
            f.write("}\n")

        # Extract the real compiler from compilation database
        # Some build systems use wrapper scripts (e.g., ccache, distcc)
        # that pass the real compiler via --cc= flag
        compiler: str = compile_flags[0]
        for flag in compile_flags:
            if flag.startswith("--cc="):
                compiler = flag.split("=", 1)[1]
                break

        # Require clang++ compiler
        if not compiler.endswith("clang++"):
            raise RuntimeError(
                f"Compiler must be clang++, but got: {compiler}. Hot reloading requires clang for compilation."
            )

        # Filter out flags that conflict with our compilation
        # We only remove flags that specify input/output files
        # All compiler flags (includes, defines, warnings, optimizations) are preserved
        filtered_flags: List[str] = []
        skip_next: bool = False

        for flag in compile_flags[1:]:
            if skip_next:
                skip_next = False
                continue

            # Skip output file specification (we provide our own)
            if flag in ["-o"]:
                skip_next = True
                continue

            # Skip compile-only flag (we control this explicitly)
            if flag == "-c":
                continue

            # Skip input source files (we provide our own)
            if flag.endswith((".cpp", ".cc", ".c", ".cxx", ".o", ".a")):
                continue

            # Skip wrapper-specific flags that are not actual compiler flags
            # These are used by build system wrappers but not recognized by clang++
            if flag.startswith("--cc=") or flag.startswith("--log-"):
                continue

            filtered_flags.append(flag)

        # TWO-STEP COMPILATION: Separate compile and link phases
        # This avoids issues with build-system-specific linker flags (ASAN, custom paths, etc.)
        # and ensures we create a clean, portable shared library

        # Step 1: Compile to object file (.o) using all build system flags
        # This preserves all include paths, defines, and compiler settings from the original build
        temp_obj: Path = self.cache_dir / f"{lib_name}.o"

        cmd_compile: List[str] = [
            compiler,
            "-c",  # Compile only, no linking
            *filtered_flags,
            "-fPIC",
            "-o",
            str(temp_obj),
            str(temp_modified_cpp),
        ]

        self.log(f"  → {' '.join(cmd_compile)}")

        # Ensure PATH includes standard compiler locations
        env = os.environ.copy()
        env["PATH"] = "/usr/bin:/usr/local/bin:" + env.get("PATH", "")

        result: subprocess.CompletedProcess[str] = subprocess.run(
            cmd_compile, capture_output=True, text=True, timeout=30, env=env
        )
        if result.returncode != 0:
            self.log(f"✗ Compilation failed:\n{result.stderr}")
            return None

        # Step 2: Link object file to shared library (.so) using minimal flags
        # Let the compiler use its default library paths to avoid compatibility issues
        cmd_link: List[str] = [
            compiler,
            "-shared",
            "-o",
            str(temp_so),
            str(temp_obj),
        ]

        self.log(f"  → {' '.join(cmd_link)}")

        result = subprocess.run(
            cmd_link, capture_output=True, text=True, timeout=30, env=env
        )
        if result.returncode != 0:
            self.log(f"✗ Linking failed:\n{result.stderr}")
            return None

        return (temp_so, function_line_map)

    def load_shared_library(self, so_path: Path) -> int:
        thread: Any = self.process.GetSelectedThread()
        if not thread.IsValid():
            return 0

        frame: Any = thread.GetSelectedFrame()
        if not frame.IsValid():
            return 0

        options: Any = lldb.SBExpressionOptions()
        options.SetIgnoreBreakpoints(True)
        options.SetTryAllThreads(True)
        options.SetTimeoutInMicroSeconds(5000000)

        dlopen_cmd = f'(void*)dlopen("{so_path}", 2 | 256)'
        self.log(f"  → {dlopen_cmd}")

        result: Any = frame.EvaluateExpression(dlopen_cmd, options)
        if not result.GetError().Success():
            self.log(
                f"  ⚠ Expression evaluation warning: {result.GetError().GetCString()}"
            )
            # Don't return 0 here - check the handle value instead

        handle: int = result.GetValueAsUnsigned()
        if handle == 0:
            dlerror_result: Any = frame.EvaluateExpression("(char*)dlerror()", options)
            error_msg: str = "unknown error"
            if dlerror_result.GetError().Success():
                error_addr: int = dlerror_result.GetValueAsUnsigned()
                if error_addr:
                    try:
                        error: Any = lldb.SBError()
                        error_msg = self.process.ReadCStringFromMemory(
                            error_addr, 512, error
                        )
                        if not error.Success():
                            error_msg = (
                                f"unknown error (failed to read: {error.GetCString()})"
                            )
                    except Exception as e:
                        error_msg = f"unknown error (exception: {e})"

            if "undefined symbol" in error_msg:
                self.log(f"✗ dlopen() failed: {error_msg}")
                self.log("")
                self.log("⚠ HINT: Build with -rdynamic")
                self.log(
                    "  Example: clang++ -rdynamic -g -O0 your_files.cpp -o your_program"
                )
            else:
                self.log(f"✗ dlopen() failed: {error_msg}")
            return 0

        self.log(f"  → dlopen() returned handle 0x{handle:x}")

        self.loaded_libs[str(so_path)] = handle

        so_name = so_path.name
        module = None
        for existing_module in self.target.module_iter():
            if existing_module.GetFileSpec().GetFilename() == so_name:
                module = existing_module
                self.log(f"  → LLDB auto-detected module: {so_name}")
                break

        if not module:
            error = lldb.SBError()
            module = self.target.AddModule(
                str(so_path), lldb.LLDB_ARCH_DEFAULT, None, None
            )
            if module and module.IsValid():
                self.log(f"  → Manually added module to LLDB: {so_name}")
                self.loaded_libs[f"{so_path}_module"] = module
            else:
                self.log(f"  ⚠ Warning: Could not add module to LLDB")

        return handle

    def unload_shared_library(self, lib_handle: int) -> bool:
        thread: Any = self.process.GetSelectedThread()
        if not thread.IsValid():
            return False

        frame: Any = thread.GetSelectedFrame()
        if not frame.IsValid():
            return False

        options: Any = lldb.SBExpressionOptions()
        options.SetIgnoreBreakpoints(True)
        options.SetTryAllThreads(True)
        options.SetTimeoutInMicroSeconds(5000000)

        dlclose_cmd = f"(int)dlclose((void*)0x{lib_handle:x})"
        self.log(f"  → {dlclose_cmd}")

        result: Any = frame.EvaluateExpression(dlclose_cmd, options)
        if not result.GetError().Success():
            self.log(f"  ✗ dlclose() failed: {result.GetError().GetCString()}")
            return False

        ret_val: int = result.GetValueAsSigned()
        if ret_val != 0:
            dlerror_result: Any = frame.EvaluateExpression("(char*)dlerror()", options)
            error_msg: str = "unknown error"
            if dlerror_result.GetError().Success():
                error_addr: int = dlerror_result.GetValueAsUnsigned()
                if error_addr:
                    try:
                        error: Any = lldb.SBError()
                        error_msg = self.process.ReadCStringFromMemory(
                            error_addr, 512, error
                        )
                        if not error.Success():
                            error_msg = (
                                f"unknown error (failed to read: {error.GetCString()})"
                            )
                    except Exception as e:
                        error_msg = f"unknown error (exception: {e})"
            self.log(f"  ✗ dlclose() returned {ret_val}: {error_msg}")
            return False

        self.log(f"  → dlclose() succeeded")
        return True

    def resolve_function_address(
        self, lib_handle: int, function_name: str, content_hash: str
    ) -> Optional[Dict[str, Optional[int]]]:
        thread: Any = self.process.GetSelectedThread()
        frame: Any = thread.GetSelectedFrame()

        base_name: str = (
            function_name.split("(")[0] if "(" in function_name else function_name
        )

        wrapper_name: str = f"__{base_name}_hotreload_{content_hash}_ptr"

        options: Any = lldb.SBExpressionOptions()
        options.SetIgnoreBreakpoints(True)
        options.SetTryAllThreads(True)
        options.SetTimeoutInMicroSeconds(5000000)

        dlsym_cmd = f'((void*(*)())dlsym((void*)0x{lib_handle:x}, "{wrapper_name}"))())'
        self.log(f"  → {dlsym_cmd}")

        result: Any = frame.EvaluateExpression(dlsym_cmd, options)
        if not result.GetError().Success():
            self.log(f"  ✗ dlsym() failed: {result.GetError().GetCString()}")
            return None

        func_addr: int = result.GetValueAsUnsigned()
        if func_addr == 0:
            self.log(f"  ✗ dlsym() returned NULL for {wrapper_name}")
            return None

        self.log(f"  → Resolved {function_name} to 0x{func_addr:x}")
        return {"wrapper": func_addr, "actual": func_addr}

    def analyze_function_state(self, frame: Any, func_addr: int) -> Tuple[int, str]:
        pc: int = frame.GetPC()
        offset: int = pc - func_addr

        if offset == 0:
            return (0, "at entry")

        function: Any = frame.GetFunction()
        if function.IsValid():
            prologue_size: int = function.GetPrologueByteSize()
            if prologue_size > 0 and offset < prologue_size:
                return (0, "in prologue")

        try:
            variables: Any = frame.GetVariables(False, True, False, True)
            initialized_count: int = sum(
                1 for var in variables if var.GetValue() is not None
            )
            if initialized_count == 0:
                return (1, "no locals")
            return (2, f"{initialized_count} locals initialized")
        except Exception:
            return (3, "unknown state")

    def is_function_on_stack(self, function_name: str) -> bool:
        for thread_idx in range(self.process.GetNumThreads()):
            thread: Any = self.process.GetThreadAtIndex(thread_idx)
            for frame_idx in range(thread.GetNumFrames()):
                frame: Any = thread.GetFrameAtIndex(frame_idx)
                frame_func: Any = frame.GetFunction()
                if frame_func:
                    frame_func_name: str = frame_func.GetName()
                    if (
                        frame_func_name == function_name
                        or function_name in frame_func_name
                    ):
                        return True
        return False

    def patch_function(
        self, old_addr: int, old_end_addr: int, new_addr: int, function_name: str
    ) -> bool:
        TRAMPOLINE_SIZE: int = 12  # movabsq (10 bytes) + jmp *%rax (2 bytes)

        func_size: int = (
            old_end_addr - old_addr if old_end_addr > old_addr else TRAMPOLINE_SIZE
        )

        # CRITICAL: Remove any breakpoints at the original function address
        # Breakpoints can interfere with trampoline execution, causing PC to skip
        # past the first instruction (movabsq) and jump directly to the jmp *%rax
        breakpoints_removed = 0
        for bp_idx in range(self.target.GetNumBreakpoints()):
            breakpoint: Any = self.target.GetBreakpointAtIndex(bp_idx)
            if not breakpoint.IsValid():
                continue

            for loc_idx in range(breakpoint.GetNumLocations()):
                location: Any = breakpoint.GetLocationAtIndex(loc_idx)
                loc_addr: int = location.GetLoadAddress()

                # Check if this breakpoint is at or within the function being patched
                if loc_addr >= old_addr and loc_addr < old_addr + func_size:
                    self.log(
                        f"  → Removing breakpoint #{breakpoint.GetID()} at 0x{loc_addr:x} (conflicts with trampoline)"
                    )
                    self.target.BreakpointDelete(breakpoint.GetID())
                    breakpoints_removed += 1
                    break  # Break inner loop since we deleted the breakpoint

        if breakpoints_removed > 0:
            self.log(f"  → Removed {breakpoints_removed} conflicting breakpoint(s)")
            # Clear memory first after removing breakpoints
            nop_clear = bytes([0x90] * TRAMPOLINE_SIZE)
            clear_error = lldb.SBError()
            self.process.WriteMemory(old_addr, nop_clear, clear_error)

        if func_size < TRAMPOLINE_SIZE:
            self.log(
                f"⚠ {function_name}: Function too small ({func_size} bytes), patching entry only"
            )
            trampoline = (
                bytes([0x48, 0xB8]) + struct.pack("<Q", new_addr) + bytes([0xFF, 0xE0])
            )

            trampoline_hex = " ".join(f"{b:02x}" for b in trampoline)
            self.log(
                f"  → WriteMemory(0x{old_addr:x}, [{trampoline_hex}], {len(trampoline)} bytes)"
            )
            self.log(f"     Disassembly: movabsq $0x{new_addr:x}, %rax; jmp *%rax")

            error: Any = lldb.SBError()
            self.process.WriteMemory(old_addr, trampoline, error)
            if not error.Success():
                self.log(
                    f"✗ Failed to write JMP for {function_name}: {error.GetCString()}"
                )
                return False
        else:
            trampoline = (
                bytes([0x48, 0xB8])  # movabsq imm64, %rax (10 bytes)
                + struct.pack("<Q", new_addr)
                + bytes([0xFF, 0xE0])
            )

            # Build buffer: trampoline first, then NOPs to fill the rest
            patch_buffer = bytearray()
            patch_buffer.extend(trampoline)

            # Fill remaining space with NOPs
            remaining_size = func_size - TRAMPOLINE_SIZE
            patch_buffer.extend(bytes([0x90] * remaining_size))

            trampoline_hex = " ".join(f"{b:02x}" for b in trampoline)
            self.log(f"  → WriteMemory(0x{old_addr:x}, {func_size} bytes)")
            self.log(
                f"     Disassembly: movabsq $0x{new_addr:x}, %rax; jmp *%rax; nop×{remaining_size}"
            )

            error: Any = lldb.SBError()
            buffer_bytes = bytes(patch_buffer)

            self.process.WriteMemory(old_addr, buffer_bytes, error)

            if not error.Success():
                self.log(
                    f"✗ Failed to write JMP for {function_name}: {error.GetCString()}"
                )
                return False

            # Verify write succeeded (LLDB bug: deleted breakpoints can corrupt writes)
            verify_bytes = self.process.ReadMemory(old_addr, 12, error)
            if verify_bytes and verify_bytes[10:12] != bytes([0xFF, 0xE0]):
                self.log(f"     ⚠ WARNING: Memory write corrupted, restart debugger")

        self.patched_functions[function_name] = {
            "old_addr": old_addr,
            "new_addr": new_addr,
            "timestamp": time.time(),
        }

        return True

    def refresh_breakpoints_for_source(
        self,
        source_file: str | Path,
        patched_functions_info: Dict[str, Dict[str, Any]],
        new_module: Any,
    ) -> int:
        source_path: str = str(Path(source_file).resolve())
        source_filename: str = Path(source_file).name
        refreshed_count: int = 0
        breakpoints_to_update: List[Dict[str, Any]] = []

        self.log(
            f"  Checking {self.target.GetNumBreakpoints()} breakpoints for refresh..."
        )

        for bp_idx in range(self.target.GetNumBreakpoints()):
            breakpoint: Any = self.target.GetBreakpointAtIndex(bp_idx)
            if not breakpoint.IsValid():
                continue

            for loc_idx in range(breakpoint.GetNumLocations()):
                location: Any = breakpoint.GetLocationAtIndex(loc_idx)
                address: Any = location.GetAddress()
                if not address.IsValid():
                    continue

                line_entry: Any = address.GetLineEntry()
                if not line_entry.IsValid():
                    continue

                if line_entry.GetFileSpec().GetFilename() != source_filename:
                    continue

                symbol: Any = address.GetSymbol()
                if not symbol.IsValid():
                    continue

                bp_func_name: str = symbol.GetName()
                if bp_func_name not in patched_functions_info:
                    continue

                func_info: Dict[str, Any] = patched_functions_info[bp_func_name]
                offset: int = (
                    address.GetLoadAddress(self.target) - func_info["old_addr"]
                )
                new_bp_addr: int = func_info["new_addr"] + offset

                breakpoints_to_update.append(
                    {
                        "breakpoint": breakpoint,
                        "old_line": line_entry.GetLine(),
                        "source_file": source_path,
                        "new_addr": new_bp_addr,
                    }
                )
                break

        if breakpoints_to_update:
            self.log(f"  Refreshing {len(breakpoints_to_update)} breakpoint(s)...")

        for bp_info in breakpoints_to_update:
            old_bp: Any = bp_info["breakpoint"]
            line_num: int = bp_info["old_line"]
            is_enabled: bool = old_bp.IsEnabled()
            condition: Optional[str] = old_bp.GetCondition()
            ignore_count: int = old_bp.GetIgnoreCount()

            self.target.BreakpointDelete(old_bp.GetID())
            new_bp: Any = self.target.BreakpointCreateByLocation(source_path, line_num)

            if new_module and new_module.IsValid():
                for loc_idx in range(new_bp.GetNumLocations()):
                    location: Any = new_bp.GetLocationAtIndex(loc_idx)
                    loc_module: Any = location.GetAddress().GetModule()
                    if (
                        loc_module.IsValid()
                        and loc_module.GetFileSpec().GetFilename()
                        != new_module.GetFileSpec().GetFilename()
                    ):
                        location.SetEnabled(False)

            if new_bp.IsValid():
                new_bp.SetEnabled(is_enabled)
                if condition:
                    new_bp.SetCondition(condition)
                new_bp.SetIgnoreCount(ignore_count)
                refreshed_count += 1

        return refreshed_count

    def attach_breakpoint_callbacks(self) -> int:
        count = 0
        for bp_idx in range(self.target.GetNumBreakpoints()):
            breakpoint = self.target.GetBreakpointAtIndex(bp_idx)
            if not breakpoint.IsValid():
                continue

            breakpoint.SetScriptCallbackFunction("hotreload.breakpoint_callback")
            count += 1

        if count > 0:
            self.log(f"  → Attached callback to {count} breakpoint(s)")

        return count

    def hotreload_file(
        self, source_file: str | Path, compile_flags: Optional[List[str]] = None
    ) -> Tuple[int, int]:
        global _PATCHED_FILE_HASHES, _FUNCTION_INFO

        if not self.target.IsValid() or not self.process.IsValid():
            self.log("✗ No valid target/process")
            return (0, 0)

        source_path: Path = Path(source_file).resolve()
        if not source_path.exists():
            self.log(f"✗ File not found: {source_file}")
            return (0, 0)

        with open(source_path, "rb") as f:
            current_hash: str = hashlib.md5(f.read()).hexdigest()[:8]

        source_key: str = str(source_path)

        self.log(f"Hot reloading: {source_path.name}")

        # Use AST to find hotreloadable functions (most accurate)
        ast_functions: List[str] = self.find_all_functions_in_file(source_path)

        if not ast_functions:
            self.log("✗ No hotreloadable functions found")
            return (0, 0)

        self.log(
            f"  Found {len(ast_functions)} hotreloadable function(s): {ast_functions}"
        )

        # Now use DWARF to get addresses for the AST-discovered functions
        all_dwarf_functions: List[Dict[str, Any]] = self.find_functions_from_dwarf(
            source_path
        )

        # Filter DWARF results to only include AST-discovered functions
        # Need to match by base name since DWARF has signatures like "addOne(int)"
        # but AST has just "addOne"
        dwarf_functions: List[Dict[str, Any]] = []
        for dwarf_func in all_dwarf_functions:
            dwarf_name = dwarf_func["name"]
            # Extract base name (before parenthesis)
            base_name = dwarf_name.split("(")[0] if "(" in dwarf_name else dwarf_name

            # Check if this function was found by AST
            if base_name in ast_functions:
                dwarf_functions.append(dwarf_func)

        if not dwarf_functions:
            self.log(
                "✗ No DWARF symbols found for hotreloadable functions (compile with -g)"
            )
            return (0, 0)

        skipped_on_stack: List[str] = []
        for func_info in dwarf_functions:
            func_name: str = func_info["name"]
            original_addr: Optional[int] = func_info.get("addr")

            if not original_addr:
                symbols: Any = self.target.FindFunctions(func_name)
                if symbols.GetSize() == 0:
                    continue
                original_addr = (
                    symbols.GetContextAtIndex(0)
                    .GetSymbol()
                    .GetStartAddress()
                    .GetLoadAddress(self.target)
                )

            if original_addr:
                is_on_stack: bool = self.is_function_on_stack(func_name)
                if is_on_stack:
                    skipped_on_stack.append(func_name)
                    self.log(f"  DEBUG: {func_name} is on stack, skipping")

        if skipped_on_stack:
            self.log(
                f"⚠ {len(skipped_on_stack)} function(s) on stack (set breakpoint outside to reload)"
            )
            return (0, len(dwarf_functions))

        self.log(f"  Compiling .so...")

        old_so_handle: Optional[int] = None
        for func_info in dwarf_functions:
            func_name = func_info["name"]
            if func_name in _FUNCTION_INFO:
                old_so_handle = _FUNCTION_INFO[func_name]["current_so_handle"]
                break

        compile_result = self.compile_file_to_shared_lib(
            source_path, compile_flags, functions_to_compile=ast_functions
        )
        if not compile_result:
            self.log("✗ Compilation failed")
            return (0, 0)

        so_path, function_line_map = compile_result
        self.log(f"  Compiled to {so_path}")

        content_hash = so_path.stem.split("_")[-1]

        lib_handle: int = self.load_shared_library(so_path)
        if lib_handle == 0:
            self.log("✗ Failed to load library")
            return (0, len(dwarf_functions))

        if old_so_handle:
            if not self.unload_shared_library(old_so_handle):
                self.log("  ⚠ Warning: Failed to unload old .so")

        refresh_cmd = "target modules list"
        result = lldb.SBCommandReturnObject()
        self.debugger.GetCommandInterpreter().HandleCommand(refresh_cmd, result)

        success_count: int = 0

        for func_info in dwarf_functions:
            func_name = func_info["name"]
            original_addr = func_info.get("addr")
            original_end_addr = func_info.get("end_addr", 0)

            self.log(f"  Processing {func_name} @ 0x{original_addr:x}")

            if not original_addr:
                symbols = self.target.FindFunctions(func_name)
                if symbols.GetSize() == 0:
                    continue
                sym = symbols.GetContextAtIndex(0).GetSymbol()
                original_addr = sym.GetStartAddress().GetLoadAddress(self.target)
                end_addr = sym.GetEndAddress()
                if end_addr.IsValid():
                    original_end_addr = end_addr.GetLoadAddress(self.target)

            if not original_addr:
                continue

            addr_info: Optional[Dict[str, Optional[int]]] = (
                self.resolve_function_address(lib_handle, func_name, content_hash)
            )
            if not addr_info:
                continue

            wrapper_addr: int = addr_info["wrapper"]

            if func_name not in _FUNCTION_INFO:
                self.log(
                    f"  Patching {func_name}: 0x{original_addr:x} → 0x{wrapper_addr:x}"
                )
                _FUNCTION_INFO[func_name] = {"original_addr": original_addr}
            else:
                self.log(
                    f"  Re-patching {func_name}: 0x{original_addr:x} → 0x{wrapper_addr:x}"
                )

            self.patch_function(
                original_addr, original_end_addr, wrapper_addr, func_name
            )

            _FUNCTION_INFO[func_name]["current_so_handle"] = lib_handle
            _FUNCTION_INFO[func_name]["current_wrapper"] = wrapper_addr
            _FUNCTION_INFO[func_name]["line_number"] = func_info.get("line")

            global _HOTRELOADED_FUNCTIONS
            _HOTRELOADED_FUNCTIONS.add(func_name)

            success_count += 1

        if success_count > 0:
            self.log(f"✓ Patched {success_count}/{len(dwarf_functions)} functions")

            self.attach_breakpoint_callbacks()

            self.log("")
            self.log("=" * 60)
            self.log(f"  ✓ Hot reload complete!")
            self.log(
                f"  Breakpoints in {source_path.name} will now hit hot-reloaded code"
            )
            self.log(f"  Set breakpoints in the original source file as usual:")
            self.log(f"    (lldb) b {source_path.name}:<line>")
            self.log("=" * 60)

            _PATCHED_FILE_HASHES[source_key] = current_hash
        else:
            self.log("⚠ No functions patched")

        return (success_count, len(dwarf_functions))


def hotreload_file(
    debugger: Any, command: str, result: Any, _internal_dict: Dict[str, Any]
) -> None:
    args: List[str] = command.split()

    if len(args) < 1:
        result.AppendMessage("Usage: hotreload <source_file> [flags...]")
        result.AppendMessage("\nExamples:")
        result.AppendMessage("  hotreload example.cpp")
        result.AppendMessage("  hotreload demo.cpp -std=c++17 -O0")
        return

    source_file: str = args[0]
    compile_flags: Optional[List[str]] = args[1:] if len(args) > 1 else None

    hr: FileHotReload = FileHotReload(debugger, result)
    hr.hotreload_file(source_file, compile_flags)


def __lldb_init_module(debugger: Any, _internal_dict: Dict[str, Any]) -> None:
    debugger.HandleCommand("command script add -f hotreload.hotreload_file hotreload")
