#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import re
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

    if not module_name.startswith("hotreload_"):
        return False

    return True


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
                                parts: List[str] = entry.get("command", "").split()
                                if not parts:
                                    continue
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
        with open(source_file) as f:
            content: str = f.read()

        pattern: str = (
            r"\b(\w+(?:\s*<[^>]+>)?(?:\s*::\s*\w+)*)\s+(\w+)\s*\([^)]*\)\s*(?:const)?\s*(?:override)?\s*\{"
        )
        functions: List[str] = []

        for match in re.finditer(pattern, content):
            return_type: str = match.group(1).strip()
            func_name: str = match.group(2).strip()
            if (
                func_name != "main"
                and not func_name.startswith("~")
                and return_type not in ["", func_name]
                and not func_name.startswith("__")
            ):
                functions.append(func_name)

        return functions

    def compile_file_to_shared_lib(
        self, source_file: str | Path, compile_flags: Optional[List[str]] = None,
        function_line_info: Optional[Dict[str, int]] = None
    ) -> Optional[Tuple[Path, Dict[str, int]]]:

        if compile_flags is None:
            compile_flags = self.load_compile_commands(source_file)
            if compile_flags is None:
                compile_flags = ["clang++", "-std=c++17", "-O0", "-g"]

        source_path: Path = Path(source_file).resolve()
        with open(source_path, "rb") as f:
            content_hash: str = hashlib.md5(f.read()).hexdigest()[:8]

        lib_name: str = f"hotreload_{source_path.stem}_{content_hash}"
        temp_so: Path = self.cache_dir / f"{lib_name}.so"

        with open(source_path) as f:
            original_content: str = f.read()

        functions: List[str] = self.find_all_functions_in_file(source_path)

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

        compiler: str = compile_flags[0]
        filtered_flags: List[str] = []
        skip_next: bool = False

        for flag in compile_flags[1:]:
            if skip_next:
                skip_next = False
                continue
            if flag in ["-o", "-c"]:
                skip_next = True
                continue
            if flag.endswith((".cpp", ".cc", ".c", ".o")):
                continue
            filtered_flags.append(flag)

        cmd_compile: List[str] = [
            compiler,
            *filtered_flags,
            "-fPIC",
            "-shared",
            "-o",
            str(temp_so),
            str(temp_modified_cpp),
        ]

        self.log(f"  → {' '.join(cmd_compile)}")

        result: subprocess.CompletedProcess[str] = subprocess.run(
            cmd_compile, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            self.log(f"✗ Compilation failed:\n{result.stderr}")
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
            self.log(f"  ⚠ Expression evaluation warning: {result.GetError().GetCString()}")
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
                self.log("  Example: clang++ -rdynamic -g -O0 your_files.cpp -o your_program")
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
            self.log(f"     [{trampoline_hex}] + {remaining_size} NOPs")
            self.log(
                f"     Disassembly: movabsq $0x{new_addr:x}, %rax; jmp *%rax; nop×{remaining_size}"
            )

            error: Any = lldb.SBError()
            bytes_written = self.process.WriteMemory(
                old_addr, bytes(patch_buffer), error
            )

            if not error.Success():
                self.log(
                    f"✗ Failed to write JMP for {function_name}: {error.GetCString()}"
                )
                return False

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

        dwarf_functions: List[Dict[str, Any]] = self.find_functions_from_dwarf(
            source_path
        )

        dwarf_functions = [
            f
            for f in dwarf_functions
            if not f["name"].startswith("__")
            and not f["name"].startswith("_GLOBAL__sub_I_")
            and f["name"] != "main"
        ]

        if not dwarf_functions:
            self.log("✗ No functions found (compile with -g)")
            return (0, 0)

        self.log(
            f"  Found {len(dwarf_functions)} functions: {[f['name'] for f in dwarf_functions]}"
        )

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

        compile_result = self.compile_file_to_shared_lib(source_path, compile_flags)
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

        new_module: Any = self.loaded_libs.get(f"{so_path}_module")
        if success_count > 0:
            patched_info: Dict[str, Dict[str, Any]] = {}

            for func_info in dwarf_functions:
                func_name = func_info["name"]
                if (
                    func_name in _FUNCTION_INFO
                    and "line_number" in _FUNCTION_INFO[func_name]
                ):
                    patched_info[func_name] = {
                        "line": _FUNCTION_INFO[func_name]["line_number"]
                    }

            deleted_count = 0
            breakpoints_to_delete = []

            for bp_idx in range(self.target.GetNumBreakpoints()):
                breakpoint: Any = self.target.GetBreakpointAtIndex(bp_idx)
                if not breakpoint.IsValid():
                    continue

                if breakpoint.MatchesName("hotreload_auto"):
                    is_current = False
                    for loc_idx in range(breakpoint.GetNumLocations()):
                        location = breakpoint.GetLocationAtIndex(loc_idx)
                        addr = location.GetAddress()
                        if addr.IsValid():
                            symbol = addr.GetSymbol()
                            if symbol.IsValid():
                                symbol_name = symbol.GetName()
                                if f"_hotreload_{content_hash}" in symbol_name:
                                    is_current = True
                                    break

                    if not is_current:
                        breakpoints_to_delete.append(breakpoint.GetID())

            for bp_id in breakpoints_to_delete:
                self.target.BreakpointDelete(bp_id)
                deleted_count += 1

            if deleted_count > 0:
                self.log(
                    f"  Deleted {deleted_count} old breakpoint(s) from previous hot reloads"
                )

            self.log(f"✓ Patched {success_count}/{len(dwarf_functions)} functions")

            so_cpp_file = so_path.with_suffix(".cpp")
            auto_bp_count = 0

            for func_info in dwarf_functions:
                func_name = func_info["name"]
                if func_name not in self.patched_functions:
                    continue

                content_hash = so_path.stem.split("_")[-1]
                base_func_name = (
                    func_name.split("(")[0] if "(" in func_name else func_name
                )
                hotreload_func_name = f"{base_func_name}_hotreload_{content_hash}"

                cmd = f"breakpoint set -n {hotreload_func_name} -K 0"
                result = lldb.SBCommandReturnObject()
                self.debugger.GetCommandInterpreter().HandleCommand(cmd, result)

                if not result.Succeeded():
                    self.log(f"  ⚠ Failed to create breakpoint: {result.GetError()}")
                    continue

                bp = self.target.GetBreakpointAtIndex(
                    self.target.GetNumBreakpoints() - 1
                )

                if bp.IsValid():
                    bp.AddName("hotreload_auto")

                    if bp.GetNumLocations() > 0:
                        auto_bp_count += 1
                        location = bp.GetLocationAtIndex(0)
                        addr = location.GetLoadAddress()
                        line_entry = location.GetAddress().GetLineEntry()
                        if line_entry.IsValid():
                            line_num = line_entry.GetLine()
                            self.log(
                                f"  Auto-breakpoint: {func_name} at {so_cpp_file.name}:{line_num} (addr 0x{addr:x})"
                            )
                        else:
                            self.log(f"  Auto-breakpoint: {func_name} at 0x{addr:x}")
                    else:
                        self.log(
                            f"  ⚠ Breakpoint created but has no locations: {hotreload_func_name}"
                        )
                else:
                    self.log(f"  ⚠ Could not retrieve created breakpoint")

            self.attach_breakpoint_callbacks()

            so_cpp_file = so_path.with_suffix(".cpp")
            self.log("")
            self.log("=" * 60)
            if auto_bp_count > 0:
                self.log(
                    f"  ✓ Created {auto_bp_count} auto-breakpoint(s) in hot-reloaded code"
                )
                self.log(f"  Next 'continue' will hit breakpoints in new code!")
            self.log(f"  Breakpoints in {source_path.name} will now hit hot-reloaded code!")
            self.log(f"  Alternative: b {so_cpp_file.name}:<line>")
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
