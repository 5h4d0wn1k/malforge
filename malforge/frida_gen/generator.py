"""Frida hook snippet generator.

Generates .js hooking snippets from a config. Syntax-validates with a
lightweight regex-based parser (no external deps).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class HookConfig:
    module: str = ""
    function: str = ""
    action: str = "log"  # log, replace, block
    replacement_value: str = ""
    log_args: bool = True
    log_return: bool = True


@dataclass
class FridaSnippet:
    config: HookConfig = field(default_factory=HookConfig)
    js_code: str = ""
    syntax_valid: bool = False
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "module": self.config.module,
            "function": self.config.function,
            "action": self.config.action,
            "js_code": self.js_code,
            "syntax_valid": self.syntax_valid,
            "errors": self.errors,
        }


def _validate_js_syntax(code: str) -> list[str]:
    """Lightweight JS syntax validation (brace/paren matching)."""
    errors = []
    stack = []
    pairs = {")": "(", "}": "{", "]": "["}
    in_string = False
    string_char = ""
    prev = ""

    for i, ch in enumerate(code):
        if in_string:
            if ch == string_char and prev != "\\":
                in_string = False
            prev = ch
            continue
        if ch in ('"', "'", "`"):
            in_string = True
            string_char = ch
            prev = ch
            continue
        if ch in "({[":
            stack.append(ch)
        elif ch in ")}]":
            if not stack or stack[-1] != pairs.get(ch):
                errors.append(f"Unmatched '{ch}' at position {i}")
            else:
                stack.pop()
        prev = ch

    if stack:
        errors.append(f"Unclosed brackets: {''.join(stack)}")
    return errors


class FridaGenerator:
    """Generate Frida JS hook snippets from config."""

    def generate(self, config: HookConfig) -> FridaSnippet:
        if config.action == "log":
            js = self._gen_log_hook(config)
        elif config.action == "replace":
            js = self._gen_replace_hook(config)
        elif config.action == "block":
            js = self._gen_block_hook(config)
        else:
            js = f"// Unknown action: {config.action}"

        errors = _validate_js_syntax(js)
        return FridaSnippet(
            config=config,
            js_code=js,
            syntax_valid=len(errors) == 0,
            errors=errors,
        )

    def generate_batch(self, configs: list[HookConfig]) -> list[FridaSnippet]:
        return [self.generate(c) for c in configs]

    def _gen_log_hook(self, c: HookConfig) -> str:
        args_str = ""
        ret_str = ""
        if c.log_args:
            args_str = f"""
    console.log("[HOOK] {c.module}!{c.function} called with args: " +
                Array.from(arguments).map(x => x.toString()).join(", "));"""
        if c.log_return:
            ret_str = f"""
    console.log("[HOOK] {c.module}!{c.function} returned: " + retval);"""

        return f"""Interceptor.attach(Module.findExportByName("{c.module}", "{c.function}"), {{
    onEnter: function(args) {{{args_str}
    }},
    onLeave: function(retval) {{{ret_str}
    }}
}});"""

    def _gen_replace_hook(self, c: HookConfig) -> str:
        val = c.replacement_value or "0"
        return f"""Interceptor.attach(Module.findExportByName("{c.module}", "{c.function}"), {{
    onLeave: function(retval) {{
        retval.replace({val});
        console.log("[HOOK] {c.module}!{c.function} replaced with {val}");
    }}
}});"""

    def _gen_block_hook(self, c: HookConfig) -> str:
        return f"""Interceptor.attach(Module.findExportByName("{c.module}", "{c.function}"), {{
    onEnter: function(args) {{
        console.log("[HOOK] {c.module}!{c.function} BLOCKED");
        return NULL;
    }}
}});"""

    def save_snippet(self, snippet: FridaSnippet, path: str) -> None:
        with open(path, "w") as f:
            f.write(snippet.js_code)
