#!/usr/bin/env python3
"""
PreToolUse guard: enforces read-only mode for the incident assistant.

Claude Code sends the pending tool call as JSON on stdin. Exit code 2 blocks the
call and the message on stderr is shown to Claude. Exit 0 lets the normal
permission flow continue.

This is defence in depth. The real boundary is the credentials you give the
session (no prod kubeconfig, read-only RBAC). See README.md.
"""
import json
import os
import re
import shlex
import sys

PROJECT_DIR = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
WRITABLE_DIR = os.path.realpath(os.path.join(PROJECT_DIR, "reports"))

# kubectl verbs that only read.
KUBECTL_READ_VERBS = {"get", "describe", "logs", "top", "events", "explain",
                      "version", "api-resources", "api-versions", "cluster-info"}
KUBECTL_READ_SUBCOMMANDS = {
    ("config", "current-context"), ("config", "get-contexts"), ("config", "view"),
    ("auth", "can-i"),
}
# Resources we never read, even with a read verb.
FORBIDDEN_RESOURCES = re.compile(r"(^|,)(secret|secrets)(/|\.|,|$)", re.I)

# Plain shell commands that are safe (read-only) for log inspection.
SAFE_COMMANDS = {"cat", "head", "tail", "grep", "egrep", "rg", "wc", "sort", "uniq",
                 "cut", "awk", "ls", "find", "jq", "less", "date", "echo", "pwd", "tr",
                 "column", "diff", "stat", "file"}
PROD_PATTERN = re.compile(r"prod|prd|live", re.I)


def block(msg: str) -> None:
    print(f"BLOCKED by read-only guard: {msg}", file=sys.stderr)
    sys.exit(2)


def split_segments(cmd: str):
    """Split on shell control operators so each command in a chain is checked."""
    return [s.strip() for s in re.split(r"\|\||&&|;|\||\n", cmd) if s.strip()]


def check_kubectl(tokens):
    args = tokens[1:]
    # Disallow switching context/cluster/kubeconfig on the command line.
    for i, a in enumerate(args):
        if a.startswith(("--kubeconfig", "--context", "--cluster", "--server", "-s=", "--token", "--as")):
            value = a.split("=", 1)[1] if "=" in a else (args[i + 1] if i + 1 < len(args) else "")
            if a.startswith(("--context", "--cluster")) and not PROD_PATTERN.search(value):
                continue  # explicit non-prod context is allowed
            block(f"flag '{a}' is not allowed (no credential/cluster overrides, no prod).")
    positional = [a for a in args if not a.startswith("-")]
    if not positional:
        block("bare kubectl call.")
    verb = positional[0]
    if len(positional) >= 2 and (positional[0], positional[1]) in KUBECTL_READ_SUBCOMMANDS:
        if positional[0] == "config" and positional[1] == "view" and "--raw" in args:
            block("'kubectl config view --raw' exposes credentials.")
        return
    if verb not in KUBECTL_READ_VERBS:
        block(f"'kubectl {verb}' changes or accesses state beyond read-only.")
    if verb in {"get", "describe"} and len(positional) >= 2 and FORBIDDEN_RESOURCES.search(positional[1]):
        block("reading Secrets is not allowed.")
    if "-o" in args or any(a.startswith("--output") for a in args):
        pass  # output formats are fine for non-secret resources


def check_bash(cmd: str):
    if re.search(r"(^|[^<>&0-9])>{1,2}(?!&)", cmd.replace("2>&1", "").replace("2>/dev/null", "")):
        block("output redirection ('>' or '>>') writes files.")
    if "$(" in cmd or "`" in cmd:
        block("command substitution is not allowed.")
    for seg in split_segments(cmd):
        try:
            tokens = shlex.split(seg)
        except ValueError:
            block("could not parse command.")
        if not tokens:
            continue
        # Strip leading env assignments like FOO=bar cmd
        while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
            if tokens[0].startswith(("KUBECONFIG=", "KUBE_CONTEXT=")):
                block("overriding KUBECONFIG is not allowed.")
            tokens = tokens[1:]
        if not tokens:
            continue
        prog = os.path.basename(tokens[0])
        if prog == "kubectl":
            check_kubectl(tokens)
        elif prog in {"python3", "python"}:
            if len(tokens) < 2 or not tokens[1].startswith("tools/"):
                block("only scripts in tools/ may be run with python.")
        elif prog in SAFE_COMMANDS:
            if prog == "find" and any(t in {"-delete", "-exec", "-execdir", "-fprint"} for t in tokens):
                block("find with -delete/-exec is not allowed.")
            if prog == "awk" and re.search(r"system\(|print\s*>|\|\s*\"", seg):
                block("awk with system()/file output is not allowed.")
        else:
            block(f"'{prog}' is not on the read-only allowlist.")


def check_write(path: str):
    if not path:
        block("no path given.")
    real = os.path.realpath(path if os.path.isabs(path) else os.path.join(PROJECT_DIR, path))
    if not (real == WRITABLE_DIR or real.startswith(WRITABLE_DIR + os.sep)):
        block(f"writes are only allowed inside reports/ (got {path}).")


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        block("could not parse hook input.")
    tool = data.get("tool_name", "")
    tin = data.get("tool_input", {}) or {}
    if tool == "Bash":
        check_bash(tin.get("command", ""))
    elif tool == "Write":
        check_write(tin.get("file_path", ""))
    elif tool in {"Edit", "MultiEdit", "NotebookEdit"}:
        block(f"{tool} is disabled in read-only mode.")
    sys.exit(0)


if __name__ == "__main__":
    main()
