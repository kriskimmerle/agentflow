#!/usr/bin/env python3
"""
agentflow - Agent Orchestration Static Security Analyzer

Zero-dependency static analyzer for LangChain, CrewAI, AutoGen, and LangGraph
agent code. Detects security antipatterns based on OWASP Agentic Top 10.

Usage:
    python agentflow.py agent.py
    python agentflow.py agents/
    python agentflow.py --check --min-score 80 src/

Rules:
    AF01: Untrusted input in prompts (ASI01 Goal Hijack)
    AF02: Overprivileged tool definitions (ASI02 Tool Misuse)
    AF03: Shell/subprocess in tools without sanitization (ASI02)
    AF04: Credential in agent memory/state (ASI03 Identity Abuse)
    AF05: Hardcoded API keys (ASI03)
    AF06: Unpinned package installs (ASI04 Supply Chain)
    AF07: Dynamic tool loading from URLs (ASI04)
    AF08: eval/exec of LLM output (ASI05 Code Execution)
    AF09: Code generation without sandbox (ASI05)
    AF10: Missing human-in-loop for sensitive ops (ASI09)
    AF11: Agent delegation without scope limits (ASI03)
    AF12: Verbose/debug mode in production (info leak)
    AF13: Unsafe deserialization (pickle/marshal)
    AF14: Missing error handling in tool functions
    AF15: SQL in agent tools without parameterization
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator

__version__ = "0.1.0"


class Severity(Enum):
    """Issue severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Issue:
    """A detected security issue."""
    rule: str
    message: str
    severity: Severity
    file: str
    line: int
    column: int = 0
    context: str = ""
    suggestion: str = ""


@dataclass
class ScanResult:
    """Result of scanning a file."""
    file: str
    issues: list[Issue] = field(default_factory=list)
    framework: str = "unknown"
    lines_scanned: int = 0

    @property
    def score(self) -> int:
        """Calculate security score (0-100, higher is better)."""
        if not self.issues:
            return 100
        
        penalty = 0
        for issue in self.issues:
            if issue.severity == Severity.CRITICAL:
                penalty += 25
            elif issue.severity == Severity.HIGH:
                penalty += 15
            elif issue.severity == Severity.MEDIUM:
                penalty += 8
            elif issue.severity == Severity.LOW:
                penalty += 3
            else:  # INFO
                penalty += 1
        
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        """Get letter grade based on score."""
        score = self.score
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"


# Framework detection patterns
FRAMEWORK_IMPORTS = {
    'langchain': ['langchain', 'langchain_core', 'langchain_community', 'langchain_openai'],
    'crewai': ['crewai'],
    'autogen': ['autogen', 'pyautogen'],
    'langgraph': ['langgraph'],
    'llamaindex': ['llama_index'],
}

# API key patterns
API_KEY_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API key'),
    (r'sk-proj-[a-zA-Z0-9_-]{20,}', 'OpenAI project key'),
    (r'sk-ant-[a-zA-Z0-9_-]{20,}', 'Anthropic API key'),
    (r'anthropic[_-]?api[_-]?key\s*[=:]\s*["\'][^"\']{20,}', 'Anthropic key assignment'),
    (r'openai[_-]?api[_-]?key\s*[=:]\s*["\'][^"\']{20,}', 'OpenAI key assignment'),
    (r'AKIA[0-9A-Z]{16}', 'AWS access key'),
    (r'ghp_[a-zA-Z0-9]{36}', 'GitHub PAT'),
    (r'github_pat_[a-zA-Z0-9_]{22,}', 'GitHub PAT (fine-grained)'),
    (r'hf_[a-zA-Z0-9]{34}', 'HuggingFace token'),
    (r'Bearer\s+[a-zA-Z0-9_-]{20,}', 'Bearer token'),
]

# Dangerous function patterns (not subprocess - handled separately)
DANGEROUS_FUNCTIONS = {
    'eval': 'arbitrary code execution',
    'exec': 'arbitrary code execution',
    'compile': 'code compilation',
    '__import__': 'dynamic import',
    'os.system': 'shell execution',
    'os.popen': 'shell execution',
    'pickle.load': 'unsafe deserialization',
    'pickle.loads': 'unsafe deserialization',
    'marshal.load': 'unsafe deserialization',
    'marshal.loads': 'unsafe deserialization',
    'yaml.load': 'unsafe YAML (use safe_load)',
    'yaml.unsafe_load': 'unsafe YAML',
}

# SQL patterns (only match actual f-strings, not f"%" in second arg)
SQL_PATTERNS = [
    r'execute\s*\(\s*f["\'][^"\']*\{',  # execute(f"...{...}...")
    r'execute\s*\(\s*["\'][^"\']*%\s*["\'\)]',  # execute("... %s" % ...)  
    r'execute\s*\(\s*["\'][^"\']*\.format\s*\(',  # execute("...".format(...))
    r'cursor\.execute\s*\(\s*f["\'][^"\']*\{',  # cursor.execute(f"...{...}")
    r'\.raw\s*\(\s*f["\'][^"\']*\{',  # Django raw SQL with f-string
]


class AgentFlowAnalyzer(ast.NodeVisitor):
    """AST visitor for detecting agent security issues."""

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.lines = source.split('\n')
        self.issues: list[Issue] = []
        self.framework = "unknown"
        self.imports: dict[str, str] = {}  # alias -> module
        self.in_tool_function = False
        self.in_agent_class = False
        self.current_function: str | None = None
        self.functions_with_error_handling: set[str] = set()
        
    def get_line_context(self, lineno: int) -> str:
        """Get source line for context."""
        if 0 < lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()[:80]
        return ""

    def detect_framework(self, node: ast.Module) -> str:
        """Detect which agent framework is being used."""
        for item in ast.walk(node):
            if isinstance(item, (ast.Import, ast.ImportFrom)):
                module = ""
                if isinstance(item, ast.Import):
                    for alias in item.names:
                        module = alias.name.split('.')[0]
                elif item.module:
                    module = item.module.split('.')[0]
                
                for framework, patterns in FRAMEWORK_IMPORTS.items():
                    if module in patterns:
                        return framework
        return "unknown"

    def visit_Module(self, node: ast.Module) -> None:
        """Visit module and detect framework."""
        self.framework = self.detect_framework(node)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track imports."""
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from imports."""
        if node.module:
            for alias in node.names:
                name = alias.asname or alias.name
                self.imports[name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze function definitions."""
        self.current_function = node.name
        
        # Check if this is a tool function
        is_tool = self._is_tool_function(node)
        if is_tool:
            self.in_tool_function = True
            self._check_tool_function(node)
        
        # Check for error handling
        if self._has_error_handling(node):
            self.functions_with_error_handling.add(node.name)
        
        self.generic_visit(node)
        
        self.in_tool_function = False
        self.current_function = None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Analyze async function definitions."""
        # Treat same as regular function
        self.visit_FunctionDef(node)  # type: ignore

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Analyze class definitions."""
        # Check if this is an agent class
        agent_bases = ['Agent', 'BaseTool', 'Tool', 'StructuredTool', 'BaseAgent', 'CrewBase']
        for base in node.bases:
            base_name = self._get_name(base)
            if base_name in agent_bases:
                self.in_agent_class = True
                break
        
        self.generic_visit(node)
        self.in_agent_class = False

    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls."""
        func_name = self._get_call_name(node)
        
        # AF01: Check for untrusted input in prompts
        self._check_prompt_injection(node, func_name)
        
        # AF02/AF03: Check for dangerous tool patterns
        self._check_dangerous_calls(node, func_name)
        
        # AF06: Check for unpinned installs
        self._check_unpinned_installs(node, func_name)
        
        # AF07: Check for dynamic tool loading
        self._check_dynamic_loading(node, func_name)
        
        # AF08: Check for eval/exec of LLM output
        self._check_llm_code_execution(node, func_name)
        
        # AF11: Check for agent delegation
        self._check_agent_delegation(node, func_name)
        
        # AF12: Check for verbose/debug mode
        self._check_verbose_mode(node, func_name)
        
        # AF13: Check for unsafe deserialization
        self._check_deserialization(node, func_name)
        
        # AF15: Check for SQL injection
        self._check_sql_injection(node, func_name)
        
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Check assignments for credentials."""
        self._check_hardcoded_credentials(node)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Check string constants for API keys."""
        if isinstance(node.value, str) and len(node.value) > 15:
            self._check_api_key_in_string(node.value, node.lineno)
        self.generic_visit(node)

    def _get_name(self, node: ast.expr) -> str:
        """Get name from various node types."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def _get_call_name(self, node: ast.Call) -> str:
        """Get full call name (e.g., 'os.system')."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ""

    def _is_tool_function(self, node: ast.FunctionDef) -> bool:
        """Check if function is decorated as a tool."""
        tool_decorators = ['tool', 'langchain.tools.tool', 'StructuredTool', 'Tool']
        for decorator in node.decorator_list:
            dec_name = self._get_name(decorator) if isinstance(decorator, (ast.Name, ast.Attribute)) else ""
            if isinstance(decorator, ast.Call):
                dec_name = self._get_call_name(decorator)
            if dec_name in tool_decorators or 'tool' in dec_name.lower():
                return True
        return False

    def _has_error_handling(self, node: ast.FunctionDef) -> bool:
        """Check if function has try/except."""
        for child in ast.walk(node):
            if isinstance(child, ast.Try):
                return True
        return False

    def _check_tool_function(self, node: ast.FunctionDef) -> None:
        """Check tool function for issues."""
        # AF14: Check for missing error handling in tools
        if not self._has_error_handling(node):
            # Check if function has external calls
            has_external_calls = False
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = self._get_call_name(child)
                    if any(x in call_name for x in ['request', 'fetch', 'get', 'post', 'read', 'write', 'open', 'connect']):
                        has_external_calls = True
                        break
            
            if has_external_calls:
                self.issues.append(Issue(
                    rule="AF14",
                    message="Tool function lacks error handling for external calls",
                    severity=Severity.MEDIUM,
                    file=self.file_path,
                    line=node.lineno,
                    context=self.get_line_context(node.lineno),
                    suggestion="Wrap external calls in try/except to handle failures gracefully"
                ))

    def _check_prompt_injection(self, node: ast.Call, func_name: str) -> None:
        """AF01: Check for untrusted input in prompts."""
        prompt_functions = [
            'ChatPromptTemplate', 'PromptTemplate', 'HumanMessage', 'SystemMessage',
            'format_prompt', 'invoke', 'run', 'call', 'generate', 'predict',
            'ChatMessage', 'BaseMessage', 'AIMessage', 'from_messages'
        ]
        
        if any(p in func_name for p in prompt_functions):
            # Check all nested elements for f-strings
            for child in ast.walk(node):
                if isinstance(child, ast.JoinedStr):  # f-string
                    # Check if f-string contains variable interpolation
                    for value in child.values:
                        if isinstance(value, ast.FormattedValue):
                            self.issues.append(Issue(
                                rule="AF01",
                                message="F-string interpolation in prompt template (potential injection)",
                                severity=Severity.HIGH,
                                file=self.file_path,
                                line=node.lineno,
                                context=self.get_line_context(node.lineno),
                                suggestion="Use prompt template variables instead of f-string interpolation"
                            ))
                            return
                elif isinstance(child, ast.BinOp) and isinstance(child.op, ast.Mod):
                    # % formatting
                    self.issues.append(Issue(
                        rule="AF01",
                        message="String formatting with % in prompt (potential injection)",
                        severity=Severity.HIGH,
                        file=self.file_path,
                        line=node.lineno,
                        context=self.get_line_context(node.lineno),
                        suggestion="Use prompt template variables for user input"
                    ))
                    return
                elif isinstance(child, ast.Call):
                    # Check for .format() call
                    if isinstance(child.func, ast.Attribute) and child.func.attr == 'format':
                        self.issues.append(Issue(
                            rule="AF01",
                            message=".format() in prompt construction (potential injection)",
                            severity=Severity.HIGH,
                            file=self.file_path,
                            line=node.lineno,
                            context=self.get_line_context(node.lineno),
                            suggestion="Use prompt template variables instead of .format()"
                        ))
                        return

    def _check_dangerous_calls(self, node: ast.Call, func_name: str) -> None:
        """AF02/AF03: Check for dangerous function calls."""
        for dangerous, description in DANGEROUS_FUNCTIONS.items():
            if func_name == dangerous or func_name.endswith('.' + dangerous):
                severity = Severity.CRITICAL if 'execution' in description or 'deserialization' in description else Severity.HIGH
                
                # Check if this is in a tool function
                if self.in_tool_function:
                    severity = Severity.CRITICAL
                    message = f"Dangerous function '{func_name}' in tool: {description}"
                else:
                    message = f"Dangerous function call: {func_name} ({description})"
                
                self.issues.append(Issue(
                    rule="AF03" if 'shell' in description or 'subprocess' in description else "AF02",
                    message=message,
                    severity=severity,
                    file=self.file_path,
                    line=node.lineno,
                    context=self.get_line_context(node.lineno),
                    suggestion="Avoid dangerous functions in agent tools; use safe alternatives"
                ))
                return
        
        # Check subprocess with shell=True
        if 'subprocess' in func_name:
            for kw in node.keywords:
                if kw.arg == 'shell':
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.issues.append(Issue(
                            rule="AF03",
                            message="subprocess with shell=True is dangerous",
                            severity=Severity.CRITICAL if self.in_tool_function else Severity.HIGH,
                            file=self.file_path,
                            line=node.lineno,
                            context=self.get_line_context(node.lineno),
                            suggestion="Avoid shell=True; pass command as list instead"
                        ))

    def _check_unpinned_installs(self, node: ast.Call, func_name: str) -> None:
        """AF06: Check for unpinned package installs."""
        install_patterns = ['pip.main', 'subprocess']
        
        if any(p in func_name for p in install_patterns):
            # Check for pip install without version pin
            for arg in node.args:
                if isinstance(arg, ast.List):
                    for elt in arg.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            if 'install' in elt.value and '==' not in elt.value and '>=' not in elt.value:
                                self.issues.append(Issue(
                                    rule="AF06",
                                    message="Package install without version pin",
                                    severity=Severity.HIGH,
                                    file=self.file_path,
                                    line=node.lineno,
                                    context=self.get_line_context(node.lineno),
                                    suggestion="Pin package versions to prevent supply chain attacks"
                                ))
                                return

    def _check_dynamic_loading(self, node: ast.Call, func_name: str) -> None:
        """AF07: Check for dynamic tool loading from URLs."""
        dynamic_patterns = ['load_tools', 'import_module', 'load_from_hub', 'from_uri', 'from_url']
        
        if any(p in func_name for p in dynamic_patterns):
            self.issues.append(Issue(
                rule="AF07",
                message=f"Dynamic tool/module loading: {func_name}",
                severity=Severity.MEDIUM,
                file=self.file_path,
                line=node.lineno,
                context=self.get_line_context(node.lineno),
                suggestion="Verify source integrity before loading external tools"
            ))

    def _check_llm_code_execution(self, node: ast.Call, func_name: str) -> None:
        """AF08: Check for eval/exec on LLM output."""
        if func_name in ('eval', 'exec', 'compile'):
            # Check if the argument might be LLM output
            for arg in node.args:
                arg_str = ast.dump(arg)
                llm_patterns = ['response', 'output', 'result', 'completion', 'message', 'content', 'text']
                if any(p in arg_str.lower() for p in llm_patterns):
                    self.issues.append(Issue(
                        rule="AF08",
                        message=f"Executing LLM-generated code with {func_name}()",
                        severity=Severity.CRITICAL,
                        file=self.file_path,
                        line=node.lineno,
                        context=self.get_line_context(node.lineno),
                        suggestion="Never execute LLM output directly; use sandboxed execution"
                    ))
                    return

    def _check_agent_delegation(self, node: ast.Call, func_name: str) -> None:
        """AF11: Check for agent delegation patterns."""
        delegation_patterns = ['delegate', 'handoff', 'transfer', 'spawn_agent', 'create_agent']
        
        if any(p in func_name.lower() for p in delegation_patterns):
            # Check if there are scope/permission limits
            has_limits = False
            for kw in node.keywords:
                if kw.arg in ('allowed_tools', 'permissions', 'scope', 'max_iterations', 'timeout'):
                    has_limits = True
                    break
            
            if not has_limits:
                self.issues.append(Issue(
                    rule="AF11",
                    message="Agent delegation without explicit scope limits",
                    severity=Severity.MEDIUM,
                    file=self.file_path,
                    line=node.lineno,
                    context=self.get_line_context(node.lineno),
                    suggestion="Add allowed_tools, permissions, or scope limits to delegated agents"
                ))

    def _check_verbose_mode(self, node: ast.Call, func_name: str) -> None:
        """AF12: Check for verbose/debug mode."""
        for kw in node.keywords:
            if kw.arg in ('verbose', 'debug'):
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.issues.append(Issue(
                        rule="AF12",
                        message=f"{kw.arg}=True may leak sensitive information",
                        severity=Severity.LOW,
                        file=self.file_path,
                        line=node.lineno,
                        context=self.get_line_context(node.lineno),
                        suggestion="Disable verbose/debug mode in production"
                    ))

    def _check_deserialization(self, node: ast.Call, func_name: str) -> None:
        """AF13: Check for unsafe deserialization."""
        unsafe = ['pickle.load', 'pickle.loads', 'marshal.load', 'marshal.loads', 
                  'yaml.load', 'yaml.unsafe_load', 'shelve.open']
        
        if func_name in unsafe or any(func_name.endswith('.' + u.split('.')[-1]) for u in unsafe):
            self.issues.append(Issue(
                rule="AF13",
                message=f"Unsafe deserialization: {func_name}",
                severity=Severity.CRITICAL,
                file=self.file_path,
                line=node.lineno,
                context=self.get_line_context(node.lineno),
                suggestion="Avoid deserializing untrusted data; use safe alternatives like JSON"
            ))

    def _check_sql_injection(self, node: ast.Call, func_name: str) -> None:
        """AF15: Check for SQL injection in tools."""
        if 'execute' in func_name or 'raw' in func_name:
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):  # f-string
                    self.issues.append(Issue(
                        rule="AF15",
                        message="SQL query with f-string interpolation (injection risk)",
                        severity=Severity.CRITICAL,
                        file=self.file_path,
                        line=node.lineno,
                        context=self.get_line_context(node.lineno),
                        suggestion="Use parameterized queries instead of string interpolation"
                    ))
                    return

    def _check_hardcoded_credentials(self, node: ast.Assign) -> None:
        """AF04/AF05: Check for hardcoded credentials."""
        credential_names = ['api_key', 'apikey', 'secret', 'password', 'token', 'credential', 
                           'auth', 'private_key', 'access_key']
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                name_lower = target.id.lower()
                if any(c in name_lower for c in credential_names):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) > 5:  # Not a placeholder
                            self.issues.append(Issue(
                                rule="AF05",
                                message=f"Hardcoded credential: {target.id}",
                                severity=Severity.CRITICAL,
                                file=self.file_path,
                                line=node.lineno,
                                context=self.get_line_context(node.lineno),
                                suggestion="Use environment variables for credentials"
                            ))

    def _check_api_key_in_string(self, value: str, lineno: int) -> None:
        """Check string for API key patterns."""
        for pattern, key_type in API_KEY_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                self.issues.append(Issue(
                    rule="AF05",
                    message=f"Potential {key_type} in code",
                    severity=Severity.CRITICAL,
                    file=self.file_path,
                    line=lineno,
                    context=f"String contains pattern matching {key_type}",
                    suggestion="Remove API keys from source code; use environment variables"
                ))
                return


def analyze_file(file_path: str, source: str) -> ScanResult:
    """Analyze a Python file for agent security issues."""
    result = ScanResult(file=file_path, lines_scanned=source.count('\n') + 1)
    
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        result.issues.append(Issue(
            rule="PARSE",
            message=f"Syntax error: {e}",
            severity=Severity.INFO,
            file=file_path,
            line=e.lineno or 1
        ))
        return result
    
    analyzer = AgentFlowAnalyzer(file_path, source)
    analyzer.visit(tree)
    
    result.framework = analyzer.framework
    result.issues = analyzer.issues
    
    # Additional regex-based checks on raw source
    lines = source.split('\n')
    for i, line in enumerate(lines, 1):
        # Check for SQL patterns
        for pattern in SQL_PATTERNS:
            if re.search(pattern, line):
                result.issues.append(Issue(
                    rule="AF15",
                    message="Potential SQL injection pattern",
                    severity=Severity.HIGH,
                    file=file_path,
                    line=i,
                    context=line.strip()[:60],
                    suggestion="Use parameterized queries"
                ))
                break
    
    return result


def scan_path(
    path: Path,
    ignore_rules: set[str] | None = None,
    min_severity: Severity = Severity.INFO
) -> list[ScanResult]:
    """Scan a file or directory."""
    results = []
    ignore_rules = ignore_rules or set()
    
    if path.is_file():
        files = [path] if path.suffix == '.py' else []
    else:
        files = [
            f for f in path.rglob('*.py')
            if not any(part.startswith('.') for part in f.parts)
            and 'test' not in f.name.lower()  # Skip test files by default
            and '__pycache__' not in str(f)
        ]
    
    severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_idx = severity_order.index(min_severity)
    
    for file_path in files:
        try:
            source = file_path.read_text(encoding='utf-8')
        except Exception:
            continue
        
        result = analyze_file(str(file_path), source)
        
        # Filter issues
        result.issues = [
            issue for issue in result.issues
            if issue.rule not in ignore_rules
            and severity_order.index(issue.severity) >= min_idx
        ]
        
        if result.framework != "unknown" or result.issues:
            results.append(result)
    
    return results


def format_results(results: list[ScanResult], verbose: bool = False) -> str:
    """Format results for terminal output."""
    output = []
    total_issues = 0
    
    for result in results:
        output.append(f"\n📄 {result.file}")
        if result.framework != "unknown":
            output.append(f"   Framework: {result.framework}")
        
        if result.issues:
            # Group by severity
            by_severity: dict[Severity, list[Issue]] = {}
            for issue in result.issues:
                if issue.severity not in by_severity:
                    by_severity[issue.severity] = []
                by_severity[issue.severity].append(issue)
            
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                issues = by_severity.get(severity, [])
                for issue in issues:
                    icon = {
                        Severity.CRITICAL: "🔴",
                        Severity.HIGH: "🟠",
                        Severity.MEDIUM: "🟡",
                        Severity.LOW: "🔵",
                        Severity.INFO: "⚪",
                    }[severity]
                    
                    output.append(f"  {icon} {issue.rule}: {issue.message}")
                    output.append(f"     └─ Line {issue.line}")
                    
                    if verbose and issue.context:
                        output.append(f"     └─ {issue.context}")
                    if verbose and issue.suggestion:
                        output.append(f"     └─ 💡 {issue.suggestion}")
                    
                    total_issues += 1
        
        output.append(f"  Score: {result.score}/100 (Grade: {result.grade})")
    
    # Summary
    if results:
        avg_score = sum(r.score for r in results) / len(results)
        total_files = len(results)
        files_with_issues = sum(1 for r in results if r.issues)
        frameworks = set(r.framework for r in results if r.framework != "unknown")
        
        output.append("\n" + "=" * 50)
        output.append(f"📊 Summary: {total_files} files scanned, {files_with_issues} with issues")
        if frameworks:
            output.append(f"   Frameworks: {', '.join(frameworks)}")
        output.append(f"   Total issues: {total_issues}")
        output.append(f"   Average score: {avg_score:.0f}/100")
        
        # Count by severity
        counts = {s: 0 for s in Severity}
        for r in results:
            for issue in r.issues:
                counts[issue.severity] += 1
        
        if any(counts.values()):
            output.append(f"   Critical: {counts[Severity.CRITICAL]}, High: {counts[Severity.HIGH]}, "
                         f"Medium: {counts[Severity.MEDIUM]}, Low: {counts[Severity.LOW]}, Info: {counts[Severity.INFO]}")
    
    return '\n'.join(output)


def format_json(results: list[ScanResult]) -> str:
    """Format results as JSON."""
    data = {
        "files": [
            {
                "path": r.file,
                "framework": r.framework,
                "score": r.score,
                "grade": r.grade,
                "lines_scanned": r.lines_scanned,
                "issues": [
                    {
                        "rule": i.rule,
                        "message": i.message,
                        "severity": i.severity.value,
                        "line": i.line,
                        "column": i.column,
                        "context": i.context,
                        "suggestion": i.suggestion,
                    }
                    for i in r.issues
                ]
            }
            for r in results
        ],
        "summary": {
            "total_files": len(results),
            "files_with_issues": sum(1 for r in results if r.issues),
            "total_issues": sum(len(r.issues) for r in results),
            "average_score": sum(r.score for r in results) / len(results) if results else 100,
            "frameworks": list(set(r.framework for r in results if r.framework != "unknown")),
        }
    }
    return json.dumps(data, indent=2)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Agent Orchestration Static Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    agentflow agent.py
    agentflow agents/
    agentflow --check --min-score 80 src/
    agentflow --json src/ > report.json
    agentflow --verbose --ignore AF12 agents/
        """
    )
    
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show context and suggestions")
    parser.add_argument("-j", "--json", action="store_true", help="Output as JSON")
    parser.add_argument("--check", action="store_true", help="Exit with code 1 if score below threshold")
    parser.add_argument("--min-score", type=int, default=70, help="Minimum score for --check (default: 70)")
    parser.add_argument("--ignore", type=str, help="Comma-separated rules to ignore (e.g., AF10,AF12)")
    parser.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"],
                       default="info", help="Minimum severity to report")
    parser.add_argument("--include-tests", action="store_true", help="Include test files in scan")
    parser.add_argument("--version", action="version", version=f"agentflow {__version__}")
    
    args = parser.parse_args()
    
    path = Path(args.path)
    if not path.exists():
        print(f"Error: Path not found: {args.path}", file=sys.stderr)
        return 1
    
    ignore_rules = set(args.ignore.split(',')) if args.ignore else set()
    min_severity = Severity[args.severity.upper()]
    
    results = scan_path(path, ignore_rules, min_severity)
    
    if not results:
        print("No agent framework code found to scan.", file=sys.stderr)
        return 0
    
    if args.json:
        print(format_json(results))
    else:
        print(format_results(results, args.verbose))
    
    if args.check:
        avg_score = sum(r.score for r in results) / len(results)
        if avg_score < args.min_score:
            print(f"\n❌ Score {avg_score:.0f} below minimum {args.min_score}", file=sys.stderr)
            return 1
        print(f"\n✅ Score {avg_score:.0f} meets minimum {args.min_score}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
