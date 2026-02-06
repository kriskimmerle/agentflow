#!/usr/bin/env python3
"""Tests for agentflow - Agent Orchestration Static Security Analyzer."""

import json
import tempfile
import unittest
from pathlib import Path

from agentflow import (
    Severity,
    ScanResult,
    analyze_file,
    scan_path,
    format_json,
    AgentFlowAnalyzer,
)


class TestFrameworkDetection(unittest.TestCase):
    """Tests for framework detection."""

    def test_detect_langchain(self):
        code = """
from langchain.tools import tool
from langchain_openai import ChatOpenAI
"""
        result = analyze_file("test.py", code)
        self.assertEqual(result.framework, "langchain")

    def test_detect_crewai(self):
        code = """
from crewai import Agent, Task, Crew
"""
        result = analyze_file("test.py", code)
        self.assertEqual(result.framework, "crewai")

    def test_detect_autogen(self):
        code = """
from autogen import AssistantAgent, UserProxyAgent
"""
        result = analyze_file("test.py", code)
        self.assertEqual(result.framework, "autogen")

    def test_detect_langgraph(self):
        code = """
from langgraph.graph import StateGraph
"""
        result = analyze_file("test.py", code)
        self.assertEqual(result.framework, "langgraph")

    def test_no_framework(self):
        code = """
import os
print("Hello")
"""
        result = analyze_file("test.py", code)
        self.assertEqual(result.framework, "unknown")


class TestAF01PromptInjection(unittest.TestCase):
    """Tests for AF01: Untrusted input in prompts."""

    def test_fstring_in_prompt(self):
        code = """
from langchain_core.prompts import ChatPromptTemplate
user_input = "test"
prompt = ChatPromptTemplate.from_messages([
    ("system", f"User said: {user_input}")
])
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF01" for i in result.issues))

    def test_format_in_prompt(self):
        code = """
from langchain_core.prompts import ChatPromptTemplate
prompt = ChatPromptTemplate.from_messages([
    ("system", "User: {}".format(user_input))
])
"""
        result = analyze_file("test.py", code)
        # This tests the .format() detection
        self.assertTrue(any("AF01" in i.rule for i in result.issues))

    def test_safe_template(self):
        code = """
from langchain_core.prompts import ChatPromptTemplate
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are helpful"),
    ("human", "{user_input}")
])
"""
        result = analyze_file("test.py", code)
        self.assertFalse(any(i.rule == "AF01" for i in result.issues))


class TestAF02DangerousFunctions(unittest.TestCase):
    """Tests for AF02: Dangerous function calls."""

    def test_eval(self):
        code = """
result = eval(user_code)
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF02" for i in result.issues))

    def test_exec(self):
        code = """
exec(generated_code)
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF02" for i in result.issues))

    def test_eval_in_tool(self):
        code = """
from langchain.tools import tool

@tool
def calculate(expr: str) -> str:
    return str(eval(expr))
"""
        result = analyze_file("test.py", code)
        issues = [i for i in result.issues if i.rule == "AF02"]
        self.assertTrue(len(issues) > 0)
        self.assertEqual(issues[0].severity, Severity.CRITICAL)


class TestAF03ShellExecution(unittest.TestCase):
    """Tests for AF03: Shell execution in tools."""

    def test_subprocess_shell_true(self):
        code = """
import subprocess
subprocess.run(cmd, shell=True)
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF03" for i in result.issues))

    def test_os_system(self):
        code = """
import os
os.system(command)
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF03" for i in result.issues))

    def test_subprocess_shell_false(self):
        code = """
import subprocess
subprocess.run(["ls", "-la"], shell=False)
"""
        result = analyze_file("test.py", code)
        self.assertFalse(any(i.rule == "AF03" for i in result.issues))


class TestAF05HardcodedCredentials(unittest.TestCase):
    """Tests for AF05: Hardcoded API keys."""

    def test_openai_key(self):
        code = '''
api_key = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
'''
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF05" for i in result.issues))

    def test_anthropic_key(self):
        code = '''
key = "sk-ant-abcdef1234567890abcdef"
'''
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF05" for i in result.issues))

    def test_credential_variable(self):
        code = '''
password = "supersecretpassword123"
'''
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF05" for i in result.issues))

    def test_env_var_ok(self):
        code = '''
import os
api_key = os.environ.get("OPENAI_API_KEY")
'''
        result = analyze_file("test.py", code)
        self.assertFalse(any(i.rule == "AF05" for i in result.issues))


class TestAF08LLMCodeExecution(unittest.TestCase):
    """Tests for AF08: Executing LLM output."""

    def test_exec_response(self):
        code = """
exec(response.content)
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF08" for i in result.issues))

    def test_eval_completion(self):
        code = """
result = eval(completion.text)
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF08" for i in result.issues))


class TestAF11AgentDelegation(unittest.TestCase):
    """Tests for AF11: Agent delegation without limits."""

    def test_delegate_no_limits(self):
        code = """
agent.delegate(task)
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF11" for i in result.issues))

    def test_delegate_with_limits(self):
        code = """
agent.delegate(task, allowed_tools=["search"], max_iterations=5)
"""
        result = analyze_file("test.py", code)
        self.assertFalse(any(i.rule == "AF11" for i in result.issues))


class TestAF12VerboseMode(unittest.TestCase):
    """Tests for AF12: Verbose/debug mode."""

    def test_verbose_true(self):
        code = """
llm = ChatOpenAI(verbose=True)
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF12" for i in result.issues))

    def test_debug_true(self):
        code = """
agent = Agent(debug=True)
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF12" for i in result.issues))

    def test_verbose_false(self):
        code = """
llm = ChatOpenAI(verbose=False)
"""
        result = analyze_file("test.py", code)
        self.assertFalse(any(i.rule == "AF12" for i in result.issues))


class TestAF13Deserialization(unittest.TestCase):
    """Tests for AF13: Unsafe deserialization."""

    def test_pickle_load(self):
        code = """
import pickle
data = pickle.load(f)
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF13" for i in result.issues))

    def test_yaml_load(self):
        code = """
import yaml
data = yaml.load(content)
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF13" for i in result.issues))


class TestAF14ErrorHandling(unittest.TestCase):
    """Tests for AF14: Missing error handling in tools."""

    def test_tool_no_try_except(self):
        code = """
from langchain.tools import tool

@tool
def fetch_data(url: str) -> str:
    response = requests.get(url)
    return response.text
"""
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF14" for i in result.issues))

    def test_tool_with_try_except(self):
        code = """
from langchain.tools import tool

@tool
def fetch_data(url: str) -> str:
    try:
        response = requests.get(url)
        return response.text
    except Exception as e:
        return str(e)
"""
        result = analyze_file("test.py", code)
        self.assertFalse(any(i.rule == "AF14" for i in result.issues))


class TestAF15SQLInjection(unittest.TestCase):
    """Tests for AF15: SQL injection."""

    def test_fstring_sql(self):
        code = '''
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        result = analyze_file("test.py", code)
        self.assertTrue(any(i.rule == "AF15" for i in result.issues))

    def test_parameterized_sql(self):
        code = '''
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''
        result = analyze_file("test.py", code)
        self.assertFalse(any(i.rule == "AF15" for i in result.issues))


class TestScoring(unittest.TestCase):
    """Tests for scoring and grading."""

    def test_perfect_score(self):
        result = ScanResult(file="test.py", issues=[])
        self.assertEqual(result.score, 100)
        self.assertEqual(result.grade, "A")

    def test_critical_penalty(self):
        from agentflow import Issue
        result = ScanResult(
            file="test.py",
            issues=[
                Issue(rule="AF05", message="test", severity=Severity.CRITICAL, 
                      file="test.py", line=1)
            ]
        )
        self.assertEqual(result.score, 75)

    def test_grade_boundaries(self):
        from agentflow import Issue
        
        # B grade: 80-89
        result = ScanResult(
            file="test.py",
            issues=[
                Issue(rule="AF12", message="test", severity=Severity.LOW, 
                      file="test.py", line=1)
            ] * 5  # 5 LOW = -15 = 85
        )
        self.assertEqual(result.grade, "B")


class TestScanPath(unittest.TestCase):
    """Tests for file/directory scanning."""

    def test_scan_single_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("from langchain.tools import tool\n")
            f.flush()
            
            path = Path(f.name)
            results = scan_path(path)
            
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].framework, "langchain")
            
            path.unlink()

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "agent.py").write_text("from crewai import Agent\n")
            (Path(tmpdir) / "tools.py").write_text("from langchain.tools import tool\n")
            
            results = scan_path(Path(tmpdir))
            
            self.assertEqual(len(results), 2)
            frameworks = {r.framework for r in results}
            self.assertIn("langchain", frameworks)
            self.assertIn("crewai", frameworks)

    def test_ignore_rules(self):
        code = """
llm = ChatOpenAI(verbose=True)
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            f.flush()
            
            path = Path(f.name)
            
            # With AF12
            results = scan_path(path)
            has_af12 = any(i.rule == "AF12" for r in results for i in r.issues)
            
            # Ignoring AF12
            results_ignored = scan_path(path, ignore_rules={"AF12"})
            no_af12 = all(i.rule != "AF12" for r in results_ignored for i in r.issues)
            
            self.assertTrue(has_af12 or len(results) == 0)
            self.assertTrue(no_af12)
            
            path.unlink()


class TestJSONOutput(unittest.TestCase):
    """Tests for JSON output formatting."""

    def test_json_format(self):
        result = ScanResult(
            file="test.py",
            framework="langchain",
            issues=[],
            lines_scanned=10
        )
        json_output = format_json([result])
        
        data = json.loads(json_output)
        self.assertEqual(len(data["files"]), 1)
        self.assertEqual(data["files"][0]["framework"], "langchain")
        self.assertEqual(data["summary"]["total_files"], 1)


class TestIntegration(unittest.TestCase):
    """Integration tests."""

    def test_clean_agent_code(self):
        code = """
import os
from langchain.tools import tool
from langchain_core.prompts import ChatPromptTemplate

api_key = os.environ.get("OPENAI_API_KEY")

@tool
def search(query: str) -> str:
    try:
        # Safe implementation
        return f"Results for: {query}"
    except Exception as e:
        return f"Error: {e}"

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are helpful"),
    ("human", "{input}")
])
"""
        result = analyze_file("test.py", code)
        self.assertEqual(result.framework, "langchain")
        self.assertEqual(result.score, 100)
        self.assertEqual(result.grade, "A")

    def test_vulnerable_agent_code(self):
        code = '''
from langchain.tools import tool
import pickle

api_key = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"

@tool
def dangerous(code: str) -> str:
    return str(eval(code))

@tool
def load_data(path: str) -> dict:
    with open(path, "rb") as f:
        return pickle.load(f)
'''
        result = analyze_file("test.py", code)
        self.assertEqual(result.framework, "langchain")
        self.assertLess(result.score, 50)
        self.assertEqual(result.grade, "F")
        self.assertTrue(len(result.issues) >= 3)


if __name__ == "__main__":
    unittest.main()
