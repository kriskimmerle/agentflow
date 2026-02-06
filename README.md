# agentflow

**Agent Orchestration Static Security Analyzer** — Zero-dependency static analyzer for LangChain, CrewAI, AutoGen, and LangGraph agent code.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-green.svg)]()

## Why agentflow?

AI agents are now production systems with access to tools, APIs, databases, and user data. The [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) identifies critical security risks unique to autonomous AI systems.

agentflow detects these risks **before deployment** through static analysis:

- **ASI01 Goal Hijack**: Untrusted input in prompts → prompt injection
- **ASI02 Tool Misuse**: Dangerous functions in tools → RCE, data theft
- **ASI03 Identity Abuse**: Hardcoded credentials → account compromise
- **ASI04 Supply Chain**: Unpinned dependencies → malicious packages
- **ASI05 Code Execution**: eval/exec of LLM output → arbitrary code execution

## Installation

```bash
# Just download the single file - zero dependencies!
curl -O https://raw.githubusercontent.com/kriskimmerle/agentflow/main/agentflow.py
chmod +x agentflow.py

# Or clone the repo
git clone https://github.com/kriskimmerle/agentflow
cd agentflow
```

## Quick Start

```bash
# Scan a single file
python agentflow.py agent.py

# Scan your agents directory
python agentflow.py agents/

# Verbose mode with suggestions
python agentflow.py --verbose src/

# CI mode: exit 1 if score below threshold
python agentflow.py --check --min-score 80 src/

# JSON output for automation
python agentflow.py --json src/ > report.json
```

## Example Output

```
📄 agents/my_agent.py
   Framework: langchain
  🔴 AF05: Hardcoded credential: api_key
     └─ Line 5
     └─ api_key = "sk-1234567890..."
     └─ 💡 Use environment variables for credentials
  🔴 AF02: Dangerous function 'eval' in tool: arbitrary code execution
     └─ Line 18
     └─ return str(eval(code))
     └─ 💡 Avoid dangerous functions in agent tools; use safe alternatives
  🔴 AF03: subprocess with shell=True is dangerous
     └─ Line 25
     └─ subprocess.run(cmd, shell=True)
     └─ 💡 Avoid shell=True; pass command as list instead
  🟠 AF01: F-string interpolation in prompt template (potential injection)
     └─ Line 32
     └─ 💡 Use prompt template variables instead of f-string interpolation
  Score: 0/100 (Grade: F)

==================================================
📊 Summary: 1 files scanned, 1 with issues
   Frameworks: langchain
   Total issues: 4
   Average score: 0/100
   Critical: 3, High: 1, Medium: 0, Low: 0, Info: 0
```

## Supported Frameworks

agentflow auto-detects and analyzes code for:

- **LangChain** (langchain, langchain_core, langchain_community, langchain_openai)
- **CrewAI** (crewai)
- **AutoGen** (autogen, pyautogen)
- **LangGraph** (langgraph)
- **LlamaIndex** (llama_index)

## Rules

| Rule | Severity | OWASP | Description |
|------|----------|-------|-------------|
| AF01 | HIGH | ASI01 | F-string/format interpolation in prompt templates |
| AF02 | CRITICAL | ASI02 | Dangerous functions (eval, exec, compile) in tools |
| AF03 | CRITICAL | ASI02 | Shell execution (os.system, subprocess with shell=True) |
| AF04 | CRITICAL | ASI03 | Credentials stored in agent memory/state |
| AF05 | CRITICAL | ASI03 | Hardcoded API keys and secrets |
| AF06 | HIGH | ASI04 | Unpinned package installs in agent code |
| AF07 | MEDIUM | ASI04 | Dynamic tool loading from URLs |
| AF08 | CRITICAL | ASI05 | eval/exec of LLM-generated code |
| AF09 | HIGH | ASI05 | Code generation without sandboxing |
| AF10 | MEDIUM | ASI09 | Missing human-in-loop for sensitive operations |
| AF11 | MEDIUM | ASI03 | Agent delegation without scope limits |
| AF12 | LOW | - | Verbose/debug mode enabled (info leak) |
| AF13 | CRITICAL | - | Unsafe deserialization (pickle, marshal, yaml.load) |
| AF14 | MEDIUM | - | Tool functions lacking error handling |
| AF15 | CRITICAL | - | SQL injection in agent tools |

## CLI Options

```
usage: agentflow.py [-h] [-v] [-j] [--check] [--min-score MIN_SCORE]
                    [--ignore IGNORE] [--severity SEVERITY]
                    [--include-tests] [--version] path

Arguments:
  path                  File or directory to scan

Options:
  -v, --verbose         Show context and suggestions
  -j, --json            Output as JSON
  --check               Exit with code 1 if score below threshold
  --min-score           Minimum score for --check (default: 70)
  --ignore              Comma-separated rules to ignore (e.g., AF10,AF12)
  --severity            Minimum severity to report (info/low/medium/high/critical)
  --include-tests       Include test files in scan
  --version             Show version
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Audit agent security
  run: |
    curl -sO https://raw.githubusercontent.com/kriskimmerle/agentflow/main/agentflow.py
    python agentflow.py --check --min-score 80 src/agents/
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: agentflow
        name: Agent Security Check
        entry: python agentflow.py --check
        language: python
        files: \.py$
```

## Secure Patterns

❌ **Vulnerable:**
```python
@tool
def execute(code: str) -> str:
    return str(eval(code))  # AF02: Arbitrary code execution
```

✅ **Secure:**
```python
@tool
def calculate(expression: str) -> str:
    try:
        # Use ast.literal_eval for safe evaluation
        return str(ast.literal_eval(expression))
    except Exception as e:
        return f"Error: {e}"
```

---

❌ **Vulnerable:**
```python
prompt = ChatPromptTemplate.from_messages([
    ("system", f"User asked: {user_input}")  # AF01: Prompt injection
])
```

✅ **Secure:**
```python
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant."),
    ("human", "{user_input}")  # Template variable - safe
])
```

---

❌ **Vulnerable:**
```python
api_key = "sk-1234567890abcdef..."  # AF05: Hardcoded credential
```

✅ **Secure:**
```python
api_key = os.environ.get("OPENAI_API_KEY")
```

## Related Research

- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [AI Agent Security Risks](https://www.mintmcp.com/blog/ai-agent-security-risks)
- [Prompt Injection and Agentic Coding Tools](https://www.securecodewarrior.com/article/prompt-injection-and-the-security-risks-of-agentic-coding-tools)
- [Kaspersky: Top Agentic AI Risks 2026](https://www.kaspersky.com/blog/top-agentic-ai-risks-2026/)

## License

MIT License - see [LICENSE](LICENSE)
