# Contributing to agentflow

Thank you for your interest in contributing to agentflow! This document provides guidelines and instructions for contributing.

## Project Mission

agentflow is a zero-dependency Python static security analyzer for agent orchestration frameworks (LangChain, CrewAI, AutoGen, LangGraph). We prioritize:

- **OWASP Agentic Top 10 alignment** - focus on real agent security risks
- **Zero dependencies** - uses only Python stdlib
- **Actionable findings** - clear fixes, not just warnings
- **Framework-specific patterns** - detect issues unique to agent orchestration

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/kriskimmerle/agentflow.git
   cd agentflow
   ```

2. **Install development dependencies**
   ```bash
   pip install pytest ruff
   ```

3. **Run tests**
   ```bash
   python -m pytest test_agentflow.py -v
   ```

4. **Lint the code**
   ```bash
   ruff check agentflow.py test_agentflow.py
   ```

## Adding New Detection Rules

To add a new security check:

1. **Identify the pattern**
   - What agent-specific security antipattern are you targeting?
   - How does it map to OWASP Agentic Top 10 (ASI01-ASI10)?
   - Is this pattern already covered by general security tools?
   - Does it produce false positives in legitimate agent code?

2. **Choose a rule ID**
   - Use the next available AF## number (AF01-AF15 are taken)
   - Update the module docstring in `agentflow.py` with the new rule

3. **Implement the check**
   - Add a method to `AgentFlowVisitor` class in `agentflow.py`
   - Use AST visiting methods (`visit_Call`, `visit_Assign`, etc.)
   - Provide clear error messages and fix suggestions
   - Include framework detection context when applicable

4. **Write tests**
   - Add test cases to `test_agentflow.py`
   - Test both positive (should detect) and negative (should not detect) cases
   - Include examples from multiple frameworks (LangChain, CrewAI, AutoGen, LangGraph)
   - Test edge cases

5. **Update documentation**
   - Add the rule to README.md detection rules table
   - Include severity, OWASP mapping, description, and example
   - Document framework-specific behavior if applicable

### Example Rule Implementation

```python
def visit_Call(self, node: ast.Call):
    """Check function calls for security issues."""
    func_name = self._get_call_name(node)
    
    # AF16: Example agent-specific pattern
    if func_name in ('AgentExecutor', 'initialize_agent'):
        # Check for missing max_iterations
        keywords = {kw.arg: kw.value for kw in node.keywords}
        if 'max_iterations' not in keywords:
            self.add_issue(
                node, "AF16", Severity.MEDIUM,
                "Agent executor without max_iterations limit (ASI09)",
                "Add max_iterations parameter to prevent infinite loops",
                "AgentExecutor(..., max_iterations=10)"
            )
    
    self.generic_visit(node)
```

### Example Test Case

```python
def test_af16_missing_max_iterations():
    """Test AF16: Agent executor without iteration limit."""
    code = '''
from langchain.agents import AgentExecutor

executor = AgentExecutor(
    agent=agent,
    tools=tools
)
'''
    result = scan_code(code, "test.py")
    assert len(result.issues) == 1
    assert result.issues[0].rule == "AF16"
    assert result.issues[0].severity == Severity.MEDIUM
    assert "max_iterations" in result.issues[0].message
```

## Code Style

- **Follow PEP 8** - use `ruff` for linting
- **Type hints** - use modern type hints (e.g., `list[str]` not `List[str]`)
- **Comments** - explain *why*, not *what*
- **Docstrings** - required for public methods and classes

## Testing Guidelines

- **Test coverage** - aim for >90% coverage of new code
- **Multi-framework testing** - include examples from LangChain, CrewAI, AutoGen, and LangGraph where applicable
- **Test both cases** - positive (should detect) and negative (shouldn't)
- **Edge cases** - test boundary conditions
- **Real-world code** - use realistic agent patterns, not toy examples

Run tests:
```bash
python -m pytest test_agentflow.py -v
```

## Commit Guidelines

- **Clear messages** - describe what and why
- **One logical change per commit**
- **Reference issues** - use "Fixes #123" in commit messages

Example:
```
Add AF16: Detect missing max_iterations in AgentExecutor

LangChain AgentExecutors without max_iterations can loop infinitely
if the agent fails to reach a conclusion. This maps to ASI09 
(Excessive Agency) and is commonly missed in agent code.

Fixes #42
```

## Pull Request Process

1. **Fork the repository** and create a feature branch
   ```bash
   git checkout -b feature/add-af16-rule
   ```

2. **Make your changes**
   - Implement the feature or fix
   - Write tests
   - Update documentation

3. **Test locally**
   ```bash
   python -m pytest test_agentflow.py -v
   ruff check agentflow.py test_agentflow.py
   ```

4. **Submit a pull request**
   - Describe the change and motivation
   - Reference OWASP Agentic Top 10 categories if applicable
   - Include example code that triggers the rule
   - Show which frameworks are affected

5. **Respond to feedback**
   - Address review comments
   - Update tests or documentation as needed

## What to Contribute

### High-priority contributions
- **New detection rules** for agent-specific security patterns
- **Framework support** - improve detection for CrewAI, AutoGen, LangGraph
- **False positive fixes** - improve precision
- **OWASP alignment** - map more rules to Agentic Top 10
- **Documentation** - better examples, framework-specific guides

### Medium-priority
- **IDE integrations** - VS Code, PyCharm plugins
- **CI/CD examples** - GitHub Actions, GitLab CI configurations
- **Test cases** - more edge cases, real-world agent patterns
- **Performance improvements** - faster scanning of large codebases

### Not currently needed
- External dependencies (keep it zero-dependency)
- Rewrites or major refactors (focus on incremental improvements)
- Style-only changes (functional improvements preferred)
- Non-agent-specific rules (use vibeguard, Bandit, or Semgrep instead)

## Framework-Specific Guidelines

### LangChain
- Focus on `AgentExecutor`, `initialize_agent`, chain composition
- Check tool definitions and memory handling
- Watch for prompt injection in template strings

### CrewAI
- Focus on `Crew`, `Agent`, `Task` configurations
- Check delegation patterns and tool assignments
- Verify role-based access controls

### AutoGen
- Focus on `ConversableAgent`, `AssistantAgent` configurations
- Check code execution settings
- Verify human-in-the-loop patterns

### LangGraph
- Focus on graph node definitions and state management
- Check conditional edges and routing logic
- Verify error handling in node functions

## Questions or Ideas?

- **Open an issue** on GitHub for discussion
- **Check existing issues** to avoid duplicates
- **Search closed PRs** - your idea may have been discussed before

## Code of Conduct

Be respectful, inclusive, and constructive. We're all here to build better tools for agent security.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make agentflow better! 🛡️
