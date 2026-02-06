"""Example vulnerable agent code for testing agentflow."""

from langchain.tools import tool
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
import subprocess
import pickle
import os

# AF05: Hardcoded API key
api_key = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"

# AF05: Another hardcoded credential
openai_api_key = "sk-proj-super-secret-key-here-do-not-share"


@tool
def execute_command(command: str) -> str:
    """Execute a shell command - DANGEROUS!"""
    # AF03: Shell execution in tool with shell=True
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@tool  
def run_code(code: str) -> str:
    """Run arbitrary code - DANGEROUS!"""
    # AF02: eval in tool function
    return str(eval(code))


@tool
def load_data(path: str) -> dict:
    """Load pickled data - DANGEROUS!"""
    # AF13: Unsafe deserialization
    with open(path, 'rb') as f:
        return pickle.load(f)


@tool
def query_database(user_input: str) -> list:
    """Query database - SQL INJECTION VULNERABLE!"""
    import sqlite3
    conn = sqlite3.connect('db.sqlite')
    # AF15: SQL injection
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    return cursor.fetchall()


def create_agent():
    """Create an agent with security issues."""
    # AF01: User input in f-string prompt
    user_question = input("Ask a question: ")
    prompt = ChatPromptTemplate.from_messages([
        ("system", f"You are an assistant. User asked: {user_question}"),
        ("human", "{input}")
    ])
    
    # AF12: Verbose mode enabled
    llm = ChatOpenAI(model="gpt-4", verbose=True)
    
    return prompt | llm


def process_llm_output(response):
    """Process LLM output dangerously."""
    # AF08: Executing LLM output
    code = response.content
    exec(code)  # DANGEROUS!


def delegate_to_agent(task):
    """Delegate without limits."""
    from crewai import Agent, Task, Crew
    
    # AF11: Delegation without scope limits
    agent = Agent(
        role="Helper",
        goal="Help with tasks",
        backstory="I help with everything"
    )
    agent.delegate(task)  # No scope limits!
