"""Example secure agent code for testing agentflow."""

import os
from langchain.tools import tool
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI


# Use environment variables for credentials
api_key = os.environ.get("OPENAI_API_KEY")


@tool
def safe_read_file(filename: str) -> str:
    """Read a file safely with proper error handling."""
    try:
        # Only allow reading from specific directory
        allowed_dir = "/app/data"
        if not filename.startswith(allowed_dir):
            return "Error: Access denied"
        
        with open(filename, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "Error: File not found"
    except PermissionError:
        return "Error: Permission denied"
    except Exception as e:
        return f"Error: {str(e)}"


@tool
def safe_query(search_term: str) -> list:
    """Query database safely with parameterized queries."""
    import sqlite3
    
    try:
        conn = sqlite3.connect('db.sqlite')
        cursor = conn.cursor()
        # Use parameterized query - safe from SQL injection
        cursor.execute("SELECT * FROM items WHERE name LIKE ?", (f"%{search_term}%",))
        return cursor.fetchall()
    except Exception as e:
        return [f"Error: {str(e)}"]
    finally:
        conn.close()


def create_secure_agent():
    """Create a secure agent with proper prompt handling."""
    # Use template variables instead of f-string interpolation
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant."),
        ("human", "{user_input}")  # Template variable - safe
    ])
    
    # Verbose disabled for production
    llm = ChatOpenAI(model="gpt-4", verbose=False)
    
    return prompt | llm
