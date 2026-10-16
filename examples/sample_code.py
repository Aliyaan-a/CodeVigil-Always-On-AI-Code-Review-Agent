"""
Sample code with intentional issues for demonstrating CodeVigil.

Run: codevigil review examples/sample_code.py
"""

import os
import pickle
from os import *

# SEC-001: Hardcoded API key
API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"

# SEC-002: Hardcoded password
password = "hunter2_super_secret"

# SEC-025: Debug mode enabled
DEBUG = True


# AST-001: Mutable default argument
# CX-004: Too many parameters
# STY-003: Non-snake_case function name
def ProcessUserData(user_id, data=[], config={}, options=None, verbose=False, retry=3):
    # SEC-021: Use of eval
    result = eval(data)

    # SEC-011: Command injection
    os.system(f"echo {user_id}")

    # SEC-020: Insecure deserialization
    loaded = pickle.loads(data)

    # AST-012: Comparison to None with ==
    if result == None:
        return None

    # PERF-001: String concatenation in loop (approximate)
    output = ""
    for item in result:
        output += str(item)

    # CX-001/CX-002: High complexity
    if user_id > 0:
        if data:
            for item in data:
                if item:
                    for sub in item:
                        if sub > 0:
                            if sub < 100:
                                if verbose:
                                    print(sub)

    # AST-003: Unreachable code
    return output
    print("This will never execute")


# STY-004: Non-PascalCase class name
class data_processor:
    # AST-010: Return with value in __init__
    def __init__(self):
        self.data = []
        return True

    # AST-009: Empty except (silenced exception)
    def process(self):
        try:
            self._do_work()
        except:
            pass

    # AST-002: Bare except
    def fetch(self, url):
        try:
            return self._fetch(url)
        except:
            return None

    def _do_work(self):
        pass

    def _fetch(self, url):
        pass


# AST-013: Duplicate dictionary key
settings = {
    "mode": "fast",
    "timeout": 30,
    "mode": "slow",  # duplicate!
}

# AST-004: Shadowed builtin
list = [1, 2, 3]
dict = {"a": 1}

# SEC-023: Weak hash
import hashlib
weak_hash = hashlib.md5(b"data")

# SEC-026: SSL verification disabled
# requests.get("https://api.example.com", verify=False)
