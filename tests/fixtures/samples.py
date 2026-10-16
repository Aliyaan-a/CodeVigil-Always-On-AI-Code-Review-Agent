"""Shared test fixtures."""

# Sample code snippets for testing

CLEAN_CODE = '''"""A clean module."""


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
'''

BUGGY_CODE = '''
def buggy(items=[]):
    try:
        process(items)
    except:
        pass
    return items
    cleanup()
'''

SECURITY_CODE = '''
import pickle
import os

API_KEY = "sk-abc123def456ghi789jkl012mno345"

def run(cmd):
    os.system(cmd)
    data = pickle.loads(external_data)
    return eval(user_input)
'''

COMPLEX_CODE = '''
def very_complex(a, b, c, d, e, f, g, h):
    if a:
        if b:
            for i in range(c):
                if d:
                    while e:
                        try:
                            if f:
                                if g and h:
                                    pass
                                elif g or h:
                                    pass
                        except:
                            if a or b:
                                pass
    return None
'''
