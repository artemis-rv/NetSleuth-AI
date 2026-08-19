import glob
import re

for filepath in glob.glob("backend/tests/unit/test_*.py"):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Fix broken split
    # The broken split looks like: lines = content.split('\n            if lines
    # Wait, the error is: lines = content.split('\n
    # So I can just do:
    content = re.sub(r"lines = content\.split\('([^']*)'\)", r"lines = content.split('\\n')", content)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
