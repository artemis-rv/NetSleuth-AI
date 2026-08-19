import glob
import re

for filepath in glob.glob("backend/tests/unit/test_*.py"):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Replace broken string split
    content = content.replace("lines = content.split('\\\n')", "lines = content.split('\\n')")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
