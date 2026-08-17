import os
import re

directories = ['backend/tests']

for d in directories:
    for root, dirs, files in os.walk(d):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Replace .parent.parent.parent / "fixtures" with .parent.parent.parent.parent / "fixtures"
                # or similar permutations. A safer approach:
                # Find where Path(__file__) is used to build a path to ixtures or docs/contracts
                
                new_content = re.sub(r'\.parent\.parent\.parent\s*/\s*"fixtures"', r'.parent.parent.parent.parent / "fixtures"', content)
                new_content = re.sub(r'\.parent\.parent\.parent\s*/\s*"docs"', r'.parent.parent.parent.parent / "docs"', new_content)
                
                if new_content != content:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f'Fixed fixture path in {filepath}')

