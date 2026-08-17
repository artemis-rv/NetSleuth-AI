import os
import re

directories = ['backend']

replacements = [
    (r'(?m)^from src\.m3_correlation\b', 'from backend.app.engines.correlation'),
    (r'(?m)^import src\.m3_correlation\b', 'import backend.app.engines.correlation'),
    
    (r'(?m)^from src\.m4_evidence\b', 'from backend.app.engines.reporting'),
    (r'(?m)^import src\.m4_evidence\b', 'import backend.app.engines.reporting'),
    
    (r'(?m)^from src\.m4_reporting\b', 'from backend.app.engines.reporting'),
    (r'(?m)^import src\.m4_reporting\b', 'import backend.app.engines.reporting'),
    
    (r'(?m)^from src\.shared\b', 'from backend.app.shared'),
    (r'(?m)^import src\.shared\b', 'import backend.app.shared'),
    
    (r'(?m)^from src\.m2_analysis\b', 'from backend.app.engines.analysis'),
    (r'(?m)^import src\.m2_analysis\b', 'import backend.app.engines.analysis'),
]

for d in directories:
    for root, dirs, files in os.walk(d):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                new_content = content
                for pattern, replacement in replacements:
                    new_content = re.sub(pattern, replacement, new_content)
                
                if new_content != content:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f'Updated {filepath}')

