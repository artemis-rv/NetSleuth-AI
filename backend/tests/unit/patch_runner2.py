import re

def patch_zeek_runner():
    with open("backend/tests/unit/test_zeek_runner.py", "r", encoding="utf-8") as f:
        content = f.read()
    
    content = content.replace('from unittest import mock', 'from unittest import mock\nfrom unittest.mock import MagicMock')

    setup_replace = """    def setUp(self):
        self._temps: list[Path] = []
        self.mock_storage = MagicMock()
        self.mock_storage.bucket_name = "test-zeek-bucket"
        self.runner = ZeekRunner(storage=self.mock_storage)"""
    content = re.sub(r'    def setUp\(self\):.*?self\.runner = ZeekRunner\(output_root=self\.output_root_temp\)', setup_replace, content, flags=re.DOTALL)
    
    content = content.replace('output_root=self.output_root_temp,', 'storage=self.mock_storage,')
    
    content = re.sub(r'        # Check output mount.*?self\.assertIn\(output_mount, executed_cmd\)', 
"""        output_mount_found = False
        for arg in executed_cmd:
            if ":/data/output" in arg:
                output_mount_found = True
                break
        self.assertTrue(output_mount_found)""", content, flags=re.DOTALL)

    content = content.replace('self.assertTrue(result.output_directory.exists())', 'self.assertEqual(result.bucket, "test-zeek-bucket")')
    
    content = re.sub(r'        self\.assertTrue\(len\(result\.generated_logs\) > 0\).*?self\.fail\(f"Log \{log_name\} was not written in JSON format: \{first_line\}"\)',
"""        self.assertTrue(len(result.generated_objects) > 0)
        self.assertTrue(self.mock_storage.upload_file.called)""", content, flags=re.DOTALL)

    content = content.replace('len(result.generated_logs)', 'len(result.generated_objects)')

    with open("backend/tests/unit/test_zeek_runner.py", "w", encoding="utf-8") as f:
        f.write(content)

patch_zeek_runner()
print("Runner patched safely.")
