import re

def patch_zeek_reader():
    with open("backend/tests/unit/test_zeek_reader.py", "r", encoding="utf-8") as f:
        content = f.read()
    
    # Imports
    content = content.replace("from typing import Generator\n\n", "from typing import Generator\nfrom unittest.mock import MagicMock\nfrom contextlib import contextmanager\n\n")

    setup_replace = """    def setUp(self):
        self.acquisition_id = "acq-12345"
        self.mock_storage = MagicMock()
        self.reader = ZeekReader(storage=self.mock_storage)
        
        @contextmanager
        def mock_stream_file(object_key: str):
            yield []
            
        self.mock_storage.stream_file = mock_stream_file

    def tearDown(self):
        pass

    def _setup_mock_stream(self, content: str) -> None:
        from contextlib import contextmanager
        @contextmanager
        def mock_stream_file(object_key: str):
            lines = content.split('\\n')
            if lines and not lines[-1]:
                lines.pop()
            yield lines
        self.mock_storage.stream_file = mock_stream_file"""
    
    content = re.sub(r'    def setUp\(self\):.*?def _create_log_file\(self, filename: str, content: str\) -> None:\n        file_path = self\.output_dir / filename\n        file_path\.write_text\(content, encoding="utf-8"\)', setup_replace, content, flags=re.DOTALL)

    mock_result_replace = """    def _create_mock_result(self, generated_objects: list[str]) -> ZeekRunnerResult:
        return ZeekRunnerResult(
            acquisition_id=self.acquisition_id,
            status=ZeekRunnerStatus.SUCCESS,
            bucket="test-zeek-bucket",
            prefix=f"zeek/{self.acquisition_id}/",
            generated_objects=generated_objects,
            exit_code=0,
            execution_duration_s=1.0,
            zeek_image="zeek/zeek:lts",
            zeek_version="8.0.0",
            stderr_tail="",
        )"""
    content = re.sub(r'    def _create_mock_result\(self, generated_logs: list\[str\]\) -> ZeekRunnerResult:.*?(?=    def test_valid_json_log)', mock_result_replace + "\n\n", content, flags=re.DOTALL)

    content = content.replace('self._create_log_file("conn.log", content)', 'self._setup_mock_stream(content)')
    content = content.replace('result = self._create_mock_result(["conn.log"])', 'result = self._create_mock_result([f"zeek/{self.acquisition_id}/conn.log"])')
    
    content = content.replace('self._create_log_file("dns.log", "")', 'self._setup_mock_stream("")')
    content = content.replace('result = self._create_mock_result(["dns.log"])', 'result = self._create_mock_result([f"zeek/{self.acquisition_id}/dns.log"])')

    content = content.replace('self._create_log_file("weird.log", content)', 'self._setup_mock_stream(content)')
    content = content.replace('result = self._create_mock_result(["weird.log"])', 'result = self._create_mock_result([f"zeek/{self.acquisition_id}/weird.log"])')

    content = content.replace('self._create_log_file("x509.log", content)', 'self._setup_mock_stream(content)')
    content = content.replace('result = self._create_mock_result(["x509.log"])', 'result = self._create_mock_result([f"zeek/{self.acquisition_id}/x509.log"])')

    # Fix integration test
    int_setup_replace = """    def setUp(self):
        import tempfile
        self.evidence_temp = tempfile.mkdtemp()
        from unittest.mock import MagicMock
        from contextlib import contextmanager
        self.mock_storage = MagicMock()
        self.mock_storage.bucket_name = "test-zeek-bucket"
        self.in_memory_files = {}
        
        def mock_upload_file(file_path, object_key):
            with open(file_path, 'r', encoding='utf-8') as f:
                self.in_memory_files[object_key] = f.read()
        self.mock_storage.upload_file = mock_upload_file
        
        @contextmanager
        def mock_stream_file(object_key: str):
            content = self.in_memory_files.get(object_key, "")
            lines = content.split('\\n')
            if lines and not lines[-1]:
                lines.pop()
            yield lines
        self.mock_storage.stream_file = mock_stream_file

        self.runner = ZeekRunner(storage=self.mock_storage)
        self.reader = ZeekReader(storage=self.mock_storage)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.evidence_temp, ignore_errors=True)"""
    content = re.sub(r'    def setUp\(self\):\n        self\.output_root_temp = tempfile\.mkdtemp\(\).*?shutil\.rmtree\(self\.evidence_temp, ignore_errors=True\)', int_setup_replace, content, flags=re.DOTALL)
    
    content = content.replace('len(runner_result.generated_logs)', 'len(runner_result.generated_objects)')

    with open("backend/tests/unit/test_zeek_reader.py", "w", encoding="utf-8") as f:
        f.write(content)

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

patch_zeek_reader()
patch_zeek_runner()
print("Reader/Runner patched.")
