import re

def patch_zeek_reader():
    with open("backend/tests/unit/test_zeek_reader.py", "r", encoding="utf-8") as f:
        content = f.read()

    content = content.replace("output_directory=self.output_dir,\n            generated_logs=generated_logs", "bucket=\"test-zeek-bucket\",\n            prefix=f\"zeek/{self.acquisition_id}/\",\n            generated_objects=generated_logs")

    content = content.replace('def _create_log_file(self, filename: str, content: str) -> None:\n        file_path = self.output_dir / filename\n        file_path.write_text(content, encoding="utf-8")', 
"""def _setup_mock_stream(self, content: str) -> None:
        from contextlib import contextmanager
        @contextmanager
        def mock_stream_file(object_key: str):
            lines = content.split('\\\\n')
            if lines and not lines[-1]:
                lines.pop()
            yield lines
        self.mock_storage.stream_file = mock_stream_file""")

    content = content.replace('self._create_log_file("conn.log", content)', 'self._setup_mock_stream(content)')
    content = content.replace('self._create_log_file("dns.log", "")', 'self._setup_mock_stream("")')
    content = content.replace('self._create_log_file("weird.log", content)', 'self._setup_mock_stream(content)')
    content = content.replace('self._create_log_file("x509.log", content)', 'self._setup_mock_stream(content)')
    content = content.replace('self._create_log_file("conn.log", \'{"uid": "1"}\\n\')\n        self._create_log_file("dns.log", \'{"uid": "2"}\\n\')', 'self._setup_mock_stream(\'{"uid": "1"}\\n{"uid": "2"}\\n\')')

    content = content.replace('self._create_mock_result(["conn.log"])', 'self._create_mock_result([f"zeek/{self.acquisition_id}/conn.log"])')
    content = content.replace('self._create_mock_result(["dns.log"])', 'self._create_mock_result([f"zeek/{self.acquisition_id}/dns.log"])')
    content = content.replace('self._create_mock_result(["weird.log"])', 'self._create_mock_result([f"zeek/{self.acquisition_id}/weird.log"])')
    content = content.replace('self._create_mock_result(["x509.log"])', 'self._create_mock_result([f"zeek/{self.acquisition_id}/x509.log"])')
    content = content.replace('self._create_mock_result(["conn.log", "dns.log"])', 'self._create_mock_result([f"zeek/{self.acquisition_id}/conn.log", f"zeek/{self.acquisition_id}/dns.log"])')
    
    setup_replace = """    def setUp(self):
        self.acquisition_id = "acq-12345"
        from unittest.mock import MagicMock
        self.mock_storage = MagicMock()
        self.reader = ZeekReader(storage=self.mock_storage)"""
    content = re.sub(r'    def setUp\(self\):\n        self\.temp_dir = tempfile\.TemporaryDirectory\(\)\n        self\.output_dir = Path\(self\.temp_dir\.name\)\n        self\.acquisition_id = "acq-12345"\n        self\.reader = ZeekReader\(\)', setup_replace, content)
    
    content = content.replace("    def tearDown(self):\n        self.temp_dir.cleanup()", "    def tearDown(self):\n        pass")

    start_invalid = content.find("    def test_invalid_output_directory(self):")
    if start_invalid != -1:
        end_invalid = content.find("    def test_metadata_preservation(self):", start_invalid)
        content = content[:start_invalid] + content[end_invalid:]

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
            lines = content.split('\\\\n')
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
        f.write(content.replace("\\\\n", "\\n"))

patch_zeek_reader()
print("Reader patched safely.")
