import glob

for test_file in [
    "backend/tests/unit/test_conn_adapter.py",
    "backend/tests/unit/test_dns_adapter.py",
    "backend/tests/unit/test_http_adapter.py",
    "backend/tests/unit/test_tls_adapter.py",
]:
    with open(test_file, "r", encoding="utf-8") as f:
        content = f.read()
    
    # 1. Update ZeekRunnerResult fields
    content = content.replace('output_directory=self.output_dir,', 'bucket="test-bucket",\n            prefix="zeek/test/",')
    content = content.replace('output_directory=Path("/fake/output"),', 'bucket="test-bucket",\n            prefix="zeek/test/",')
    
    content = content.replace('generated_logs=["conn.log"],', 'generated_objects=["zeek/test/conn.log"],')
    content = content.replace('generated_logs=["conn.log", "dns.log"],', 'generated_objects=["zeek/test/conn.log", "zeek/test/dns.log"],')
    content = content.replace('generated_logs=["conn.log", "http.log"],', 'generated_objects=["zeek/test/conn.log", "zeek/test/http.log"],')
    content = content.replace('generated_logs=["conn.log", "ssl.log"],', 'generated_objects=["zeek/test/conn.log", "zeek/test/ssl.log"],')

    # 2. Mock storage in setUp
    setup_replace = """    def setUp(self):
        from unittest.mock import MagicMock
        from contextlib import contextmanager
        self.mock_storage = MagicMock()
        self.in_memory_files = {}

        @contextmanager
        def mock_stream_file(object_key: str):
            content = self.in_memory_files.get(object_key, "")
            lines = content.split('\\n')
            if lines and not lines[-1]:
                lines.pop()
            yield lines
        self.mock_storage.stream_file = mock_stream_file

        self.reader = ZeekReader(storage=self.mock_storage)"""
    
    # Find `self.reader = ZeekReader()` in setUp and replace previous lines
    import re
    content = re.sub(r'    def setUp\(self\):.*?self\.reader = ZeekReader\(\)', setup_replace, content, flags=re.DOTALL)

    # Remove writing to self.output_dir / "..." and put in self.in_memory_files
    content = content.replace('(self.output_dir / "conn.log").write_text(conn_log_content, encoding="utf-8")', 'self.in_memory_files["zeek/test/conn.log"] = conn_log_content')
    content = content.replace('(self.output_dir / "dns.log").write_text(dns_log_content, encoding="utf-8")', 'self.in_memory_files["zeek/test/dns.log"] = dns_log_content')
    content = content.replace('(self.output_dir / "http.log").write_text(http_log_content, encoding="utf-8")', 'self.in_memory_files["zeek/test/http.log"] = http_log_content')
    content = content.replace('(self.output_dir / "ssl.log").write_text(ssl_log_content, encoding="utf-8")', 'self.in_memory_files["zeek/test/ssl.log"] = ssl_log_content')

    with open(test_file, "w", encoding="utf-8") as f:
        f.write(content)

print("Adapters patched.")
