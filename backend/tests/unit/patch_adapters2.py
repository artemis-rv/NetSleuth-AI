import re

def patch_adapter(test_file, class_name, log_types):
    with open(test_file, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Update ZeekRunnerResult fields
    content = content.replace('output_directory=self.output_dir,', 'bucket="test-bucket",\n            prefix="zeek/test/",')
    content = content.replace('output_directory=Path("/fake/output"),', 'bucket="test-bucket",\n            prefix="zeek/test/",')
    
    content = content.replace('generated_logs=["conn.log"],', 'generated_objects=["zeek/test/conn.log"],')
    content = content.replace('generated_logs=["conn.log", "dns.log"],', 'generated_objects=["zeek/test/conn.log", "zeek/test/dns.log"],')
    content = content.replace('generated_logs=["conn.log", "http.log"],', 'generated_objects=["zeek/test/conn.log", "zeek/test/http.log"],')
    content = content.replace('generated_logs=["conn.log", "ssl.log"],', 'generated_objects=["zeek/test/conn.log", "zeek/test/ssl.log"],')

    setup_start = content.find(f"class {class_name}(unittest.TestCase):")
    if setup_start == -1:
        return
        
    tear_down_start = content.find("    def tearDown(self):", setup_start)
    next_def = content.find("    def test_", tear_down_start)
    def_setup_idx = content.find("    def setUp(self):", setup_start)
    
    adapter_inits = []
    if "Conn" in class_name:
        adapter_inits.append("self.adapter = ConnAdapter()")
    else:
        adapter_inits.append("self.conn_adapter = ConnAdapter()")
        if "DNS" in class_name:
            adapter_inits.append("self.dns_adapter = DNSAdapter()")
        elif "HTTP" in class_name:
            adapter_inits.append("self.http_adapter = HTTPAdapter()")
        elif "TLS" in class_name:
            adapter_inits.append("self.tls_adapter = TLSAdapter()")
            
    adapter_inits_str = "\\n        ".join(adapter_inits)

    setup_replace = f"""    def setUp(self):
        from unittest.mock import MagicMock
        from contextlib import contextmanager
        self.mock_storage = MagicMock()
        self.mock_storage.bucket_name = "test-bucket"
        self.in_memory_files = {{}}

        @contextmanager
        def mock_stream_file(object_key: str):
            content = self.in_memory_files.get(object_key, "")
            lines = content.split('\\\\n')
            if lines and not lines[-1]:
                lines.pop()
            yield lines
        self.mock_storage.stream_file = mock_stream_file

        self.reader = ZeekReader(storage=self.mock_storage)
        """ + adapter_inits_str.replace("\\n", "\n") + "\n\n"
    
    content = content[:def_setup_idx] + setup_replace + content[tear_down_start:next_def].replace("        import shutil\n        shutil.rmtree(self.output_root_temp, ignore_errors=True)", "        pass") + content[next_def:]

    content = content.replace('(self.output_dir / "conn.log").write_text(conn_log_content, encoding="utf-8")', 'self.in_memory_files["zeek/test/conn.log"] = conn_log_content')
    content = content.replace('(self.output_dir / "dns.log").write_text(dns_log_content, encoding="utf-8")', 'self.in_memory_files["zeek/test/dns.log"] = dns_log_content')
    content = content.replace('(self.output_dir / "http.log").write_text(http_log_content, encoding="utf-8")', 'self.in_memory_files["zeek/test/http.log"] = http_log_content')
    content = content.replace('(self.output_dir / "ssl.log").write_text(ssl_log_content, encoding="utf-8")', 'self.in_memory_files["zeek/test/ssl.log"] = ssl_log_content')

    with open(test_file, "w", encoding="utf-8") as f:
        f.write(content.replace("\\\\n", "\\n"))

patch_adapter("backend/tests/unit/test_conn_adapter.py", "TestConnAdapterIntegration", ["conn.log"])
patch_adapter("backend/tests/unit/test_dns_adapter.py", "TestDNSAdapterIntegration", ["conn.log", "dns.log"])
patch_adapter("backend/tests/unit/test_http_adapter.py", "TestHTTPAdapterIntegration", ["conn.log", "http.log"])
patch_adapter("backend/tests/unit/test_tls_adapter.py", "TestTLSAdapterIntegration", ["conn.log", "ssl.log"])
print("Adapters patched safely.")
