import glob

for filepath in glob.glob("backend/tests/unit/test_*.py"):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Common adapter replacements
    content = content.replace('output_directory=self.output_dir', 'bucket="test-bucket",\n            prefix="zeek/test/"')
    content = content.replace('output_directory=Path("/fake/output")', 'bucket="test-bucket",\n            prefix="zeek/test/"')
    
    # We will replace `generated_logs=[...]` with `generated_objects=[...]` in each
    content = content.replace('generated_logs=["conn.log"]', 'generated_objects=["zeek/test/conn.log"]')
    content = content.replace('generated_logs=["conn.log", "dns.log"]', 'generated_objects=["zeek/test/conn.log", "zeek/test/dns.log"]')
    content = content.replace('generated_logs=["conn.log", "http.log"]', 'generated_objects=["zeek/test/conn.log", "zeek/test/http.log"]')
    content = content.replace('generated_logs=["conn.log", "ssl.log"]', 'generated_objects=["zeek/test/conn.log", "zeek/test/ssl.log"]')

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
