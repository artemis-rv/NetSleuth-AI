import os
import boto3
from botocore.exceptions import ClientError
import asyncio
import asyncpg

def parse_env(file_path):
    if not os.path.exists(file_path):
        print(f"Warning: {file_path} not found.")
        return
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, val = line.split('=', 1)
                os.environ[key.strip()] = val.strip()

async def init_postgres():
    print("\n--- Initializing PostgreSQL ---")
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("DATABASE_URL not found in .env")
        return

    # Extract base URL without the database name (assuming /netsleuth is at the end)
    base_url = db_url.rsplit('/', 1)[0]
    base_url = f"{base_url}/postgres"

    try:
        conn = await asyncpg.connect(base_url)
        try:
            await conn.execute('CREATE DATABASE netsleuth')
            print("Database 'netsleuth' created successfully.")
        except Exception as e:
            print(f"Database creation skipped (it might already exist): {e}")
        finally:
            await conn.close()
    except Exception as e:
        print(f"Failed to connect to local Postgres using connection string '{base_url}': {e}")


def init_minio():
    print("\n--- Initializing MinIO Buckets ---")
    endpoint_url = os.environ.get("MINIO_ENDPOINT", "localhost:9000")
    if not endpoint_url.startswith("http"):
        use_ssl = os.environ.get("MINIO_USE_SSL", "false").lower() in ("true", "1", "yes")
        scheme = "https" if use_ssl else "http"
        endpoint_url = f"{scheme}://{endpoint_url}"

    access_key = os.environ.get("MINIO_ROOT_USER")
    secret_key = os.environ.get("MINIO_ROOT_PASSWORD")
    region = os.environ.get("MINIO_REGION", "us-east-1")

    if not access_key or not secret_key:
        print("Error: MINIO_ROOT_USER or MINIO_ROOT_PASSWORD not found in environment.")
        return

    print(f"Connecting to MinIO at {endpoint_url} as '{access_key}'...")
    
    try:
        s3 = boto3.client(
            's3',
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        buckets = [
            ("MINIO_BUCKET_EVIDENCE", "netsleuth-evidence", True),
            ("MINIO_BUCKET_ZEEK", "netsleuth-zeek", False),
            ("MINIO_BUCKET_DATASETS", "netsleuth-datasets", False),
            ("MINIO_BUCKET_MODELS", "netsleuth-models", False),
            ("MINIO_BUCKET_REPORTS", "netsleuth-reports", False),
        ]

        for env_var, default_name, is_locked in buckets:
            bucket_name = os.environ.get(env_var, default_name)
            try:
                s3.head_bucket(Bucket=bucket_name)
                print(f"Bucket '{bucket_name}' already exists.")
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code')
                if error_code == '404':
                    print(f"Creating bucket '{bucket_name}'...")
                    create_kwargs = {'Bucket': bucket_name}
                    if is_locked:
                        create_kwargs['ObjectLockEnabledForBucket'] = True
                    s3.create_bucket(**create_kwargs)
                    print(f"  -> Created.")
                    
                    if is_locked:
                        print(f"  -> Enabling versioning for '{bucket_name}'...")
                        s3.put_bucket_versioning(
                            Bucket=bucket_name,
                            VersioningConfiguration={'Status': 'Enabled'}
                        )
                else:
                    print(f"Error checking bucket '{bucket_name}': {e}")
    except Exception as e:
        print(f"Failed to connect to MinIO: {e}")

def main():
    parse_env(".env")
    asyncio.run(init_postgres())
    init_minio()

if __name__ == "__main__":
    main()
