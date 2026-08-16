# NetSleuth-AI — MinIO Docker Configuration

This directory documents the MinIO container deployment for NetSleuth-AI local development.

## Location

The authoritative Compose configuration is at the repository root:

```
NetSleuth-AI/docker-compose.yml
```

## Image

```
quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z
```

## Services

| Service      | Container Name          | Role                              |
|-------------|-------------------------|-----------------------------------|
| minio        | netsleuth-minio         | MinIO S3 server + Console         |
| minio-init   | netsleuth-minio-init    | One-shot idempotent bucket init   |

## Ports

| Port | Protocol | Service           |
|------|----------|-------------------|
| 9000 | HTTP     | S3 API            |
| 9001 | HTTP     | MinIO Console     |

## Volume

| Volume Name          | Mount Point | Persists across `down`? |
|----------------------|-------------|-------------------------|
| netsleuth_minio_data | /data        | Yes                    |

See `docs/infrastructure/minio.md` for full documentation.
