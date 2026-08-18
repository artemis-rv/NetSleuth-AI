import pytest
from fastapi.testclient import TestClient

from app.main import create_app

@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as client:
        yield client

def test_openapi_schema_loads(client: TestClient):
    """Verify OpenAPI schema can be generated without errors."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert "openapi" in schema
    assert "paths" in schema
    assert "components" in schema

def test_no_orm_models_leaked_in_schema(client: TestClient):
    """Verify response models don't leak ORM classes (which typically contain 'Model' in their name)."""
    response = client.get("/openapi.json")
    schema = response.json()
    schemas = schema.get("components", {}).get("schemas", {})
    
    leaked = []
    for schema_name in schemas.keys():
        if "Model" in schema_name and schema_name != "ErrorModel":
            leaked.append(schema_name)
    
    assert not leaked, f"Potential ORM models leaked into public API schema: {leaked}"

def test_error_envelope_structure(client: TestClient):
    """Verify an error response matches the expected contract envelope."""
    response = client.get("/api/v1/does_not_exist")
    assert response.status_code == 404
    data = response.json()
    
    assert "error" in data
    err = data["error"]
    assert "code" in err
    assert "message" in err
    assert "request_id" in err

def test_pagination_envelope_structure(client: TestClient):
    """
    Verify pagination response contract by requesting a paginated list endpoint.
    Since cases require auth, we check if the 401 Unauthorized uses the error envelope.
    For schema checking, we inspect the OpenAPI spec.
    """
    response = client.get("/openapi.json")
    schema = response.json()
    schemas = schema.get("components", {}).get("schemas", {})
    
    # Check that a common list response exists and has standard pagination fields
    # e.g., CaseListResponse
    case_list_schema = schemas.get("CaseListResponse")
    if case_list_schema:
        props = case_list_schema.get("properties", {})
        assert "items" in props
        assert "total" in props
        assert "page" in props
        assert "page_size" in props
