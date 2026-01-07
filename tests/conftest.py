"""Pytest configuration."""
import pytest
from fastapi.testclient import TestClient

@pytest.fixture
def client():
    """Test client fixture."""
    from backend.app.main import app
    return TestClient(app)
