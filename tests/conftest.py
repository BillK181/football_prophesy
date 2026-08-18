import pytest

from football_prophesy.app import create_app
from football_prophesy.extensions import db


@pytest.fixture
def app():
    app = create_app()

    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
    )

    with app.app_context():
        yield app


@pytest.fixture
def client(app):
    return app.test_client()