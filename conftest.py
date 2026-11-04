import os
import pytest

BASE = "https://dummyjson.com"

@pytest.fixture(scope="session")
def anon_context(playwright):
    context = playwright.request.new_context(base_url=BASE)
    yield context
    context.dispose()

@pytest.fixture(scope="session")
def auth_context(playwright):
    login_ctx = playwright.request.new_context(base_url=BASE)
    login = login_ctx.post("auth/login", data={
        "username":os.environ["API_USERNAME"],
        "password": os.environ["API_PASSWORD"],
    })
    assert login.status == 200, f"Login failed:{login.text()}"
    token = login.json()["accessToken"]
    login_ctx.dispose() 

    context = playwright.request.new_context(
        base_url=BASE,
        extra_http_headers={"Authorization":f"Bearer {token}"},
    )
    yield context
    context.dispose()

