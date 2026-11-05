from jsonschema import validate
import time
import pytest

me_schema = {
    "type":"object",
    "required":["id","firstName","email"],
    "properties":{
        "id":{"type":"integer"},
        "firstname":{"type":"string"},
        "email":{"type":"string"},
    },
}

def test_user_login_get_token(auth_context):
    response = auth_context.get("/auth/me")
    assert response.status == 200
    assert response.json()["username"]=="emilys"

def test_me_without_token(anon_context):
    response = anon_context.get("/auth/me")
    print(anon_context.storage_state())
    assert response.status == 401

def test_fake_toke_test(anon_context):
    response = anon_context.get("/auth/me",headers={"Authorization":"Bearer abc12234"})
    assert response.status == 401

def test_schema_get_me(auth_context):
    response = auth_context.get("/auth/me",timeout=5000)
    assert response.status == 200
    validate(instance = response.json(),schema=me_schema)

def test_pagination(anon_context):
    start = time.perf_counter()
    response = anon_context.get("/products", params={"limit":5, "skip":10})
    elapsed_time = time.perf_counter() - start
    assert response.status == 200
    body = response.json()
    assert elapsed_time < 2, f"Too slow: {elapsed_time:.2f}s"
    assert len(body["products"]) == 5
    assert body["skip"] == 10
    assert body["limit"] == 5
    assert body["total"] >10

def test_pagination_negative(anon_context):
    response = anon_context.get("/products", params={"limit":5, "skip":195})
    assert response.status == 200
    body = response.json()
    assert body["products"] == []
    print(body)

# def test_pagination_negative2(anon_context):
#     response = anon_context.get("/products", params={"limit":"abc","skip":5})
#     assert response.status == 400
#     assert "Bad request" in response.json()

def test_pagination_page(anon_context):
    responsePage1 = anon_context.get("/products",params={"limit":5})
    responsePage2 = anon_context.get("/products",params={"limit":5,"skip":5})
    assert responsePage1.status == 200
    assert responsePage2.status == 200
    ids_page1 = {p["id"] for p in responsePage1.json()["products"]}
    ids_page2 = {p["id"] for p in responsePage2.json()["products"]}
    assert len(ids_page1) == 5 == len(ids_page2)
    assert ids_page1.isdisjoint(ids_page2),f"Duplicates: {ids_page1 & ids_page2}"

def test_pagination_elapsed_time_validation(anon_context):
    response_times = []
    for i in range(5):
        start = time.perf_counter()
        response = anon_context.get("/products", params={"limit":5, "skip":10})
        response_times.append(time.perf_counter() - start)
        assert response.status == 200
    avergae_time = sum(response_times)/len(response_times)
    print(f"Average response time: {avergae_time:.2f}s")
    assert avergae_time < 2, f"Average too slow: {avergae_time:.2f}s"

def test_idempotency_put(anon_context):
    payload = {"title":"Updated title"}
    response1 = anon_context.put("/products/1",data=payload)
    response2 = anon_context.put("/products/1",data=payload)

    assert response1.status == 200
    assert response2.status == 200

    assert response1.json()["title"] == response2.json()["title"] == payload["title"]

def test_idempotency_delete(anon_context):
    response1 = anon_context.delete("/products/1")
    response2 = anon_context.delete("/products/1")

    assert response1.status == 200
    assert response2.status == 200

    assert response1.json()["id"] == 1
    assert response2.json()["id"] == 1

@pytest.mark.parametrize("bad_value", [
    pytest.param("' OR 1=1 --", id="sql-injection"),
    pytest.param("<script>alert(1)</script>", id="xss"),
    pytest.param("a" * 100000, id="oversized-100k"),
])

    
def test_login_rejects_malicious_input(anon_context,bad_value):
    response = anon_context.post("/auth/login",data={"username":"emilys","password":bad_value})
    print(response.status)
    assert response.status in (401,400)
    assert response.status != 500

@pytest.mark.xfail(reason="Supposed to failed; response contains password", strict=True)
def test_me_response_has_no_password(auth_context):
    body = auth_context.get("/auth/me").json()
    assert "password" not in body

def test_delete_notfound(anon_context):
    response = anon_context.delete("/products/196")
    assert response.status == 404

@pytest.mark.xfail(reason="Supposed to fail; sensitive data returned in response", strict=True)
def test_sensitive_data(anon_context):
    response = anon_context.get("/auth/me")
    assert response.status == 200
    body = response.json()
    assert "ip" not in body


def test_debug_me_fields(auth_context):
    response = auth_context.get("/auth/me")
    print(response.status)
    print(list(response.json().keys()))
    print(response.json().get("bank"))

def test_debug_me_fields(anon_context):
    response = anon_context.get("/auth/me")
    print(response.status)
    print(list(response.json().keys()))
    print(response.json().get("bank"))

TOP_LEVEL = {"password", "ip", "macAddress","ssn","ein"}
NESTED_LEVEL = {"cardExpire","cardNumber","cardType","iban"}

@pytest.mark.xfail(reason="Supposed to fail; sensitive data returned in response", strict=True)
def test_sensitive_fields_returned_in_response(auth_context):
    response = auth_context.get("/auth/me")
    assert response.status == 200
    body = response.json()
    leaked = TOP_LEVEL & set(body.keys())
    leaked_bank = NESTED_LEVEL & set(body.get("bank", {}).keys())
    assert not (leaked | leaked_bank), f"Exposed: {leaked | leaked_bank}"
