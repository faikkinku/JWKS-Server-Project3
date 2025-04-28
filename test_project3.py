import requests
import concurrent.futures

base_url = "http://localhost:8080"

def print_result(name, passed):
    if passed:
        print(f"[PASS] {name}")
    else:
        print(f"[FAIL] {name}")

def test_register():
    response = requests.post(f"{base_url}/register", json={"username": "testuser", "email": "testuser@example.com"})
    print_result("/register", response.status_code in [200, 201, 409])

def test_auth_valid():
    response = requests.post(f"{base_url}/auth")
    print_result("/auth (valid)", response.status_code == 200)

def test_auth_expired():
    response = requests.post(f"{base_url}/auth?expired=true")
    print_result("/auth (expired)", response.status_code == 200)

def test_jwks():
    response = requests.get(f"{base_url}/.well-known/jwks.json")
    try:
        result = response.status_code == 200 and "keys" in response.json()
    except Exception:
        result = False
    print_result("/.well-known/jwks.json", result)

def test_register_conflict():
    response = requests.post(f"{base_url}/register", json={"username": "testuser", "email": "another@example.com"})
    print_result("/register conflict", response.status_code == 409)

def test_rate_limiter():
    # Send 20 parallel requests at once
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(requests.post, f"{base_url}/auth") for _ in range(20)]
        responses = [f.result() for f in futures]

    # Check if any response was a 429
    passed = any(r.status_code == 429 for r in responses)
    print_result("/auth rate limit", passed)

if __name__ == "__main__":
    print("=== Running Tests ===")
    test_register()
    test_auth_valid()
    test_auth_expired()
    test_jwks()
    test_register_conflict()
    test_rate_limiter()
    print("=== Tests Done ===")
