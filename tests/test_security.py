from phishhunter.security.passwords import hash_password, verify_password
from phishhunter.security.url_guard import validate_url

def test_password_roundtrip():
    digest=hash_password("Strong-Password-123!")
    assert verify_password("Strong-Password-123!",digest)
    assert not verify_password("wrong",digest)

def test_blocks_loopback():
    try: validate_url("http://127.0.0.1/")
    except ValueError: return
    raise AssertionError("loopback not blocked")
