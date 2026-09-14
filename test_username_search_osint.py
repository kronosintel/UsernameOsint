import unittest
from unittest.mock import patch

from username_search_osint import OSINTTool, app, valid_username


class FakeResponse:
    def __init__(self, status_code, content_type="text/html", text=""):
        self.status_code = status_code
        self.headers = {"content-type": content_type}
        self.text = text

    def json(self):
        return {"login": "alice", "name": "Alice", "html_url": "https://github.com/alice"}


class UsernameSearchTests(unittest.TestCase):
    def test_username_validation(self):
        self.assertTrue(valid_username("alice.dev-1"))
        self.assertFalse(valid_username("alice smith"))
        self.assertFalse(valid_username("a/b"))
        self.assertFalse(valid_username(""))

    @patch("username_search_osint.requests.get")
    def test_404_is_not_found(self, get):
        get.return_value = FakeResponse(404)
        tool = OSINTTool("alice")
        tool.validate_profile("Instagram", "https://example.test/alice")
        self.assertEqual(tool.results["Instagram"]["status"], "not_found")
        self.assertFalse(tool.results["Instagram"]["exists"])

    @patch("username_search_osint.requests.get")
    def test_rate_limit_is_inconclusive(self, get):
        get.return_value = FakeResponse(429)
        tool = OSINTTool("alice")
        tool.validate_profile("GitHub", "https://example.test/alice")
        self.assertEqual(tool.results["GitHub"]["status"], "rate_limited")
        self.assertIsNone(tool.results["GitHub"]["exists"])

    def test_endpoint_requires_csrf(self):
        app.config.update(TESTING=True, SECRET_KEY="test")
        with app.test_client() as client:
            response = client.post("/osint", data={"username": "alice"})
            self.assertEqual(response.status_code, 400)

    def test_health_endpoint(self):
        app.config.update(TESTING=True)
        with app.test_client() as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, {"status": "ok"})

    def test_root_is_plain_text(self):
        app.config.update(TESTING=True)
        with app.test_client() as client:
            response = client.get("/")
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"UsernameSearchOSINT online", response.data)


if __name__ == "__main__":
    unittest.main()
