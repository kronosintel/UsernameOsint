import unittest

from usernamesearchosint import app, executar_varredura_com_timeout, resultados_username_rapidos


class UsernameSearchTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "healthy")
        self.assertIn("telegram_configured", response.json)
        self.assertIn("mercadopago_configured", response.json)
        self.assertIn("maigret_enabled", response.json)

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Kronos Intel OSINT Active", response.data)

    def test_fast_username_fallback_contains_links(self):
        results = resultados_username_rapidos("alice")
        self.assertIn("GitHub", results)
        self.assertTrue(results["GitHub"]["url"].endswith("/alice"))
        self.assertEqual(results["GitHub"]["exists"], True)
        self.assertEqual(results["MyCred — referência manual"]["status"], "reference_only")

    def test_email_lookup_returns_without_optional_api_key(self):
        results = executar_varredura_com_timeout("teste@example.com", "email")
        self.assertIn("Have I Been Pwned", results)
        self.assertIn("Mozilla Monitor", results)

    def test_missing_report_returns_404(self):
        response = self.client.get("/relatorio/token-inexistente")
        self.assertEqual(response.status_code, 404)

    def test_missing_pdf_returns_404(self):
        response = self.client.get("/download/pdf/token-inexistente")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
