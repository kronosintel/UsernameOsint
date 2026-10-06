import unittest
from unittest.mock import Mock, patch

import usernamesearchosint as bot_module
from usernamesearchosint import app, categoria_fonte, executar_varredura_com_timeout, resultados_username_rapidos, username_valido


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
        self.assertIn("maigret_timeout_seconds", response.json)
        self.assertIn("consulta_timeout_seconds", response.json)
        self.assertIn("consulta_price_brl", response.json)
        self.assertEqual(response.json["billing_mode"], "monthly_pass")
        self.assertEqual(response.json["monthly_pass_days"], 30)
        self.assertIn("result_cache_seconds", response.json)
        self.assertIn("query_cooldown_seconds", response.json)
        self.assertIn("metrics", response.json)
        self.assertIn("maigret_fallbacks", response.json["metrics"])

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Kronos Intel OSINT Active", response.data)

    def test_telegram_webhook_acks_start_without_blocking(self):
        payload = {
            "update_id": 999,
            "message": {"message_id": 1, "chat": {"id": 123, "type": "private"}, "text": "/start"},
        }
        with patch.object(bot_module, "bot", object()), patch.object(bot_module, "Thread") as thread:
            response = self.client.post("/telegram", json=payload)
        self.assertEqual(response.status_code, 200)
        thread.assert_called_once()

    def test_admin_bypass_skips_channel_membership_lookup(self):
        message = Mock()
        message.from_user.id = 123
        message.chat.id = 123
        with (
            patch.object(bot_module.CFG, "ADMIN_ID", 123),
            patch.object(bot_module.CFG, "ADMIN_BYPASS_PAYMENT", True),
            patch.object(bot_module, "db_execute"),
            patch.object(bot_module, "acesso_mensal_ativo", return_value=(False, None)),
            patch.object(bot_module, "usuario_esta_no_canal") as check_channel,
            patch.object(bot_module, "atualizar_progresso"),
            patch.object(bot_module, "executar_varredura_com_timeout", return_value={}),
            patch.object(bot_module, "enviar_resultado_telegram"),
        ):
            bot_module._processar_busca(message, "alice")
        check_channel.assert_not_called()

    def test_fast_username_fallback_contains_links(self):
        results = resultados_username_rapidos("alice")
        self.assertIn("GitHub", results)
        self.assertTrue(results["GitHub"]["url"].endswith("/alice"))
        self.assertEqual(results["GitHub"]["exists"], True)
        self.assertEqual(results["GitHub"]["category"], "Desenvolvimento")
        self.assertEqual(results["Instagram"]["category"], "Redes e conteúdo")
        self.assertIn("Telegram", results)
        self.assertIn("Kaggle", results)
        self.assertEqual(results["Kaggle"]["category"], "Desenvolvimento")
        self.assertEqual(results["MyCred — referência manual"]["status"], "reference_only")

    def test_source_categories_are_stable(self):
        self.assertEqual(categoria_fonte("GitHub", "https://github.com/alice"), "Desenvolvimento")
        self.assertEqual(categoria_fonte("Steam", "https://steamcommunity.com/id/alice"), "Jogos e comunidades")
        self.assertEqual(categoria_fonte("Google", "https://google.com", "reference_only"), "Busca e referências")

    def test_non_username_lookup_is_rejected(self):
        with self.assertRaises(ValueError):
            executar_varredura_com_timeout("teste@example.com", "email")

    def test_username_format_rejects_numeric_ids(self):
        self.assertFalse(username_valido("6633554708"))
        self.assertFalse(username_valido("https://example.com/user"))
        self.assertTrue(username_valido("alice_2026"))

    def test_missing_report_returns_404(self):
        response = self.client.get("/relatorio/token-inexistente")
        self.assertEqual(response.status_code, 404)

    def test_missing_pdf_returns_404(self):
        response = self.client.get("/download/pdf/token-inexistente")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
