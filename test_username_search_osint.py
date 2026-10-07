import unittest
import sqlite3
import tempfile
from unittest.mock import MagicMock, Mock, patch

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
        self.assertEqual(response.json["maigret_timeout_seconds"], bot_module.timeout_maigret_efetivo())
        self.assertIn("consulta_timeout_seconds", response.json)
        self.assertIn("consulta_price_brl", response.json)
        self.assertEqual(response.json["billing_mode"], "monthly_pass")
        self.assertEqual(response.json["monthly_pass_days"], 30)
        self.assertIn("result_cache_seconds", response.json)
        self.assertIn("query_cooldown_seconds", response.json)
        self.assertIn("metrics", response.json)
        self.assertIn("maigret_fallbacks", response.json["metrics"])

    def test_effective_maigret_timeout_is_capped_for_speed(self):
        with (
            patch.object(bot_module.CFG, "MAIGRET_TIMEOUT", 25),
            patch.object(bot_module.CFG, "CONSULTA_TIMEOUT", 35),
        ):
            self.assertEqual(bot_module.timeout_maigret_efetivo(), 10)

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Kronos Intel OSINT Active", response.data)

    def test_telegram_webhook_acks_start_immediately(self):
        payload = {
            "update_id": 999,
            "message": {"message_id": 1, "chat": {"id": 123, "type": "private"}, "text": "/start"},
        }
        with patch.object(bot_module, "bot", object()), patch.object(bot_module, "Thread") as thread:
            response = self.client.post("/telegram", json=payload)
        self.assertEqual(response.status_code, 200)
        thread.assert_called_once_with(target=bot_module._processar_update_async, args=(payload,), daemon=True)

    def test_start_worker_dispatches_welcome_directly(self):
        payload = {"update_id": 1001, "message": {"text": "/start"}}
        update = Mock()
        update.message.text = "/start"
        with (
            patch.object(bot_module, "bot", Mock()) as fake_bot,
            patch.object(bot_module.Update, "de_json", return_value=update),
            patch.object(bot_module, "send_welcome", create=True) as send_welcome,
        ):
            bot_module._processar_update_async(payload)
        send_welcome.assert_called_once_with(update.message)
        fake_bot.process_new_updates.assert_not_called()

    def test_telegram_webhook_keeps_other_updates_async(self):
        payload = {
            "update_id": 1000,
            "message": {"message_id": 2, "chat": {"id": 123, "type": "private"}, "text": "/user alice"},
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
            patch.object(bot_module, "db_execute") as db_execute,
            patch.object(bot_module, "acesso_mensal_ativo") as check_subscription,
            patch.object(bot_module, "usuario_esta_no_canal") as check_channel,
            patch.object(bot_module, "atualizar_progresso"),
            patch.object(bot_module, "executar_varredura_com_timeout", return_value={}),
            patch.object(bot_module, "enviar_resultado_telegram"),
        ):
            bot_module._processar_busca(message, "alice")
        db_execute.assert_not_called()
        check_subscription.assert_not_called()
        check_channel.assert_not_called()

    def test_failed_free_report_restores_free_query(self):
        message = Mock()
        message.from_user.id = 123
        message.chat.id = 123
        with (
            patch.object(bot_module.CFG, "ADMIN_ID", 999),
            patch.object(bot_module.CFG, "ADMIN_BYPASS_PAYMENT", False),
            patch.object(bot_module, "bot", Mock()),
            patch.object(bot_module, "db_execute"),
            patch.object(bot_module, "consulta_em_cooldown", return_value=False),
            patch.object(bot_module, "acesso_mensal_ativo", return_value=(False, None)),
            patch.object(bot_module, "usuario_esta_no_canal", return_value=True),
            patch.object(bot_module, "reivindicar_consulta_gratis", return_value=True),
            patch.object(bot_module, "devolver_consulta_gratis") as devolver,
            patch.object(bot_module, "Thread"),
            patch.object(bot_module, "atualizar_progresso"),
            patch.object(bot_module, "executar_varredura_com_timeout", return_value={"GitHub": {"url": "https://github.com/alice"}}),
            patch.object(bot_module, "enviar_resultado_telegram", side_effect=sqlite3.OperationalError("database is locked")),
        ):
            with self.assertRaises(bot_module.ConsultaGratisRestaurada):
                bot_module._processar_busca(message, "alice")
        devolver.assert_called_once_with(123)

    def test_restored_free_query_message_allows_retry(self):
        message = Mock()
        message.from_user.id = 123
        message.chat.id = 123
        fake_bot = Mock()
        with (
            patch.object(bot_module, "_processar_busca", side_effect=bot_module.ConsultaGratisRestaurada()),
            patch.object(bot_module, "bot", fake_bot),
            patch.object(bot_module, "atualizar_progresso"),
        ):
            bot_module.processar_busca(message, "alice")
        self.assertIn("consulta grátis foi devolvida", fake_bot.send_message.call_args.args[1])
        self.assertIn("enviar novamente", fake_bot.send_message.call_args.args[1])

    def test_db_execute_read_does_not_wait_on_python_lock(self):
        fake_lock = Mock()
        fake_conn = Mock()
        fake_cursor = fake_conn.cursor.return_value
        fake_cursor.fetchone.return_value = (1,)
        with (
            patch.object(bot_module, "db_lock", fake_lock),
            patch.object(bot_module.sqlite3, "connect", return_value=fake_conn) as connect,
        ):
            self.assertEqual(bot_module.db_execute("SELECT 1", fetchone=True), (1,))
        fake_lock.acquire.assert_not_called()
        connect.assert_called_once_with(bot_module.CFG.DB_FILE, timeout=30.0)
        fake_conn.close.assert_called_once()

    def test_db_execute_serializes_committing_writes(self):
        fake_lock = MagicMock()
        fake_conn = Mock()
        with (
            patch.object(bot_module, "db_lock", fake_lock),
            patch.object(bot_module.sqlite3, "connect", return_value=fake_conn),
        ):
            bot_module.db_execute("INSERT INTO test_table VALUES (?)", (1,), commit=True)
        fake_lock.acquire.assert_called_once_with(timeout=10.0)
        fake_lock.release.assert_called_once()
        fake_conn.commit.assert_called_once()
        fake_conn.close.assert_called_once()

    def test_sqlite_write_lock_times_out_when_another_process_holds_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = f"{directory}/test.db"
            lock_path = f"{db_path}.write-lock"
            blocker = open(lock_path, "a")
            bot_module.fcntl.flock(blocker.fileno(), bot_module.fcntl.LOCK_EX | bot_module.fcntl.LOCK_NB)
            try:
                with patch.object(bot_module.CFG, "DB_FILE", db_path):
                    with self.assertRaises(TimeoutError):
                        with bot_module.sqlite_write_lock(timeout_seconds=0.05):
                            self.fail("O lock deveria ter expirado antes de entrar")
            finally:
                bot_module.fcntl.flock(blocker.fileno(), bot_module.fcntl.LOCK_UN)
                blocker.close()

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

    def test_report_storage_error_returns_friendly_503(self):
        with patch.object(bot_module, "db_execute", side_effect=sqlite3.OperationalError("disk I/O error")):
            response = self.client.get("/relatorio/test-token")
        self.assertEqual(response.status_code, 503)
        self.assertIn("Relatório temporariamente indisponível", response.get_data(as_text=True))
        self.assertNotIn("disk I/O error", response.get_data(as_text=True))

    def test_pdf_storage_error_returns_friendly_503(self):
        with patch.object(bot_module, "db_execute", side_effect=sqlite3.OperationalError("disk I/O error")):
            response = self.client.get("/download/pdf/test-token")
        self.assertEqual(response.status_code, 503)
        self.assertIn("Relatório temporariamente indisponível", response.get_data(as_text=True))
        self.assertNotIn("disk I/O error", response.get_data(as_text=True))

    def test_missing_pdf_returns_404(self):
        response = self.client.get("/download/pdf/token-inexistente")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
