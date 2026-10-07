import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from sherlock_lookup import consultar_username


class SherlockLookupTests(unittest.TestCase):
    def test_rejects_empty_or_invalid_timeout(self):
        with self.assertRaises(ValueError):
            consultar_username("   ")
        with self.assertRaises(ValueError):
            consultar_username("alice", timeout=0)

    def test_returns_structured_results_from_worker(self):
        expected = [{"site": "GitHub", "url": "https://github.com/alice", "status": "found"}]
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps({"encontrados": expected}), stderr="")
        with patch("sherlock_lookup.subprocess.run", return_value=completed) as run:
            result = consultar_username("@alice", timeout=5, site_timeout=2)
        self.assertEqual(result.username, "alice")
        self.assertEqual(result.encontrados, expected)
        self.assertEqual(result.total_encontrados, 1)
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        self.assertIn("sherlock_worker.py", run.call_args.args[0][1])

    def test_preserves_confirmed_partial_results_after_timeout(self):
        expected = [{"site": "GitHub", "url": "https://github.com/alice", "status": "found"}]

        def timeout_with_partial(command, **kwargs):
            Path(command[-1]).write_text(json.dumps(expected), encoding="utf-8")
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        with patch("sherlock_lookup.subprocess.run", side_effect=timeout_with_partial):
            result = consultar_username("alice", timeout=1, site_timeout=1)
        self.assertEqual(result.encontrados, expected)
        self.assertIn("parciais", result.erro)

    def test_raises_timeout_when_no_partial_results_exist(self):
        with patch("sherlock_lookup.subprocess.run", side_effect=subprocess.TimeoutExpired("sherlock", 1)):
            with self.assertRaises(TimeoutError):
                consultar_username("alice", timeout=1, site_timeout=1)


if __name__ == "__main__":
    unittest.main()
