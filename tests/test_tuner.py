"""Run: python3 -m unittest discover -s tests"""
import importlib.util
import json
import pathlib
import threading
import unittest
import urllib.error
import urllib.request

# No proxy for loopback requests.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("tuner", ROOT / "wazuh-tuner.py")
tuner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tuner)


class ParamTable(unittest.TestCase):
    def test_defaults_inside_ranges(self):
        for key, p in tuner.ALL_PARAMS.items():
            self.assertLessEqual(p["min"], p["default"], key)
            self.assertLessEqual(p["default"], p["max"], key)
            self.assertGreaterEqual(p["min"], 0, f"{key}: negative values stop the daemon")

    def test_presets_valid_and_not_noop(self):
        for name, preset in tuner.PRESETS.items():
            clean, errors = tuner.validate(preset["values"])
            self.assertEqual(errors, [], name)
            for k, v in clean.items():
                self.assertNotEqual(v, tuner.ALL_PARAMS[k]["default"], f"{name}: {k} equals default")


class Validate(unittest.TestCase):
    def test_rejects_bad_input(self):
        _, errors = tuner.validate({
            "remoted.ctrl_msg_queue_size": 1,          # wrong name
            "wazuh_modules.task_nice": -5,             # parser rejects '-'
            "wazuh_modules.rlimit_nofile": 4096,       # below 8192
            "analysisd.event_threads": "4\nfoo=1",     # line injection
            "analysisd.debug": True,
        })
        self.assertEqual(len(errors), 5)

    def test_generate_changed_only(self):
        out = tuner.generate({"remoted.worker_pool": 8, "analysisd.debug": 0})
        self.assertIn("remoted.worker_pool=8", out)
        self.assertNotIn("analysisd.debug", out)


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = tuner.Server(("127.0.0.1", 0), tuner.Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def post(self, body):
        req = urllib.request.Request(self.base + "/api/generate", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with OPENER.open(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.load(e)

    def test_page(self):
        with OPENER.open(self.base + "/") as r:
            html = r.read().decode()
        self.assertNotIn("__PARAMS__", html)
        self.assertIn("analysisd.decode_rootcheck_queue_size", html)

    def test_generate_ok(self):
        code, body = self.post({"values": {"analysisd.decode_rootcheck_queue_size": 131072}})
        self.assertEqual(code, 200)
        self.assertIn("analysisd.decode_rootcheck_queue_size=131072", body["config"])

    def test_generate_rejects(self):
        code, body = self.post({"values": {"remoted.worker_pool": 99}})
        self.assertEqual(code, 400)
        self.assertIn("outside", body["errors"][0])


if __name__ == "__main__":
    unittest.main()
