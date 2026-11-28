import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from web.app import db, main

# Decompiled › Strings quick filters: GET /strings?kind=url|email|path|secret (heuristic, additive; no kind = unchanged).
HITS = {
    "url": ["https://api.example.com/v1/login", "ws://host:8080/socket", "content://com.x.provider/items", "krom://deeplink/open"],
    "email": ["support@example.com", "a.b+c@sub.example.co.uk", "Contact: help@example.com for support", "by <appro@openssl.org>"],
    "path": ["/system/bin/su", "/proc/self/maps", "/data/local/tmp/frida-server", "C:\\Windows\\System32"],
    "secret": [
        "AIzaSyDahXom56P260PRh8Fj-24EW81W92W-ryc",           # Google API key
        "AKIAIOSFODNN7EXAMPLE",                              # AWS access key id
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl",   # JWT
        "sk-abcdefghijklmnopqrstuvwx",
        "sk_live_abcdefghijklmnop",
        "ghp_" + "a1B2" * 9,
        "xoxb-12345-67890-abcdef",
        "-----BEGIN RSA PRIVATE KEY-----",
        "Bearer abc.def.ghi",
        "password=hunter2",
        '{"access_token": "abc"}',
        "access_token",
        "client_secret",
        "d41d8cd98f00b204e9800998ecf8427e",                  # 32 hex
        "eyJlcnJvciI6IlVOS05PV05fRVJST1IifQ==",              # padded base64 with digits
    ],
}
# near misses each heuristic must NOT claim
MISSES = [
    "plain value", "/", "relative/path/file.txt", "/ has spaces/in it", "/%@/format",
    "%@-%@.pb", "icon@2x.png", "@handle", "Item %@ at store %@.",
    "getAccessToken", "setPassword", "onTokenRefresh", "hasToken", "_timerTaskToken", "N18geo_imagery_viewer3api17ContinuationTokenE",
    "The password is wrong", "abcdefghijklmnopqrstuvwxyz==", "SinglePlacePhotoPickerGcorePlacePickerResultReceiveStatus",
    "java/util/concurrent/atomic/AtomicIntegerArray", "iVBORw0KGgoAAAANSUhEUgAAAAoAAAAoBAMAAAA1eHazAAAALVBMVEX80w==",
]


class StringsKindTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        h = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        h.close()
        self.path = h.name
        c = sqlite3.connect(self.path)
        c.execute("CREATE TABLE MachoStrings(address TEXT, value TEXT NOT NULL, segment TEXT, label TEXT, ExecutableName TEXT NOT NULL)")
        vals = [v for vs in HITS.values() for v in vs] + MISSES
        c.executemany("INSERT INTO MachoStrings VALUES (?,?,?,?,?)", [(f"0x{i:04x}", v, "__TEXT", "t", "app") for i, v in enumerate(vals)])
        c.execute("INSERT INTO MachoStrings VALUES ('0xffff','https://other.example/x','__TEXT','t','other')")   # another executable: never counted
        c.commit()
        c.close()
        self.total = len(vals)

    def tearDown(self):
        Path(self.path).unlink(missing_ok=True)

    async def page(self, kind=None, q=None, page=1, size=200):
        return await db.get_strings_page(self.path, "app", q, page, size, kind)

    async def test_each_kind_returns_exactly_its_hits(self):
        for kind, expected in HITS.items():
            r = await self.page(kind)
            got = {i.value for i in r.items}
            self.assertEqual(got, set(expected), f"kind={kind}: missing {set(expected) - got}, extra {got - set(expected)}")
            self.assertEqual(r.total, len(expected))

    async def test_default_is_unchanged(self):
        r = await self.page()
        self.assertEqual(r.total, self.total)                      # the other executable's row is still out of scope
        self.assertEqual([i.address for i in r.items[:3]], ["0x0000", "0x0001", "0x0002"])   # stable rowid order
        legacy = await db.get_strings_page(self.path, "app", None, 1, 200)                   # the 5-argument call every old caller makes
        self.assertEqual([i.value for i in legacy.items], [i.value for i in r.items])
        self.assertEqual((await db.get_strings_page(self.path, "app", "example", 1, 200)).total,
                         len([v for v in HITS["url"] + HITS["email"] + HITS["secret"] + MISSES if "example" in v.lower()]))
        self.assertEqual(len(await db.get_strings(self.path, "app", None, 2000)), self.total)

    async def test_kind_combines_with_q_by_and(self):
        r = await self.page("url", q="example")
        self.assertEqual([i.value for i in r.items], ["https://api.example.com/v1/login"])
        self.assertEqual(r.total, 1)
        self.assertEqual((await self.page("secret", q="token")).total, 2)      # access_token + {"access_token": "abc"}
        self.assertEqual((await self.page("path", q="needle-not-there")).total, 0)

    async def test_total_pages_and_paging_reflect_the_kind(self):
        n = len(HITS["secret"])
        p1 = await self.page("secret", page=1, size=10)
        p2 = await self.page("secret", page=2, size=10)
        self.assertEqual((p1.total, p1.pages, len(p1.items)), (n, 2, 10))
        self.assertEqual((p2.total, len(p2.items)), (n, n - 10))
        self.assertFalse({i.value for i in p1.items} & {i.value for i in p2.items})

    async def test_misses_are_not_claimed(self):
        every = set()
        for kind in HITS:
            every |= {i.value for i in (await self.page(kind)).items}
        self.assertFalse(every & set(MISSES), every & set(MISSES))

    async def test_legacy_list_honours_kind_too(self):
        got = await db.get_strings(self.path, "app", None, 2000, "email")
        self.assertEqual({i.value for i in got}, set(HITS["email"]))

    async def test_unknown_kind_is_rejected_by_the_db_layer(self):
        with self.assertRaises(ValueError):
            await self.page("1=1; DROP TABLE MachoStrings")


def _pad(prefix, total, ch="x"):
    return prefix + ch * (total - len(prefix))


U, E, P, S = "url", "email", "path", "secret"
# (value, kinds it must appear in). Every threshold in the heuristics has an n-1 / n / n+1 triple, so changing a constant or an
# operator in db._STRING_KINDS flips at least one of these. A value not listed for a kind must NOT appear under it.
BOUNDARY = [
    # Google API key: "AIza" + length >= 30
    (_pad("AIza", 29), set()), (_pad("AIza", 30), {S}), (_pad("AIza", 31), {S}), (_pad("aiza", 30), set()),
    # AWS access key id: "AKIA" + [A-Z0-9] and length exactly 20
    (_pad("AKIA", 19, "A"), set()), (_pad("AKIA", 20, "A"), {S}), (_pad("AKIA", 21, "A"), set()),
    (_pad("AKIB", 20, "A"), set()), (_pad("AKIA", 20, "a"), set()),
    # JWT: two dots, no space
    ("eyJa.b.c", {S}), ("eyJa.b", set()), ("eyJa.b.c d", set()),
    # sk-: length >= 20 and no space; sk_live_ / rk_live_ prefixes
    (_pad("sk-", 19, "a"), set()), (_pad("sk-", 20, "a"), {S}), (_pad("sk-", 21, "a"), {S}), (_pad("sk-", 17, "a") + " bb", set()),
    ("sk_live_x", {S}), ("rk_live_x", {S}), ("sk_liv_x", set()),
    # GitHub PAT: length >= 36
    (_pad("ghp_", 35, "a"), set()), (_pad("ghp_", 36, "a"), {S}), (_pad("ghp_", 37, "a"), {S}),
    # Slack, PEM, Bearer (length > 7, case-sensitive)
    ("xoxb-1", {S}), ("xoxp-1", {S}), ("xoxa-1", set()), ("xox-1", set()),
    ("-----BEGIN PRIVATE KEY-----", {S}), ("-----BEGIN RSA PRIVATE KEY-----", {S}), ("-----BEGIN CERTIFICATE-----", set()),
    ("Bearer ", set()), ("Bearer x", {S}), ("bearer x", set()),
    # random-looking tokens: hex 32..128, padded base64 >= 24 with a digit
    ("a" * 31, set()), ("a" * 32, {S}), ("0" * 128, {S}), ("0" * 129, set()), ("a" * 31 + "g", set()),
    (_pad("", 22, "b") + "1=", {S}), (_pad("", 21, "b") + "1=", set()), ("b" * 23 + "=", set()), ("b" * 23 + "1", set()),
    ("b" * 21 + "-1=", set()), ("iVBOR" + "b" * 18 + "1=", set()),
    # key=value pairs mentioning a credential word: length <= 120, a letter before "=", no "(" ";" or leading -+_$
    ("password=" + "x" * 111, {S}), ("password=" + "x" * 112, set()),
    ("password=x(", set()), ("password=x;", set()), ("-password=x", set()), ("_password=x", set()), ("$password=x", set()), ("+password=x", set()),
    ("password 1=2", set()), ('{"token": "x"}', {S}), ("token: x", set()), ("user=1", set()),
    ("api_key=1", {S}), ("apikey=1", {S}), ("api-key=1", {S}), ("secret=1", {S}), ("passwd=1", {S}), ("PASSWORD=1", {S}), ("ToKeN=1", {S}),
    # bare key names: length <= 48, identifier characters only, not a method/ivar/mangled name
    ("token" + "a" * 43, {S}), ("token" + "a" * 44, set()),
    ("api_key", {S}), ("apikey", {S}), ("api-key", {S}), ("client_secret", {S}), ("passwd", {S}), ("password", {S}), ("token", {S}), ("token.refresh", {S}),
    ("_token", set()), ("+token", set()), ("$token", set()), ("-token", set()), ("N9token", set()), ("Ntoken", {S}),
    ("getToken", set()), ("setToken", set()), ("onToken", set()), ("hasToken", set()), ("isToken", set()),
    ("gettoken", {S}), ("settoken", {S}), ("ontoken", {S}), ("hastoken", {S}), ("istoken", {S}),
    ("token value", set()), ("token/x", set()), ("tokenForKey:", set()), ("username", set()),
    # e-mail: a letter-led domain with a dot and a 2-letter label; the character before "@" must be an address character
    ("a@b.co", {E}), ("a@b.c.de", {E}), ("a b@c.de", {E}), ("https://a@b.co/x", {U, E}),
    ("a@b.c", set()), ("a@b.c1", set()), ("a@1b.co", set()), ("a@b", set()), ("%@b.co", set()), ("x%@b.co", set()), ("@b.co", set()),
    # path: /<name-char>…/…, no spaces, no % or @; Windows drive paths
    ("/a/b", {P}), ("/a/", {P}), ("/.hidden/x", {P}), ("/-x/y", {P}), ("/_x/y", {P}),
    ("/a", set()), ("//x/y", set()), ("/ a/b", set()), ("/a/b c", set()), ("/a/%b", set()), ("/a/b@c", set()), ("a/b/c", set()), ("/~x/y", set()),
    ("C:\\Windows", {P}), ("C:\\Program Files", set()), ("C:/x", set()), ("1:\\x", set()),
    # url: a scheme separator "://"
    ("http://x", {U}), ("x://", {U}), ("://", {U}), ("http:/x", set()), ("http//x", set()),
]


class StringsKindBoundaryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        h = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        h.close()
        self.path = h.name
        values = [v for v, _ in BOUNDARY]
        assert len(values) == len(set(values)), "boundary values must be unique"
        c = sqlite3.connect(self.path)
        c.execute("CREATE TABLE MachoStrings(address TEXT, value TEXT NOT NULL, segment TEXT, label TEXT, ExecutableName TEXT NOT NULL)")
        c.executemany("INSERT INTO MachoStrings VALUES (?,?,?,?,?)", [(f"{i}", v, "s", "l", "app") for i, v in enumerate(values)])
        c.commit()
        c.close()

    def tearDown(self):
        Path(self.path).unlink(missing_ok=True)

    async def test_every_threshold_has_a_hit_and_a_miss_on_each_side(self):
        got = {}
        for kind in db.STRING_KINDS:
            got[kind] = {i.value for i in (await db.get_strings_page(self.path, "app", None, 1, 200, kind)).items}
        wrong = [(v, k, "missing" if k in want else "unexpected") for v, want in BOUNDARY for k in db.STRING_KINDS if (k in want) != (v in got[k])]
        self.assertEqual(wrong, [], f"{len(wrong)} boundary cases differ: {wrong[:8]}")


class StringsKindRouteTests(unittest.TestCase):
    def setUp(self):
        h = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        h.close()
        self.path = h.name
        c = sqlite3.connect(self.path)
        c.execute("CREATE TABLE MachoStrings(address TEXT, value TEXT NOT NULL, segment TEXT, label TEXT, ExecutableName TEXT NOT NULL)")
        c.executemany("INSERT INTO MachoStrings VALUES (?,?,?,?,?)",
                      [("a", "https://a.example/x", "s", "l", "app"), ("b", "plain", "s", "l", "app"), ("c", "/system/bin/su", "s", "l", "app")])
        c.commit()
        c.close()
        self.patches = [patch.object(main, "_require_db", return_value=(self.path, "app")), patch.object(main.settings, "api_key", "")]
        for p in self.patches:
            p.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        Path(self.path).unlink(missing_ok=True)

    def test_kind_filters_the_paged_response(self):
        d = self.client.get("/api/v1/scans/s1/strings", params={"page": 1, "size": 10, "kind": "url"}).json()
        self.assertEqual((d["total"], d["pages"]), (1, 1))
        self.assertEqual(d["items"][0]["value"], "https://a.example/x")

    def test_without_kind_nothing_changes(self):
        d = self.client.get("/api/v1/scans/s1/strings", params={"page": 1, "size": 10}).json()
        self.assertEqual(d["total"], 3)
        self.assertEqual(len(self.client.get("/api/v1/scans/s1/strings").json()), 3)

    def test_kind_without_page_filters_the_flat_list(self):
        self.assertEqual([i["value"] for i in self.client.get("/api/v1/scans/s1/strings", params={"kind": "path"}).json()], ["/system/bin/su"])

    def test_unknown_kind_is_a_422(self):
        for bad in ("bogus", "URL", "", "url;drop"):
            r = self.client.get("/api/v1/scans/s1/strings", params={"page": 1, "kind": bad})
            self.assertEqual(r.status_code, 422, bad)


if __name__ == "__main__":
    unittest.main()
