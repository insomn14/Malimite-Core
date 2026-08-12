import sqlite3
import tempfile
import unittest
from pathlib import Path

from web.app import db


class StringPaginationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        handle.close()
        self.db_path = handle.name
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE MachoStrings (
                    address TEXT,
                    value TEXT NOT NULL,
                    segment TEXT,
                    label TEXT,
                    ExecutableName TEXT NOT NULL
                )"""
            )
            conn.executemany(
                "INSERT INTO MachoStrings VALUES (?, ?, ?, ?, ?)",
                [
                    (
                        f"0x{index:04x}",
                        f"{'needle ' if index % 10 == 0 else ''}value {index}",
                        "__TEXT",
                        "test",
                        "Target",
                    )
                    for index in range(125)
                ],
            )
            conn.execute(
                "INSERT INTO MachoStrings VALUES (?, ?, ?, ?, ?)",
                ("0xffff", "needle from another executable", "__TEXT", "test", "Other"),
            )

    def tearDown(self):
        Path(self.db_path).unlink(missing_ok=True)

    async def test_returns_stable_page_and_total(self):
        result = await db.get_strings_page(
            self.db_path, "Target", None, page=2, size=50
        )

        self.assertEqual(result.total, 125)
        self.assertEqual(result.page, 2)
        self.assertEqual(result.size, 50)
        self.assertEqual(result.pages, 3)
        self.assertEqual(len(result.items), 50)
        self.assertEqual(result.items[0].address, "0x0032")
        self.assertEqual(result.items[-1].address, "0x0063")

    async def test_filter_count_and_items_use_same_scope(self):
        result = await db.get_strings_page(
            self.db_path, "Target", "needle", page=2, size=10
        )

        self.assertEqual(result.total, 13)
        self.assertEqual(result.pages, 2)
        self.assertEqual(len(result.items), 3)
        self.assertTrue(all("needle" in item.value for item in result.items))

    async def test_legacy_query_still_returns_a_list(self):
        result = await db.get_strings(
            self.db_path, "Target", query=None, limit=7
        )

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 7)


if __name__ == "__main__":
    unittest.main()
