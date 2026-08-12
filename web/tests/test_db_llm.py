import sqlite3
import tempfile
import unittest
from pathlib import Path

from web.app import db


class LlmPaginationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        handle = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        handle.close()
        self.db_path = handle.name
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE LlmFindings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    FunctionName TEXT,
                    ClassName TEXT,
                    ExecutableName TEXT NOT NULL,
                    Mode TEXT,
                    Finding TEXT,
                    CacheKey TEXT,
                    CreatedAt INTEGER
                )"""
            )
            conn.executemany(
                """INSERT INTO LlmFindings
                   (FunctionName, ClassName, ExecutableName, Mode, Finding)
                   VALUES (?, ?, ?, ?, ?)""",
                [
                    (
                        f"fn_{index:03d}",
                        f"pkg.Class{index % 5}",
                        "Target",
                        "OFFENSIVE" if index % 2 == 0 else "SUMMARIZE",
                        (
                            '{"offensive_targets":[]}'
                            if index % 10
                            else '{"needle": true, "offensive_targets":[]}'
                        ),
                    )
                    for index in range(125)
                ],
            )
            conn.execute(
                """INSERT INTO LlmFindings
                   (FunctionName, ClassName, ExecutableName, Mode, Finding)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    "other_fn",
                    "other.Class",
                    "Other",
                    "OFFENSIVE",
                    '{"needle": true}',
                ),
            )

    def tearDown(self):
        Path(self.db_path).unlink(missing_ok=True)

    async def test_returns_stable_page_and_total(self):
        result = await db.get_llm_findings_page(
            self.db_path, "Target", None, page=2, size=50
        )

        self.assertEqual(result.total, 125)
        self.assertEqual(result.page, 2)
        self.assertEqual(result.size, 50)
        self.assertEqual(result.pages, 3)
        self.assertEqual(len(result.items), 50)
        self.assertEqual(result.items[0].function_name, "fn_050")
        self.assertEqual(result.items[-1].function_name, "fn_099")

    async def test_filter_count_and_items_use_same_scope(self):
        result = await db.get_llm_findings_page(
            self.db_path, "Target", "needle", page=2, size=10
        )

        self.assertEqual(result.total, 13)
        self.assertEqual(result.pages, 2)
        self.assertEqual(len(result.items), 3)
        self.assertTrue(all("needle" in item.finding for item in result.items))

    async def test_sort_function_name_is_whitelisted(self):
        result = await db.get_llm_findings_page(
            self.db_path,
            "Target",
            None,
            page=1,
            size=10,
            sort="function",
            direction="desc",
        )

        names = [item.function_name for item in result.items]
        self.assertEqual(names, sorted(names, reverse=True))
        self.assertEqual(result.items[0].function_name, "fn_124")

    async def test_unknown_sort_falls_back_to_rowid(self):
        result = await db.get_llm_findings_page(
            self.db_path,
            "Target",
            None,
            page=1,
            size=10,
            sort="status;DROP TABLE LlmFindings",
            direction="desc",
        )

        self.assertEqual(result.size, 10)
        self.assertEqual(
            [item.function_name for item in result.items],
            [f"fn_{index:03d}" for index in range(10)],
        )

    async def test_legacy_query_still_returns_a_list(self):
        result = await db.get_llm_findings(self.db_path, "Target")

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 125)
        self.assertEqual(result[0].function_name, "fn_000")
        self.assertEqual(result[-1].function_name, "fn_124")


if __name__ == "__main__":
    unittest.main()
