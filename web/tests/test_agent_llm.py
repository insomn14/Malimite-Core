import json
import unittest
from unittest.mock import patch

from web.app import scanner
from web.app.agent import llm


async def _feed(*events):
    for e in events:
        yield e if isinstance(e, str) else json.dumps(e)


async def _collect(gen):
    return [e async for e in gen]


CONVO = [
    {"role": "user", "content": [{"type": "text", "text": "explain"}]},
    {"role": "assistant", "content": [{"type": "text", "text": "ok"},
                                      {"type": "tool_use", "id": "t1", "name": "get_source", "input": {"class_name": "a.B"}}]},
    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "CODE"}]},
]


class TranslateTests(unittest.TestCase):
    def test_to_openai_maps_tool_use_and_result(self):
        out = llm.to_openai("SYS", CONVO)
        self.assertEqual(out[0], {"role": "system", "content": "SYS"})
        self.assertEqual(out[2]["tool_calls"][0]["function"]["name"], "get_source")
        self.assertEqual(json.loads(out[2]["tool_calls"][0]["function"]["arguments"]), {"class_name": "a.B"})
        self.assertEqual(out[3], {"role": "tool", "tool_call_id": "t1", "content": "CODE"})


class ParserTests(unittest.IsolatedAsyncioTestCase):
    async def test_anthropic_text_and_fragmented_tool_use(self):
        evs = await _collect(llm.parse_anthropic(_feed(
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text"}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hi"}},
            {"type": "content_block_stop", "index": 0},
            {"type": "content_block_start", "index": 1,
             "content_block": {"type": "tool_use", "id": "t9", "name": "search_code"}},
            {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": '{"que'}},
            {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": 'ry":"DES"}'}},
            {"type": "content_block_stop", "index": 1},
            {"type": "message_delta", "delta": {"stop_reason": "tool_use"}},
        )))
        self.assertEqual(evs[0], {"type": "text", "text": "Hi"})
        self.assertEqual(evs[1], {"type": "tool_use", "id": "t9", "name": "search_code", "input": {"query": "DES"}})
        self.assertEqual(evs[2], {"type": "stop", "reason": "tool_use"})

    async def test_anthropic_error_event_raises(self):
        with self.assertRaises(llm.LlmError):
            await _collect(llm.parse_anthropic(_feed({"type": "error", "error": {"message": "overloaded"}})))

    async def test_openai_fragmented_tool_calls_and_done(self):
        def tc(args, **extra):
            return {"choices": [{"delta": {"tool_calls": [{"index": 0, **extra, "function": args}]}}]}
        evs = await _collect(llm.parse_openai(_feed(
            {"choices": [{"delta": {"content": "Hey"}}]},
            tc({"name": "list_classes", "arguments": '{"quer'}, id="c1"),
            tc({"arguments": 'y":"net"}'}),
            {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
            "[DONE]",
        )))
        self.assertEqual(evs[0], {"type": "text", "text": "Hey"})
        self.assertEqual(evs[1], {"type": "tool_use", "id": "c1", "name": "list_classes", "input": {"query": "net"}})
        self.assertEqual(evs[2], {"type": "stop", "reason": "tool_use"})

    async def test_openai_dict_arguments_and_bad_json(self):
        evs = await _collect(llm.parse_openai(_feed(
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "o", "function": {"name": "x", "arguments": {"a": 1}}}]}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 1, "id": "p", "function": {"name": "y", "arguments": "{bad"}}]}}]},
        )))
        self.assertEqual(evs[0]["input"], {"a": 1})
        self.assertIn("_invalid_json", evs[1]["input"])


class RequestBodyTests(unittest.IsolatedAsyncioTestCase):
    async def _body(self, provider, **kw):
        import httpx
        seen = {}

        def handler(req):
            seen.update(json.loads(req.content))
            return httpx.Response(200, text="data: [DONE]\n\n" if provider != "claude" else "")
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            cfg = llm.LlmCfg(provider, "m", "k", "http://x")
            async for _ in llm.chat_step(cfg, "S", CONVO, [{"name": "t", "description": "d", "schema": {}}], client=c, **kw):
                pass
        return seen

    async def test_tool_choice_none_only_when_tools_are_disallowed(self):
        self.assertNotIn("tool_choice", await self._body("openai"))
        self.assertNotIn("tool_choice", await self._body("claude"))
        self.assertEqual((await self._body("deepseek", allow_tools=False))["tool_choice"], "none")
        self.assertEqual((await self._body("claude", allow_tools=False))["tool_choice"], {"type": "none"})
        self.assertIn("tools", await self._body("claude", allow_tools=False))  # history has tool blocks: defs must stay


class ResolveTests(unittest.TestCase):
    def test_key_from_settings_and_scan_provider_model(self):
        with patch.object(scanner.settings, "anthropic_api_key", "K"), \
             patch.object(scanner.settings, "llm_provider", "none"):
            cfg = llm.resolve_llm("claude", "my-model")
        self.assertEqual((cfg.provider, cfg.model, cfg.api_key), ("claude", "my-model", "K"))

    def test_override_provider_does_not_inherit_foreign_model(self):
        with patch.object(scanner.settings, "openai_api_key", "O"), \
             patch.object(scanner.settings, "llm_provider", "none"):
            cfg = llm.resolve_llm("claude", "claude-x", provider="openai")
        self.assertEqual(cfg.model, "gpt-4o-mini")

    def test_missing_key_and_unknown_provider(self):
        with patch.object(scanner.settings, "deepseek_api_key", ""), \
             patch.object(scanner.settings, "llm_provider", "none"):
            with self.assertRaises(llm.LlmError):
                llm.resolve_llm("deepseek", "")
            with self.assertRaises(llm.LlmError):
                llm.resolve_llm("none", "", provider="evil")

    def test_ollama_needs_no_key(self):
        cfg = llm.resolve_llm("ollama", "")
        self.assertEqual((cfg.provider, cfg.api_key), ("ollama", ""))


if __name__ == "__main__":
    unittest.main()
