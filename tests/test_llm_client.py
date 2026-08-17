from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src import llm_client


class DeepSeekThinkingModeTests(unittest.TestCase):
    def test_retry_create_disables_thinking_when_requested(self) -> None:
        # Given
        create = Mock(return_value=SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
            usage=None,
        ))
        client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
        )

        # When
        with (
            patch.object(llm_client, "is_cli_backend_enabled", return_value=False),
            patch.object(llm_client, "LLM_API_BASE_URL", "https://api.deepseek.com"),
            patch.object(llm_client, "_should_inject_user_id", return_value=False),
        ):
            llm_client._retry_create(
                client,
                "deepseek-v4-pro",
                [],
                disable_thinking=True,
            )

        # Then
        create.assert_called_once_with(
            model="deepseek-v4-pro",
            messages=[],
            extra_body={"thinking": {"type": "disabled"}},
        )

    def test_retry_create_keeps_default_request_when_not_requested(self) -> None:
        # Given
        create = Mock(return_value=SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
            usage=None,
        ))
        client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
        )

        # When
        with (
            patch.object(llm_client, "is_cli_backend_enabled", return_value=False),
            patch.object(llm_client, "LLM_API_BASE_URL", "https://api.deepseek.com"),
            patch.object(llm_client, "_should_inject_user_id", return_value=False),
        ):
            llm_client._retry_create(client, "deepseek-v4-pro", [])

        # Then
        create.assert_called_once_with(model="deepseek-v4-pro", messages=[])


if __name__ == "__main__":
    unittest.main()
