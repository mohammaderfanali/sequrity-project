"""LLM provider abstraction.

Only the chat-completions shape is implemented, because that is the one
endpoint every OpenAI-compatible service genuinely supports. dynAn does not
assume a provider offers responses, assistants or embeddings APIs just because
it accepts an OpenAI-style base URL.

Credentials are read from the environment variable named in configuration and
are never stored in configuration files, never logged, and never echoed back
to the UI.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from ...config.schema import LlmConfig


class LlmError(RuntimeError):
    """The provider could not be reached, or refused the request."""


@dataclass(slots=True)
class LlmResponse:
    text: str
    model: str
    prompt_id: str
    duration_s: float
    #: Token accounting when the provider reports it.
    usage: dict[str, int] | None = None


class LlmProvider:
    """Minimal chat client over an OpenAI-compatible endpoint."""

    def __init__(self, config: LlmConfig) -> None:
        self.config = config

    # -- configuration --------------------------------------------------

    @property
    def base_url(self) -> str:
        if self.config.base_url:
            return self.config.base_url.rstrip("/")
        if self.config.provider == "openai":
            return "https://api.openai.com/v1"
        raise LlmError(
            f"provider '{self.config.provider}' requires extensions.llm.base_url"
        )

    def api_key(self) -> str | None:
        """Read the key from the environment, if present."""
        return os.environ.get(self.config.api_key_env) or None

    def missing_credentials(self) -> bool:
        # A local model served on localhost commonly needs no key.
        return self.config.provider != "local" and not self.api_key()

    # -- requests -------------------------------------------------------

    def complete(self, system: str, user: str, *, prompt_id: str = "") -> LlmResponse:
        """Send one chat completion request.

        Retries only on transport errors and 5xx/429 responses; a 4xx is a
        configuration problem and retrying it just wastes time.
        """
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - guarded by the doctor
            raise LlmError(
                "the LLM extension needs httpx; install with: pip install -e '.[llm]'"
            ) from exc

        if self.missing_credentials():
            raise LlmError(
                f"no API key found in ${self.config.api_key_env}; "
                "export it or disable the LLM extension"
            )

        headers = {"Content-Type": "application/json"}
        key = self.api_key()
        if key:
            headers["Authorization"] = f"Bearer {key}"

        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
        }

        url = f"{self.base_url}/chat/completions"
        started = time.monotonic()
        last_error: Exception | None = None

        for attempt in range(self.config.max_retries + 1):
            try:
                response = httpx.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.config.timeout_s,
                )
            except Exception as exc:  # network-level failure
                last_error = exc
                if attempt < self.config.max_retries:
                    time.sleep(min(2**attempt, 8))
                    continue
                raise LlmError(f"could not reach {url}: {exc}") from exc

            if response.status_code in (429, 500, 502, 503, 504):
                last_error = LlmError(
                    f"provider returned {response.status_code}: {response.text[:200]}"
                )
                if attempt < self.config.max_retries:
                    time.sleep(min(2**attempt, 8))
                    continue
                raise last_error

            if response.status_code >= 400:
                raise LlmError(
                    f"provider rejected the request ({response.status_code}): "
                    f"{response.text[:300]}"
                )

            try:
                body = response.json()
                text = body["choices"][0]["message"]["content"]
            except (ValueError, KeyError, IndexError) as exc:
                raise LlmError(
                    f"unexpected response shape from {url}: {response.text[:200]}"
                ) from exc

            return LlmResponse(
                text=text,
                model=body.get("model", self.config.model),
                prompt_id=prompt_id,
                duration_s=time.monotonic() - started,
                usage=body.get("usage"),
            )

        raise LlmError(str(last_error) if last_error else "request failed")

    def test_connection(self) -> tuple[bool, str]:
        """Verify the provider really answers a supported request.

        The UI must not display a healthy connection until this succeeds - a
        reachable host is not the same as a working model endpoint.
        """
        try:
            response = self.complete(
                "You are a connection test. Reply with exactly: OK",
                "Reply with exactly: OK",
                prompt_id="connection_test",
            )
        except LlmError as exc:
            return False, str(exc)
        return True, f"{response.model} responded in {response.duration_s:.2f}s"
