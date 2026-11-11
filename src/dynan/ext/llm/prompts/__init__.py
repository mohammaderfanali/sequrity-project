"""Prompt templates.

Templates live as Markdown files with YAML front matter rather than as string
literals scattered through application code, so they can be reviewed, diffed
and versioned like any other asset.

Every prompt dynAn sends is written in English, including system and developer
instructions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_FRONT_MATTER_RE = re.compile(r"^---\n(?P<meta>.*?)\n---\n(?P<body>.*)$", re.DOTALL)
_SECTION_RE = re.compile(r"^#\s+(System|User)\s*$", re.MULTILINE)

_PROMPT_DIR = Path(__file__).parent


class PromptError(RuntimeError):
    """A prompt template is missing or malformed."""


@dataclass(slots=True)
class Prompt:
    id: str
    version: int
    description: str
    system: str
    user_template: str

    def render(self, **values: object) -> tuple[str, str]:
        """Return ``(system, user)`` with placeholders filled.

        Missing keys raise rather than silently producing a prompt with a
        literal ``{placeholder}`` in it.
        """
        try:
            return self.system, self.user_template.format(**values)
        except KeyError as exc:
            raise PromptError(
                f"prompt '{self.id}' is missing a value for {exc}"
            ) from exc

    @property
    def traceable_id(self) -> str:
        return f"{self.id}@v{self.version}"


@lru_cache(maxsize=None)
def load_prompt(name: str) -> Prompt:
    path = _PROMPT_DIR / f"{name}.md"
    if not path.is_file():
        raise PromptError(f"prompt template not found: {name}")

    raw = path.read_text(encoding="utf-8")
    match = _FRONT_MATTER_RE.match(raw)
    if not match:
        raise PromptError(f"prompt '{name}' has no YAML front matter")

    import yaml

    meta = yaml.safe_load(match.group("meta")) or {}
    body = match.group("body")

    parts = _SECTION_RE.split(body)
    # split() yields: [preamble, "System", system_body, "User", user_body]
    sections: dict[str, str] = {}
    for index in range(1, len(parts) - 1, 2):
        sections[parts[index].strip().lower()] = parts[index + 1].strip()

    if "system" not in sections or "user" not in sections:
        raise PromptError(f"prompt '{name}' must define both '# System' and '# User'")

    return Prompt(
        id=str(meta.get("id", name)),
        version=int(meta.get("version", 1)),
        description=str(meta.get("description", "")),
        system=sections["system"],
        user_template=sections["user"],
    )


def available_prompts() -> list[str]:
    return sorted(p.stem for p in _PROMPT_DIR.glob("*.md"))
