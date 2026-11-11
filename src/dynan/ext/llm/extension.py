"""LLM extension.

Produces advisory text that is stored alongside the run and clearly labelled
as unverified. It cannot change the verdict: the decision engine reads
findings and comparisons, never ``run.extension_results``.

Source code is only sent to an external provider when
``extensions.llm.allow_source_upload`` is explicitly true. With the default
settings the extension sends metadata about findings (error type, detection
mechanism, frame locations) and nothing else.
"""

from __future__ import annotations

import json
from typing import Any

from ...config.schema import DynanConfig
from ...domain.enums import Confidence, DependencyStatus, Severity
from ...domain.models import Diagnostic
from ..registry import ExtensionContext
from .prompts import PromptError, load_prompt
from .provider import LlmError, LlmProvider

#: Cap on how many findings get an explanation, so a noisy run cannot trigger
#: an unbounded number of paid requests.
_MAX_EXPLANATIONS = 5


class LlmExtension:
    name = "llm"
    description = "Explains findings and summarises the diff using a language model."

    # -- diagnostics ----------------------------------------------------

    def diagnose(self, config: DynanConfig) -> list[Diagnostic]:
        llm = config.extensions.llm
        if not llm.enabled:
            return [
                Diagnostic(
                    name="extension: llm",
                    status=DependencyStatus.NOT_REQUIRED,
                    required=False,
                    detail="listed but disabled; no provider will be contacted",
                    category="extensions",
                )
            ]

        diagnostics: list[Diagnostic] = []
        try:
            import httpx  # noqa: F401
        except ImportError:
            diagnostics.append(
                Diagnostic(
                    name="extension: llm (httpx)",
                    status=DependencyStatus.MISSING,
                    required=True,
                    detail="the LLM extension is enabled but httpx is not installed",
                    remediation="pip install -e '.[llm]'",
                    category="extensions",
                )
            )

        provider = LlmProvider(llm)
        if provider.missing_credentials():
            diagnostics.append(
                Diagnostic(
                    name="extension: llm (credentials)",
                    status=DependencyStatus.MISCONFIGURED,
                    required=True,
                    detail=f"no API key found in ${llm.api_key_env}",
                    remediation=(
                        f"export {llm.api_key_env}=... before running, "
                        "or disable extensions.llm"
                    ),
                    category="extensions",
                )
            )

        try:
            base = provider.base_url
        except LlmError as exc:
            diagnostics.append(
                Diagnostic(
                    name="extension: llm (endpoint)",
                    status=DependencyStatus.MISCONFIGURED,
                    required=True,
                    detail=str(exc),
                    remediation="set extensions.llm.base_url",
                    category="extensions",
                )
            )
        else:
            diagnostics.append(
                Diagnostic(
                    name="extension: llm",
                    status=DependencyStatus.READY if not diagnostics else DependencyStatus.MISCONFIGURED,
                    required=False,
                    detail=(
                        f"provider={llm.provider} model={llm.model} endpoint={base}; "
                        f"source upload {'allowed' if llm.allow_source_upload else 'disabled'}. "
                        "Readiness here does not prove the endpoint answers - use the "
                        "connection test for that."
                    ),
                    category="extensions",
                )
            )

        return diagnostics

    # -- execution ------------------------------------------------------

    def run(self, context: ExtensionContext) -> dict[str, Any]:
        llm = context.config.extensions.llm
        if not llm.enabled:
            return {"status": "disabled"}

        provider = LlmProvider(llm)
        results: dict[str, Any] = {
            "status": "ok",
            "model": llm.model,
            "disclaimer": (
                "LLM output is advisory and unverified. It does not affect the "
                "validation verdict, which is produced by deterministic analysis."
            ),
            "explanations": [],
            "errors": [],
        }

        run = context.run

        # -- diff summary -----------------------------------------------
        if context.raw_diff and llm.allow_source_upload:
            try:
                prompt = load_prompt("summarize_diff")
                system, user = prompt.render(
                    diff=context.raw_diff[: llm.max_prompt_chars]
                )
                response = provider.complete(system, user, prompt_id=prompt.traceable_id)
                results["diff_summary"] = {
                    "prompt": prompt.traceable_id,
                    "text": response.text,
                    "verified": False,
                }
            except (LlmError, PromptError) as exc:
                results["errors"].append(f"diff summary failed: {exc}")
        elif context.raw_diff:
            results["diff_summary"] = {
                "skipped": (
                    "extensions.llm.allow_source_upload is false, so the diff was "
                    "not sent to an external provider"
                )
            }

        # -- finding explanations ---------------------------------------
        interesting = [
            f
            for f in run.findings
            if f.confidence == Confidence.CONFIRMED
            and f.severity in (Severity.MEMORY_SAFETY, Severity.UNDEFINED_BEHAVIOR)
        ][:_MAX_EXPLANATIONS]

        for finding in interesting:
            try:
                prompt = load_prompt("explain_finding")
                frames = "\n".join(
                    f"  #{fr.index} {fr.function or '<unknown>'} "
                    f"{fr.file or '<unresolved>'}:{fr.line or '?'}"
                    for fr in finding.frames[:12]
                ) or "  (none resolved)"
                system, user = prompt.render(
                    error_type=finding.signature.error_type.value,
                    detection=finding.signature.detection.value,
                    message=finding.message,
                    profile=finding.profile.value,
                    version=finding.version.value,
                    test_id=finding.test_id,
                    frames=frames,
                    details=json.dumps(finding.details, indent=2)[: llm.max_prompt_chars],
                )
                response = provider.complete(system, user, prompt_id=prompt.traceable_id)
                results["explanations"].append(
                    {
                        "finding_id": finding.finding_id,
                        "prompt": prompt.traceable_id,
                        "text": response.text,
                        "verified": False,
                    }
                )
            except (LlmError, PromptError) as exc:
                results["errors"].append(
                    f"explanation for {finding.finding_id} failed: {exc}"
                )

        if results["errors"] and not results["explanations"]:
            results["status"] = "failed"
        return results
