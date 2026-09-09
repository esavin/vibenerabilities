"""Config resolution. Precedence: CLI flags > environment > config.json > defaults."""

import json
import os

DEFAULT_BASE_URL = "https://api.openai.com/v1"

LLM_DEFAULTS = {
    "base_url": DEFAULT_BASE_URL,
    "api_key_env": "VULN_API_KEY",
    "model": "",
    "temperature": None,
    "max_tokens": 0,
    "max_steps": 24,
    "max_steps_initial": 0,
    "max_steps_cap": 48,
    "request_timeout_seconds": 180,
    "retries": 5,
    # one "[llm] waiting for <model>: Ns" line per N seconds an in-flight
    # request runs (0 disables) - long reasoning round-trips otherwise look
    # exactly like a hang
    "heartbeat_seconds": 60,
    "extra_body": {},
    "log_transcript": True,
}

# Context-budget knobs. Resolution order: defaults <- profile preset <-
# explicit `limits` keys. The "default" profile reproduces the historical
# hardcoded constants exactly, so existing configs behave identically.
LIMIT_DEFAULTS = {
    "profile": "default",
    # per tool result kept in the session history (agent.py append-time cap)
    "tool_result_chars": 100_000,
    # per-tool output caps inside ToolSet (tools.py)
    "git_output_chars": 150_000,
    "read_file_chars": 80_000,
    "list_dir_chars": 40_000,
    # first-user-message injection caps (prompt.py)
    "diffstat_chars": 30_000,
    # full-diff injection into the first user message: the diff is injected
    # only when it fits this cap WHOLE (never truncated); 0 disables
    "diff_chars": 16_000,
    "name_status_chars": 20_000,
    "tree_digest_chars": 8_000,
    "conventions_chars": 12_000,
    "records_overview_chars": 6_000,
    # history compaction (agent.py): 0 disables. When a request reports
    # prompt_tokens >= compact_threshold_tokens, older tool results are
    # shrunk in place to compact_result_chars; the last compact_keep_groups
    # assistant+tool groups always stay verbatim.
    "compact_threshold_tokens": 0,
    "compact_keep_groups": 4,
    "compact_result_chars": 2_000,
    # path-hygiene batching (hygiene.py): records per repair session; a
    # worklist bigger than this is split into fresh sessions so combined
    # write_record payloads never exceed the context window. 0 = single
    # session (old behavior). The deterministic rename pre-pass itself is
    # always on.
    "hygiene_batch_records": 5,
}

# Preset for ~32k-context models (self-hosted/desktop gateways): tight caps
# on every injected blob plus compaction with headroom for the reply.
LIMIT_PROFILES = {
    "default": {},
    "small": {
        "tool_result_chars": 24_000,
        "git_output_chars": 30_000,
        "read_file_chars": 24_000,
        "list_dir_chars": 16_000,
        "diffstat_chars": 10_000,
        "diff_chars": 12_000,
        "name_status_chars": 8_000,
        "tree_digest_chars": 6_000,
        "conventions_chars": 8_000,
        "records_overview_chars": 3_000,
        "compact_threshold_tokens": 20_000,
        "compact_keep_groups": 3,
        "compact_result_chars": 1_500,
    },
}


# Snapshot bootstrap (run.sh --snapshot): record the CURRENT tree instead
# of replaying history, then replay only commits newer than the snapshot.
# planner_model: model for the one-shot module-planner request ("" = llm.model).
# max_modules: planner output cap - more modules than that merge into "misc".
# max_steps: per-module session step budget (0 = llm.max_steps_initial).
SNAPSHOT_DEFAULTS = {
    "planner_model": "",
    "max_modules": 40,
    "max_steps": 0,
}


# Triage fast-path (two-stage cascade, see vuln_agent/triage.py). Off by
# default: the classic behavior is one full session per commit.
TRIAGE_DEFAULTS = {
    "enabled": False,
    # "" = llm.model; point at a cheaper/faster model if the endpoint has one
    "model": "",
    "diff_chars": 16_000,
    "message_chars": 2_000,
    "name_status_chars": 6_000,
    # when EVERY changed file matches one of these globs, skip with no LLM
    # call at all (e.g. ["docs/**", "**/*_test.go", "*.md", "assets/**"])
    "irrelevant_globs": [],
    # background triage prefetch (run.sh starts vuln_agent.prefetch when > 0):
    # keep triage decisions cached AHEAD of the walk so the cascade decision
    # costs the main invocation zero LLM round-trips
    "prefetch_ahead": 0,
    "prefetch_interval_seconds": 5,
    "prefetch_max_idle_seconds": 900,
}


class ConfigError(Exception):
    """Fatal misconfiguration — the agent cannot start."""


def load_config(path):
    """Load config.json (the pipeline's config) as a dict; {} if absent."""
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError("cannot read config %s: %s" % (path, exc))
    if not isinstance(data, dict):
        raise ConfigError("config %s must be a JSON object" % path)
    return data


def resolve_llm(config, cli_model=None, cli_max_steps=None):
    """Merge llm settings from config.json, environment, and CLI overrides."""
    section = config.get("llm")
    if not isinstance(section, dict):
        section = {}
    merged = dict(LLM_DEFAULTS)
    merged.update({k: v for k, v in section.items() if v not in (None, "")})

    base_url = os.environ.get("VULN_BASE_URL") or merged["base_url"]
    model = cli_model or os.environ.get("VULN_MODEL") or merged["model"]
    if not model:
        raise ConfigError(
            "no model configured - set llm.model in config.json, export VULN_MODEL,"
            " or pass --model"
        )

    api_key = os.environ.get("VULN_API_KEY", "")
    if not api_key and merged["api_key_env"]:
        api_key = os.environ.get(merged["api_key_env"], "")
    if not api_key:
        api_key = os.environ.get("OPENAI_API_KEY", "")

    try:
        max_steps = int(cli_max_steps or merged["max_steps"])
        max_steps_initial = int(merged["max_steps_initial"] or 0)
        max_steps_cap = int(merged["max_steps_cap"] or 48)
        timeout = int(merged["request_timeout_seconds"])
        retries = int(merged["retries"])
        max_tokens = int(merged["max_tokens"] or 0)
        heartbeat = max(0, int(merged["heartbeat_seconds"] or 0))
    except (TypeError, ValueError):
        raise ConfigError("llm numeric settings must be integers")

    temperature = merged["temperature"]
    if temperature is not None:
        try:
            temperature = float(temperature)
        except (TypeError, ValueError):
            raise ConfigError("llm.temperature must be a number or null")

    extra_body = merged["extra_body"]
    if extra_body is None:
        extra_body = {}
    if not isinstance(extra_body, dict):
        raise ConfigError("llm.extra_body must be a JSON object")

    log_transcript = merged["log_transcript"]
    if not isinstance(log_transcript, bool):
        log_transcript = str(log_transcript).strip().lower() \
            not in ("false", "0", "no", "off", "")

    return {
        "base_url": base_url.rstrip("/"),
        "model": model,
        "api_key": api_key,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "max_steps": max(1, max_steps),
        "max_steps_initial": max(0, max_steps_initial),
        "max_steps_cap": max(1, max_steps_cap),
        "timeout": max(30, timeout),
        "retries": max(0, retries),
        "heartbeat_seconds": heartbeat,
        "extra_body": extra_body,
        "log_transcript": log_transcript,
    }


def resolve_limits(config):
    """Merge the `limits` config section into a flat dict of ints (+ profile).

    `profile: "small"` bundles tighter caps and enables history compaction
    for ~32k-token context models; any explicit key under `limits` overrides
    the preset, so e.g. {"profile": "small", "compact_threshold_tokens": 16000}
    works. With no `limits` section every value matches the historical
    hardcoded constants and compaction is off.
    """
    section = config.get("limits")
    if not isinstance(section, dict):
        section = {}
    profile = str(section.get("profile") or "default").strip().lower() or "default"
    preset = LIMIT_PROFILES.get(profile)
    if preset is None:
        raise ConfigError("limits.profile must be one of: %s"
                          % ", ".join(sorted(LIMIT_PROFILES)))
    merged = dict(LIMIT_DEFAULTS)
    merged.update(preset)
    for key in LIMIT_DEFAULTS:
        if key == "profile":
            continue
        if key in section and section[key] not in (None, ""):
            merged[key] = section[key]
    resolved = {"profile": profile}
    for key, value in merged.items():
        if key == "profile":
            continue
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise ConfigError("limits.%s must be an integer" % key)
        floor = 200 if key.endswith("_chars") else 0
        resolved[key] = max(floor, number)
    return resolved


def resolve_snapshot(config, llm):
    """Merge the `snapshot` section over the resolved llm settings."""
    section = config.get("snapshot")
    if not isinstance(section, dict):
        section = {}
    merged = dict(SNAPSHOT_DEFAULTS)
    merged.update({k: v for k, v in section.items() if v not in (None, "")})
    try:
        max_modules = max(1, int(merged["max_modules"]))
        max_steps = max(0, int(merged["max_steps"]))
    except (TypeError, ValueError):
        raise ConfigError("snapshot numeric settings must be integers")
    return {
        "planner_model": str(merged["planner_model"] or llm["model"]),
        "max_modules": max_modules,
        "max_steps": max_steps,
    }


def resolve_triage(config, llm):
    """Merge the `triage` section (fast-path cascade) over the llm settings."""
    section = config.get("triage")
    if not isinstance(section, dict):
        section = {}
    merged = dict(TRIAGE_DEFAULTS)
    merged.update({k: v for k, v in section.items() if v not in (None, "")})
    enabled = merged["enabled"]
    if not isinstance(enabled, bool):
        enabled = str(enabled).strip().lower() in ("true", "1", "yes", "on")
    numbers = {}
    for key in ("diff_chars", "message_chars", "name_status_chars",
                "prefetch_ahead", "prefetch_interval_seconds",
                "prefetch_max_idle_seconds"):
        try:
            numbers[key] = max(0, int(merged[key]))
        except (TypeError, ValueError):
            raise ConfigError("triage.%s must be an integer" % key)
    globs = merged["irrelevant_globs"]
    if not isinstance(globs, (list, tuple)):
        raise ConfigError("triage.irrelevant_globs must be a list of globs")
    resolved = {
        "enabled": enabled,
        "model": str(merged["model"] or llm["model"]),
        "irrelevant_globs": [str(g) for g in globs],
    }
    resolved.update(numbers)
    return resolved
