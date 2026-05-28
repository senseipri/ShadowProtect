import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


@dataclass
class RuleDefinition:
    id: str
    name: str
    tier: int
    weight: int
    pattern: str
    flags: list[str]
    applies_to: list[str] | None
    description: str
    source_file: str
    regex: re.Pattern[str]


@dataclass
class RuleMatch:
    rule_id: str
    name: str
    tier: int
    weight: int
    description: str
    matched_text: str
    span: tuple[int, int]
    source_file: str


class _RulesHotReloadHandler(FileSystemEventHandler):
    def __init__(self, engine: "RulesEngine") -> None:
        self.engine = engine

    def on_created(self, event) -> None:  # type: ignore[override]
        self._try_reload(event.src_path)

    def on_modified(self, event) -> None:  # type: ignore[override]
        self._try_reload(event.src_path)

    def on_deleted(self, event) -> None:  # type: ignore[override]
        self._try_reload(event.src_path)

    def on_moved(self, event) -> None:  # type: ignore[override]
        self._try_reload(event.dest_path)

    def _try_reload(self, changed_path: str) -> None:
        path = Path(changed_path)
        if path.suffix.lower() not in {".yaml", ".yml"}:
            return
        self.engine._reload_from_watchdog()


class RulesEngine:
    FLAG_MAP: dict[str, int] = {
        "IGNORECASE": re.IGNORECASE,
        "MULTILINE": re.MULTILINE,
        "DOTALL": re.DOTALL,
        "VERBOSE": re.VERBOSE,
        "ASCII": re.ASCII,
    }

    def __init__(self, rules_directory: str | Path | None = None) -> None:
        base = Path(__file__).resolve().parents[1]
        self.rules_directory = Path(rules_directory) if rules_directory else (base / "rules")
        self.rules: list[RuleDefinition] = []
        self._observer: Observer | None = None
        self._lock = threading.RLock()

    def load_rules(self, directory: str | Path | None = None) -> list[RuleDefinition]:
        with self._lock:
            if directory is not None:
                self.rules_directory = Path(directory)
            self.rules_directory.mkdir(parents=True, exist_ok=True)

            loaded: list[RuleDefinition] = []
            files = sorted(
                [
                    *self.rules_directory.glob("*.yaml"),
                    *self.rules_directory.glob("*.yml"),
                ]
            )
            for file_path in files:
                data = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
                items = data.get("rules", data if isinstance(data, list) else [])
                if not isinstance(items, list):
                    continue

                for idx, item in enumerate(items):
                    if not isinstance(item, dict):
                        continue
                    pattern = str(item.get("pattern", "")).strip()
                    if not pattern:
                        continue

                    rule_id = str(item.get("id") or f"{file_path.stem}-{idx}")
                    name = str(item.get("name") or rule_id)
                    tier = int(item.get("tier", 0) or 0)
                    weight = int(item.get("weight", 0) or 0)
                    flags_names = self._normalize_flags(item.get("flags"))
                    applies_to = self._normalize_applies_to(item.get("applies_to"))
                    description = str(item.get("description") or "")

                    regex = re.compile(pattern, flags=self._resolve_re_flags(flags_names))
                    loaded.append(
                        RuleDefinition(
                            id=rule_id,
                            name=name,
                            tier=tier,
                            weight=weight,
                            pattern=pattern,
                            flags=flags_names,
                            applies_to=applies_to,
                            description=description,
                            source_file=file_path.name,
                            regex=regex,
                        )
                    )

            self.rules = loaded
            return list(self.rules)

    def hot_reload(self) -> None:
        with self._lock:
            if self._observer is not None and self._observer.is_alive():
                return
            self.rules_directory.mkdir(parents=True, exist_ok=True)
            handler = _RulesHotReloadHandler(self)
            observer = Observer()
            observer.schedule(handler, str(self.rules_directory), recursive=True)
            observer.start()
            self._observer = observer

    def stop_hot_reload(self) -> None:
        with self._lock:
            if self._observer is None:
                return
            self._observer.stop()
            self._observer.join(timeout=2)
            self._observer = None

    def _reload_from_watchdog(self) -> None:
        try:
            self.load_rules()
        except Exception:
            # Never crash the watcher thread if a malformed rule is saved.
            pass

    def match(self, text: str, event_type: str | None = None) -> list[RuleMatch]:
        payload = text if isinstance(text, str) else str(text)
        requested_type = str(event_type).upper() if event_type else None

        with self._lock:
            rules_snapshot = list(self.rules)

        matches: list[RuleMatch] = []
        for rule in rules_snapshot:
            if requested_type and rule.applies_to and requested_type not in rule.applies_to:
                continue
            for hit in rule.regex.finditer(payload):
                matches.append(
                    RuleMatch(
                        rule_id=rule.id,
                        name=rule.name,
                        tier=rule.tier,
                        weight=rule.weight,
                        description=rule.description,
                        matched_text=hit.group(0),
                        span=hit.span(),
                        source_file=rule.source_file,
                    )
                )
        return matches

    def _normalize_flags(self, raw_flags: Any) -> list[str]:
        if raw_flags is None:
            return []
        if isinstance(raw_flags, str):
            tokens = [tok.strip().upper() for tok in raw_flags.split("|") if tok.strip()]
            return [tok for tok in tokens if tok in self.FLAG_MAP]
        if isinstance(raw_flags, list):
            tokens = [str(tok).strip().upper() for tok in raw_flags if str(tok).strip()]
            return [tok for tok in tokens if tok in self.FLAG_MAP]
        return []

    def _normalize_applies_to(self, raw: Any) -> list[str] | None:
        if raw is None:
            return None
        if isinstance(raw, str):
            return [raw.strip().upper()] if raw.strip() else None
        if isinstance(raw, list):
            values = [str(v).strip().upper() for v in raw if str(v).strip()]
            return values or None
        return None

    def _resolve_re_flags(self, flags: list[str]) -> int:
        value = 0
        for name in flags:
            value |= self.FLAG_MAP.get(name, 0)
        return value
