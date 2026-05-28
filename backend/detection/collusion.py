from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone


class CollusionDetector:
    def __init__(self, window: int = 60, threshold: int = 10) -> None:
        self.window = max(1, int(window))
        self.threshold = max(1, int(threshold))
        self._pair_events: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def _prune(self, pair: tuple[str, str], now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.window)
        q = self._pair_events[pair]
        while q and q[0] < cutoff:
            q.popleft()

    def record(self, src: str, dst: str) -> bool:
        pair = (str(src), str(dst))
        now = self._now()
        self._prune(pair, now)
        self._pair_events[pair].append(now)
        return len(self._pair_events[pair]) > self.threshold

    def get_pair_frequency(self, src: str, dst: str) -> int:
        pair = (str(src), str(dst))
        now = self._now()
        self._prune(pair, now)
        return len(self._pair_events[pair])

    def get_suspicious_pairs(self) -> list[dict]:
        now = self._now()
        min_count = max(1, int(self.threshold * 0.5))
        suspicious: list[dict] = []
        for pair in list(self._pair_events.keys()):
            self._prune(pair, now)
            count = len(self._pair_events[pair])
            if count >= min_count:
                suspicious.append(
                    {
                        "src": pair[0],
                        "dst": pair[1],
                        "count": count,
                        "window_seconds": self.window,
                        "threshold": self.threshold,
                    }
                )
        suspicious.sort(key=lambda x: x["count"], reverse=True)
        return suspicious
