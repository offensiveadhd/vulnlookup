"""HTTP with pacing and backoff, stdlib only.

* Parameters are always URL-encoded by ``urllib.parse.urlencode``; nothing is spliced into a
  URL by hand and nothing goes through a shell.
* The NVD allows 5 requests per rolling 30 s without a key and 50 with one. The pacer keeps
  the request stamps in a small file in the cache directory, so several invocations on the
  same machine (the limit is per IP) share one window instead of tripping it.
* 403 / 429 / 503 back off and retry (the NVD answers 403 to a rate-limited client).
* The API key travels in the ``apiKey`` header only, to ``services.nvd.nist.gov`` only, and is
  never logged.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

NVD_HOST = "services.nvd.nist.gov"
USER_AGENT = "vulnlookup/1.0 (+https://github.com/offensiveadhd/vulnlookup)"

NVD_WINDOW_S = 30.0
NVD_PUBLIC_PER_WINDOW = 5
NVD_KEYED_PER_WINDOW = 50

Fetcher = Callable[[str, dict[str, str]], tuple[int, bytes]]


class HttpError(Exception):
    def __init__(self, status: int, url: str, body: str = ""):
        self.status = status
        self.url = url
        self.body = body
        super().__init__(f"HTTP {status} from {urllib.parse.urlsplit(url).netloc}")


class OfflineError(Exception):
    """Raised when --offline is set and the cache has no answer."""


def build_url(base: str, params: dict[str, Any]) -> str:
    items = [(k, str(v)) for k, v in params.items() if v is not None and v != ""]
    return base + ("?" + urllib.parse.urlencode(items, safe=":*") if items else "")


def _default_fetch(url: str, headers: dict[str, str]) -> tuple[int, bytes]:
    if not url.startswith("https://"):
        raise ValueError(f"refusing a non-https URL: {url[:40]}")
    req = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 (https enforced above)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() if e.fp else b""


class Pacer:
    """A rolling-window limiter whose stamps persist on disk."""

    def __init__(
        self,
        path: Path,
        per_window: int,
        window_s: float = NVD_WINDOW_S,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.time,
    ):
        self.path = path
        self.per_window = per_window
        self.window_s = window_s
        self._sleep = sleep
        self._now = now

    def _load(self) -> list[float]:
        try:
            return [float(x) for x in json.loads(self.path.read_text("utf-8"))]
        except (OSError, ValueError):
            return []

    def _save(self, stamps: list[float]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(stamps), "utf-8")
        except OSError:
            pass

    def wait(self) -> float:
        """Block until a request may go; return how long it waited."""
        waited = 0.0
        while True:
            now = self._now()
            stamps = [s for s in self._load() if now - s < self.window_s]
            if len(stamps) < self.per_window:
                stamps.append(now)
                self._save(stamps)
                return waited
            delay = self.window_s - (now - stamps[0]) + 0.05
            self._sleep(delay)
            waited += delay


class Client:
    def __init__(
        self,
        cache_root: Path,
        api_key: str | None = None,
        offline: bool = False,
        fetch: Fetcher | None = None,
        verbose: bool = False,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.api_key = api_key
        self.offline = offline
        self.fetch: Fetcher = fetch or _default_fetch
        self.verbose = verbose
        self._sleep = sleep
        per = NVD_KEYED_PER_WINDOW if api_key else NVD_PUBLIC_PER_WINDOW
        self.pacer = Pacer(cache_root / ("nvd-window-keyed.json" if api_key else "nvd-window.json"), per, sleep=sleep)
        self.requests = 0
        self.waited = 0.0

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, file=sys.stderr)

    def get_json(self, url: str, retries: int = 4) -> Any:
        if self.offline:
            raise OfflineError(url)
        host = urllib.parse.urlsplit(url).netloc
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        is_nvd = host == NVD_HOST
        if is_nvd and self.api_key:
            headers["apiKey"] = self.api_key
        delay = 6.0
        last: HttpError | None = None
        for attempt in range(retries + 1):
            if is_nvd:
                self.waited += self.pacer.wait()
            self.requests += 1
            self.log(f"GET {url}")
            status, body = self.fetch(url, headers)
            if status == 200:
                try:
                    return json.loads(body.decode("utf-8"))
                except ValueError as e:
                    raise HttpError(status, url, f"invalid JSON: {e}") from None
            if status in (403, 429, 503) and attempt < retries:
                self.log(f"  {status}; retry in {delay:.0f}s")
                self._sleep(delay)
                delay = min(delay * 2, 60)
                last = HttpError(status, url)
                continue
            raise HttpError(status, url, body[:200].decode("utf-8", "replace"))
        raise last or HttpError(0, url)


def have_network_override() -> bool:
    return os.environ.get("VULNLOOKUP_OFFLINE", "") not in ("", "0", "false")
