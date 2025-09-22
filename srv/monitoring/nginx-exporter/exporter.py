import logging
import os
import re
import time
from typing import Iterator

from prometheus_client import Counter, start_http_server

LOG_PATH = os.getenv("LOG_PATH", "/var/log/nginx/access.log")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "9113"))
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "0.5"))

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)

# Regex matches the configured nginx 'main' log format.
LOG_PATTERN = re.compile(
    r"(?P<remote_addr>\S+) - (?P<remote_user>\S+) "
    r"\[(?P<time_local>[^\]]+)\] \"(?P<method>\S+) "
    r"(?P<path>[^\s\"]+)(?: (?P<protocol>[^\"]+))?\" "
    r"(?P<status>\d{3}) (?P<body_bytes_sent>\S+) \"(?P<http_referer>[^\"]*)\" "
    r"\"(?P<http_user_agent>[^\"]*)\" \"(?P<xff>[^\"]*)\""
)

REQUEST_COUNT = Counter(
    "nginx_http_requests_total",
    "Total number of nginx HTTP requests.",
    ["status", "method", "path", "remote_addr"],
)
STATUS_CLASS_COUNT = Counter(
    "nginx_http_status_class_total",
    "Nginx HTTP responses grouped by status class.",
    ["class"],
)
FORBIDDEN_COUNT = Counter(
    "nginx_http_forbidden_total",
    "Number of nginx requests returning HTTP 403.",
    ["remote_addr", "path"],
)
SUCCESS_COUNT = Counter(
    "nginx_http_success_total",
    "Number of nginx requests returning HTTP 2xx.",
    ["remote_addr", "path"],
)


def tail_log(path: str) -> Iterator[str]:
    """Yield lines appended to *path*, waiting for the file to appear."""
    last_inode = None
    position = 0

    while True:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as log_file:
                logging.info("Tailing nginx log at %s", path)
                stat_info = os.fstat(log_file.fileno())
                if stat_info.st_ino == last_inode and position:
                    log_file.seek(position)
                else:
                    log_file.seek(0, os.SEEK_END)

                last_inode = stat_info.st_ino

                while True:
                    line = log_file.readline()
                    if not line:
                        position = log_file.tell()
                        time.sleep(POLL_INTERVAL_SECONDS)
                        continue
                    yield line
        except FileNotFoundError:
            logging.warning("Log file %s not found; retrying soon", path)
            time.sleep(2)
        except Exception as exc:  # pragma: no cover - defensive guard
            logging.exception("Error while tailing log: %s", exc)
            time.sleep(2)


def process_line(line: str) -> None:
    match = LOG_PATTERN.match(line.strip())
    if not match:
        logging.debug("Ignoring unmatched log line: %s", line.strip())
        return

    data = match.groupdict()
    status = data["status"]
    method = data["method"]
    remote_addr = data["remote_addr"]
    path = data["path"].split("?")[0]

    REQUEST_COUNT.labels(status=status, method=method, path=path, remote_addr=remote_addr).inc()
    STATUS_CLASS_COUNT.labels(f"{status[0]}xx").inc()

    if status.startswith("2"):
        SUCCESS_COUNT.labels(remote_addr=remote_addr, path=path).inc()
    if status == "403":
        FORBIDDEN_COUNT.labels(remote_addr=remote_addr, path=path).inc()


if __name__ == "__main__":
    logging.info("Starting nginx log exporter on port %s", LISTEN_PORT)
    start_http_server(LISTEN_PORT)
    for log_line in tail_log(LOG_PATH):
        process_line(log_line)
