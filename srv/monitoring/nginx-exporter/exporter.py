import logging
import os
import re
import time
from ipaddress import ip_address
from typing import Dict, Iterator, Optional

from prometheus_client import Counter, start_http_server

try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
except ImportError:  # pragma: no cover - optional dependency handling
    geoip2 = None
    AddressNotFoundError = Exception

LOG_PATH = os.getenv("LOG_PATH", "/var/log/nginx/access.log")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "9113"))
POLL_INTERVAL_SECONDS = float(os.getenv("POLL_INTERVAL_SECONDS", "0.5"))
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "")

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
REQUEST_LOCATION_COUNT = Counter(
    "nginx_http_request_location_total",
    "Total nginx requests annotated with GeoIP data.",
    ["remote_addr", "country", "city", "latitude", "longitude"],
)
FORBIDDEN_LOCATION_COUNT = Counter(
    "nginx_http_forbidden_location_total",
    "403 nginx requests annotated with GeoIP data.",
    ["remote_addr", "country", "city", "latitude", "longitude"],
)
SUCCESS_LOCATION_COUNT = Counter(
    "nginx_http_success_location_total",
    "2xx nginx requests annotated with GeoIP data.",
    ["remote_addr", "country", "city", "latitude", "longitude"],
)

GEO_CACHE: Dict[str, Optional[Dict[str, str]]] = {}
GEOIP_READER: Optional["geoip2.database.Reader"] = None

if GEOIP_DB_PATH and geoip2 is not None:
    if os.path.isfile(GEOIP_DB_PATH):
        try:
            GEOIP_READER = geoip2.database.Reader(GEOIP_DB_PATH)
            logging.info("Loaded GeoIP database at %s", GEOIP_DB_PATH)
        except Exception as exc:  # pragma: no cover - defensive guard
            logging.exception("Failed to load GeoIP database: %s", exc)
            GEOIP_READER = None
    else:
        logging.warning("GeoIP database path %s not found", GEOIP_DB_PATH)
elif GEOIP_DB_PATH:
    logging.warning("geoip2 package unavailable; GeoIP lookups disabled")




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
                    log_file.seek(0)

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


# GeoIP helpers -------------------------------------------------------------

def _lookup_private(remote_addr: str) -> Optional[Dict[str, str]]:
    try:
        ip_obj = ip_address(remote_addr)
    except ValueError:
        return None

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
        return {
            "country": "Local Network",
            "city": "Private",
            "latitude": "0",
            "longitude": "0",
        }
    return None


def lookup_location(remote_addr: str) -> Optional[Dict[str, str]]:
    if remote_addr in GEO_CACHE:
        return GEO_CACHE[remote_addr]

    private_location = _lookup_private(remote_addr)
    if private_location is not None:
        GEO_CACHE[remote_addr] = private_location
        return private_location

    if GEOIP_READER is None:
        GEO_CACHE[remote_addr] = None
        return None

    try:
        response = GEOIP_READER.city(remote_addr)
        latitude = response.location.latitude
        longitude = response.location.longitude
        if latitude is None or longitude is None:
            raise AddressNotFoundError  # treat missing coords as not found
        location = {
            "country": response.country.name or "Unknown",
            "city": response.city.name
            or (response.subdivisions[0].name if response.subdivisions else "Unknown"),
            "latitude": f"{latitude:.6f}",
            "longitude": f"{longitude:.6f}",
        }
    except AddressNotFoundError:
        location = None
    except Exception as exc:  # pragma: no cover - defensive guard
        logging.exception("GeoIP lookup failed for %s: %s", remote_addr, exc)
        location = None

    GEO_CACHE[remote_addr] = location
    return location




def record_location(counter: Counter, remote_addr: str, location: Optional[Dict[str, str]]) -> None:
    if location is None:
        return
    counter.labels(
        remote_addr=remote_addr,
        country=location["country"],
        city=location["city"],
        latitude=location["latitude"],
        longitude=location["longitude"],
    ).inc()


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

    location = lookup_location(remote_addr)
    record_location(REQUEST_LOCATION_COUNT, remote_addr, location)

    if status.startswith("2"):
        SUCCESS_COUNT.labels(remote_addr=remote_addr, path=path).inc()
        record_location(SUCCESS_LOCATION_COUNT, remote_addr, location)
    if status == "403":
        FORBIDDEN_COUNT.labels(remote_addr=remote_addr, path=path).inc()
        record_location(FORBIDDEN_LOCATION_COUNT, remote_addr, location)


if __name__ == "__main__":
    logging.info("Starting nginx log exporter on port %s", LISTEN_PORT)
    start_http_server(LISTEN_PORT)
    for log_line in tail_log(LOG_PATH):
        process_line(log_line)
