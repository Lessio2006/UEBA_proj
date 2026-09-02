from __future__ import annotations

import argparse
import csv
import ipaddress
import math
import signal
import socket
import time
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from statistics import fmean
from typing import Any

import psutil


@dataclass(slots=True)
class WindowFeatures:
    timestamp: str

    # Time features
    hour_sin: float
    hour_cos: float
    weekday_sin: float
    weekday_cos: float

    # System
    cpu_mean: float
    cpu_max: float
    ram_mean: float
    ram_max: float
    swap_mean: float
    process_count_mean: float
    new_process_count: int
    disk_read_bytes: int
    disk_write_bytes: int
    disk_read_ops: int
    disk_write_ops: int

    # Network
    net_sent_bytes: int
    net_recv_bytes: int
    net_sent_packets: int
    net_recv_packets: int
    tcp_connection_count_mean: float
    udp_endpoint_count_mean: float
    established_count_mean: float
    listening_count_mean: float
    time_wait_count_mean: float
    new_connection_count: int
    closed_connection_count: int
    unique_remote_host_count: int
    new_remote_host_count: int
    unique_remote_port_count: int
    public_connection_count_mean: float
    private_connection_count_mean: float
    outbound_inbound_ratio: float


@dataclass(slots=True)
class IOCounters:
    disk_read_bytes: int
    disk_write_bytes: int
    disk_read_ops: int
    disk_write_ops: int
    net_sent_bytes: int
    net_recv_bytes: int
    net_sent_packets: int
    net_recv_packets: int


@dataclass(slots=True)
class Snapshot:
    cpu_percent: float
    ram_percent: float
    swap_percent: float
    process_count: int
    pids: set[int]

    tcp_connection_count: int
    udp_endpoint_count: int
    established_count: int
    listening_count: int
    time_wait_count: int
    public_connection_count: int
    private_connection_count: int

    connection_keys: set[tuple[Any, ...]]
    remote_hosts: set[str]
    remote_ports: set[int]


class UEBACollector:
    """
    Collects privacy-preserving aggregate system and network features.

    The collector does not write process names, usernames, command lines,
    file paths, IP addresses, port numbers or packet contents to disk.
    IP addresses and ports are held only in memory to calculate counts.
    """

    def __init__(
        self,
        output_path: str | Path,
        sample_interval_seconds: float = 5.0,
        window_seconds: int = 30,
    ) -> None:
        if sample_interval_seconds <= 0:
            raise ValueError("sample_interval_seconds must be greater than zero")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")

        samples_per_window = window_seconds / sample_interval_seconds
        if not samples_per_window.is_integer():
            raise ValueError(
                "window_seconds must be divisible by sample_interval_seconds"
            )

        self.output_path = Path(output_path)
        self.sample_interval_seconds = float(sample_interval_seconds)
        self.window_seconds = int(window_seconds)
        self.samples_per_window = int(samples_per_window)

        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        self._stop_requested = False
        self._previous_pids = set(psutil.pids())
        self._previous_connections = self._get_connection_snapshot().connection_keys
        self._previous_window_hosts: set[str] | None = None

        # The first non-blocking cpu_percent() call is not meaningful.
        psutil.cpu_percent(interval=None)

    @staticmethod
    def _field_names() -> list[str]:
        return [field.name for field in fields(WindowFeatures)]

    @staticmethod
    def _counter_value(obj: Any, name: str) -> int:
        return int(getattr(obj, name, 0) or 0)

    @classmethod
    def _read_io_counters(cls) -> IOCounters:
        disk = psutil.disk_io_counters()
        net = psutil.net_io_counters()

        if disk is None:
            raise RuntimeError("Disk I/O counters are unavailable.")
        if net is None:
            raise RuntimeError("Network I/O counters are unavailable.")

        return IOCounters(
            disk_read_bytes=cls._counter_value(disk, "read_bytes"),
            disk_write_bytes=cls._counter_value(disk, "write_bytes"),
            disk_read_ops=cls._counter_value(disk, "read_count"),
            disk_write_ops=cls._counter_value(disk, "write_count"),
            net_sent_bytes=cls._counter_value(net, "bytes_sent"),
            net_recv_bytes=cls._counter_value(net, "bytes_recv"),
            net_sent_packets=cls._counter_value(net, "packets_sent"),
            net_recv_packets=cls._counter_value(net, "packets_recv"),
        )

    @staticmethod
    def _safe_delta(current: int, previous: int) -> int:
        return max(0, current - previous)  # Protects the dataset from negative values after a counter reset.

    @staticmethod
    def _address_parts(address: Any) -> tuple[str, int] | None:
        if not address:
            return None

        if hasattr(address, "ip") and hasattr(address, "port"):
            return str(address.ip), int(address.port)

        try:
            return str(address[0]), int(address[1])
        except (IndexError, TypeError, ValueError):
            return None

    @staticmethod
    def _is_public_ip(ip_text: str) -> bool:
        try:
            return ipaddress.ip_address(ip_text).is_global
        except ValueError:
            return False

    def _get_connection_snapshot(self) -> Snapshot:
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as exc:
            raise RuntimeError(
                "Windows denied access to network connections. "
                "Run the terminal or PyCharm as administrator."
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                f"Unable to read network connections: {exc}"
            ) from exc

        tcp_count = 0
        udp_count = 0
        established_count = 0
        listening_count = 0
        time_wait_count = 0
        public_count = 0
        private_count = 0

        connection_keys: set[tuple[Any, ...]] = set()
        remote_hosts: set[str] = set()
        remote_ports: set[int] = set()

        for connection in connections:
            if connection.type == socket.SOCK_STREAM:
                tcp_count += 1
            elif connection.type == socket.SOCK_DGRAM:
                udp_count += 1

            if connection.status == psutil.CONN_ESTABLISHED:
                established_count += 1
            elif connection.status == psutil.CONN_LISTEN:
                listening_count += 1
            elif connection.status == psutil.CONN_TIME_WAIT:
                time_wait_count += 1

            local = self._address_parts(connection.laddr)
            remote = self._address_parts(connection.raddr)

            protocol = (
                "tcp"
                if connection.type == socket.SOCK_STREAM
                else "udp"
                if connection.type == socket.SOCK_DGRAM
                else str(connection.type)
            )

            connection_keys.add(
                (
                    protocol,
                    local[0] if local else "",
                    local[1] if local else 0,
                    remote[0] if remote else "",
                    remote[1] if remote else 0,
                )
            )

            if remote:
                remote_ip, remote_port = remote
                remote_hosts.add(remote_ip)
                remote_ports.add(remote_port)

                if self._is_public_ip(remote_ip):
                    public_count += 1
                else:
                    private_count += 1

        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        pids = set(psutil.pids())

        return Snapshot(
            cpu_percent=float(psutil.cpu_percent(interval=None)),
            ram_percent=float(memory.percent),
            swap_percent=float(swap.percent),
            process_count=len(pids),
            pids=pids,
            tcp_connection_count=tcp_count,
            udp_endpoint_count=udp_count,
            established_count=established_count,
            listening_count=listening_count,
            time_wait_count=time_wait_count,
            public_connection_count=public_count,
            private_connection_count=private_count,
            connection_keys=connection_keys,
            remote_hosts=remote_hosts,
            remote_ports=remote_ports,
        )

    @staticmethod
    def _time_features(local_dt: datetime) -> tuple[float, float, float, float]:
        seconds_in_day = (
            local_dt.hour * 3600
            + local_dt.minute * 60
            + local_dt.second
            + local_dt.microsecond / 1_000_000
        )
        hour_angle = 2 * math.pi * seconds_in_day / 86_400
        weekday_angle = 2 * math.pi * local_dt.weekday() / 7

        return (
            math.sin(hour_angle),
            math.cos(hour_angle),
            math.sin(weekday_angle),
            math.cos(weekday_angle),
        )

    @staticmethod
    def _mean(values: list[float | int]) -> float:
        return round(float(fmean(values)), 6)

    def collect_window(self) -> WindowFeatures:
        window_start_utc = datetime.now(timezone.utc)
        window_start_local = window_start_utc.astimezone()

        start_io = self._read_io_counters()

        cpu_values: list[float] = []
        ram_values: list[float] = []
        swap_values: list[float] = []
        process_counts: list[int] = []

        tcp_counts: list[int] = []
        udp_counts: list[int] = []
        established_counts: list[int] = []
        listening_counts: list[int] = []
        time_wait_counts: list[int] = []
        public_counts: list[int] = []
        private_counts: list[int] = []

        new_pids_in_window: set[int] = set()
        new_connection_count = 0
        closed_connection_count = 0
        remote_hosts_in_window: set[str] = set()
        remote_ports_in_window: set[int] = set()

        next_sample_at = time.monotonic() + self.sample_interval_seconds

        for _ in range(self.samples_per_window):
            sleep_seconds = max(0.0, next_sample_at - time.monotonic())
            if sleep_seconds:
                time.sleep(sleep_seconds)

            if self._stop_requested:
                raise KeyboardInterrupt

            snapshot = self._get_connection_snapshot()

            cpu_values.append(snapshot.cpu_percent)
            ram_values.append(snapshot.ram_percent)
            swap_values.append(snapshot.swap_percent)
            process_counts.append(snapshot.process_count)

            tcp_counts.append(snapshot.tcp_connection_count)
            udp_counts.append(snapshot.udp_endpoint_count)
            established_counts.append(snapshot.established_count)
            listening_counts.append(snapshot.listening_count)
            time_wait_counts.append(snapshot.time_wait_count)
            public_counts.append(snapshot.public_connection_count)
            private_counts.append(snapshot.private_connection_count)

            new_pids_in_window.update(snapshot.pids - self._previous_pids)
            self._previous_pids = snapshot.pids

            new_connection_count += len(
                snapshot.connection_keys - self._previous_connections
            )
            closed_connection_count += len(
                self._previous_connections - snapshot.connection_keys
            )
            self._previous_connections = snapshot.connection_keys

            remote_hosts_in_window.update(snapshot.remote_hosts)
            remote_ports_in_window.update(snapshot.remote_ports)

            next_sample_at += self.sample_interval_seconds

        end_io = self._read_io_counters()

        if self._previous_window_hosts is None:
            new_remote_host_count = 0
        else:
            new_remote_host_count = len(
                remote_hosts_in_window - self._previous_window_hosts
            )

        self._previous_window_hosts = remote_hosts_in_window

        net_sent_bytes = self._safe_delta(
            end_io.net_sent_bytes, start_io.net_sent_bytes
        )
        net_recv_bytes = self._safe_delta(
            end_io.net_recv_bytes, start_io.net_recv_bytes
        )

        hour_sin, hour_cos, weekday_sin, weekday_cos = self._time_features(
            window_start_local
        )

        return WindowFeatures(
            timestamp=window_start_utc.isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z"),
            hour_sin=round(hour_sin, 6),
            hour_cos=round(hour_cos, 6),
            weekday_sin=round(weekday_sin, 6),
            weekday_cos=round(weekday_cos, 6),
            cpu_mean=self._mean(cpu_values),
            cpu_max=round(max(cpu_values), 6),
            ram_mean=self._mean(ram_values),
            ram_max=round(max(ram_values), 6),
            swap_mean=self._mean(swap_values),
            process_count_mean=self._mean(process_counts),
            new_process_count=len(new_pids_in_window),
            disk_read_bytes=self._safe_delta(
                end_io.disk_read_bytes, start_io.disk_read_bytes
            ),
            disk_write_bytes=self._safe_delta(
                end_io.disk_write_bytes, start_io.disk_write_bytes
            ),
            disk_read_ops=self._safe_delta(
                end_io.disk_read_ops, start_io.disk_read_ops
            ),
            disk_write_ops=self._safe_delta(
                end_io.disk_write_ops, start_io.disk_write_ops
            ),
            net_sent_bytes=net_sent_bytes,
            net_recv_bytes=net_recv_bytes,
            net_sent_packets=self._safe_delta(
                end_io.net_sent_packets, start_io.net_sent_packets
            ),
            net_recv_packets=self._safe_delta(
                end_io.net_recv_packets, start_io.net_recv_packets
            ),
            tcp_connection_count_mean=self._mean(tcp_counts),
            udp_endpoint_count_mean=self._mean(udp_counts),
            established_count_mean=self._mean(established_counts),
            listening_count_mean=self._mean(listening_counts),
            time_wait_count_mean=self._mean(time_wait_counts),
            new_connection_count=new_connection_count,
            closed_connection_count=closed_connection_count,
            unique_remote_host_count=len(remote_hosts_in_window),
            new_remote_host_count=new_remote_host_count,
            unique_remote_port_count=len(remote_ports_in_window),
            public_connection_count_mean=self._mean(public_counts),
            private_connection_count_mean=self._mean(private_counts),
            outbound_inbound_ratio=round(
                net_sent_bytes / (net_recv_bytes + 1),
                6,
            ),
        )

    def _validate_csv_schema(self) -> bool:
        """
        Returns True if a new CSV header must be written.
        """
        if not self.output_path.exists() or self.output_path.stat().st_size == 0:
            return True

        with self.output_path.open("r", encoding="utf-8", newline="") as file:
            reader = csv.reader(file)
            existing_header = next(reader, [])

        expected_header = self._field_names()
        if existing_header != expected_header:
            raise RuntimeError(
                "The existing CSV has a different schema. "
                f"Move or delete this file first: {self.output_path}"
            )

        return False

    def _request_stop(self, _signum: int, _frame: Any) -> None:
        self._stop_requested = True

    def run(
        self,
        duration_hours: float | None = 24.0,
        max_windows: int | None = None,
    ) -> None:
        if duration_hours is not None and duration_hours <= 0:
            raise ValueError("duration_hours must be greater than zero")
        if max_windows is not None and max_windows <= 0:
            raise ValueError("max_windows must be greater than zero")

        signal.signal(signal.SIGINT, self._request_stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, self._request_stop)

        write_header = self._validate_csv_schema()
        started_at = time.monotonic()
        windows_written = 0

        print(
            f"Collection started: one row every {self.window_seconds} seconds."
        )
        print(f"Output: {self.output_path}")
        print("Press Ctrl+C to stop safely.")

        with self.output_path.open(
            "a",
            encoding="utf-8",
            newline="",
            buffering=1,
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=self._field_names(),
            )

            if write_header:
                writer.writeheader()
                file.flush()

            try:
                while not self._stop_requested:
                    features = self.collect_window()
                    writer.writerow(asdict(features))
                    file.flush()

                    windows_written += 1
                    print(
                        f"[{features.timestamp}] "
                        f"CPU={features.cpu_mean:.1f}% "
                        f"RAM={features.ram_mean:.1f}% "
                        f"sent={features.net_sent_bytes} B "
                        f"recv={features.net_recv_bytes} B "
                        f"connections={features.tcp_connection_count_mean:.1f}"
                    )

                    if max_windows is not None and windows_written >= max_windows:
                        break

                    if (
                        duration_hours is not None
                        and time.monotonic() - started_at
                        >= duration_hours * 3600
                    ):
                        break

            except KeyboardInterrupt:
                pass

        print(
            f"Collection stopped. Rows written: {windows_written}. "
            f"File: {self.output_path}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect local UEBA system and network metrics."
    )
    parser.add_argument(
        "--output",
        default="example_path.csv",  # Input path
        help="Path to the private CSV dataset.",
    )
    parser.add_argument(
        "--sample-interval",
        type=float,
        default=5.0,
        help="Seconds between measurements inside a window.",
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=15,
        help="Aggregation window length.",
    )
    parser.add_argument(
        "--duration-hours",
        type=float,
        default=20.0,
        help="Collection duration. Use 0 only with --continuous.",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run until Ctrl+C instead of using --duration-hours.",
    )
    parser.add_argument(
        "--max-windows",
        type=int,
        default=None,
        help="Stop after N rows. Useful for a short test.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    collector = UEBACollector(
        output_path=args.output,
        sample_interval_seconds=args.sample_interval,
        window_seconds=args.window_seconds,
    )

    collector.run(
        duration_hours=None if args.continuous else args.duration_hours,
        max_windows=args.max_windows,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())