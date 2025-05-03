# port_scanner/scanner.py
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event
from typing import List, Tuple
import errno


# ---------- Yardımcı kontroller ----------
def _tcp_check(ip: str, port: int, timeout: float, stop_evt: Event, counter: list) -> Tuple[int, str] | None:
    counter[0] += 1
    if stop_evt.is_set():
        return None
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(0.5)
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()
            except Exception:
                banner = ""
            return port, banner
    except Exception:
        return None


def _udp_check(ip: str, port: int, timeout: float, stop_evt: Event, counter: list) -> int | None:
    counter[0] += 1
    if stop_evt.is_set():
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b"", (ip, port))
        data, _ = sock.recvfrom(1024)  # varsa veri
        if data:
            return port
        return None
    except socket.error as e:
        # ICMP port unreachable on Linux comes as ECONNREFUSED
        if isinstance(e, OSError) and e.errno == errno.ECONNREFUSED:
            return None  # closed
        return None
    except socket.timeout:
        return None
    finally:
        sock.close()


# ---------- Toplu tarama ----------
def scan_all_tcp(ip: str, threads: int, timeout: float, stop_evt: Event) -> Tuple[List[Tuple[int, str]], int]:
    open_ports = []
    progress = [0]
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = [pool.submit(_tcp_check, ip, p, timeout, stop_evt, progress) for p in range(1, 65536)]
        for f in as_completed(futs):
            if stop_evt.is_set():
                pool.shutdown(wait=False, cancel_futures=True)
                break
            res = f.result()
            if res:
                open_ports.append(res)
    return sorted(open_ports), progress[0]


def scan_all_udp(ip: str, threads: int, timeout: float, stop_evt: Event) -> Tuple[List[int], int]:
    open_ports = []
    progress = [0]
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = [pool.submit(_udp_check, ip, p, timeout, stop_evt, progress) for p in range(1, 65536)]
        for f in as_completed(futs):
            if stop_evt.is_set():
                pool.shutdown(wait=False, cancel_futures=True)
                break
            res = f.result()
            if res:
                open_ports.append(res)
    return sorted(open_ports), progress[0]