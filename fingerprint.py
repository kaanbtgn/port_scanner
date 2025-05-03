import argparse
import time
import threading
from scanner import scan_all_tcp, scan_all_udp
import sys

def main():
    ap = argparse.ArgumentParser(description="Port tarayıcı")
    ap.add_argument("target", help="Hedef IP veya domain")
    ap.add_argument("--threads", type=int, default=100, help="Thread sayısı")
    ap.add_argument("--timeout", type=int, default=3, help="Zaman aşımı süresi")
    ap.add_argument("--no-udp", action="store_true", help="UDP taramasını kapat")
    args = ap.parse_args()

    target = args.target
    stop_evt = threading.Event()

    t0 = time.time()
    tcp_open = []
    udp_open = []

    def tcp_job():
        print(f"[+] {target} TCP taraması başlıyor…")
        nonlocal tcp_open
        nonlocal tcp_done
        tcp_open, tcp_done = scan_all_tcp(target, args.threads, args.timeout, stop_evt)

    def udp_job():
        print(f"[+] {target} UDP taraması başlıyor…")
        nonlocal udp_open
        nonlocal udp_done
        udp_open, udp_done = scan_all_udp(target, args.threads, args.timeout, stop_evt)

    tcp_done = 0
    udp_done = 0

    tcp_thread = threading.Thread(target=tcp_job, daemon=True)
    tcp_thread.start()

    if not args.no_udp:
        udp_thread = threading.Thread(target=udp_job, daemon=True)
        udp_thread.start()
    else:
        udp_thread = None

    total_ports = 65536 * (1 + (0 if args.no_udp else 1))
    while tcp_thread.is_alive() or (udp_thread and udp_thread.is_alive()):
        if stop_evt.is_set():
            break
        done = 0
        done += tcp_done if 'tcp_done' in locals() else 0
        done += udp_done if (udp_thread and 'udp_done' in locals()) else 0
        percent = done * 100 / total_ports
        sys.stdout.write(f"\r[+] İlerleme: {percent:6.2f}%")
        sys.stdout.flush()
        time.sleep(0.5)
    sys.stdout.write("\n")

    # Wait threads
    tcp_thread.join()
    if udp_thread:
        udp_thread.join()

    for p, b in tcp_open:
        first = b.splitlines()[0][:80] if b else ""
        print(f"TCP {p:<5} OPEN   {first}")

    for p in udp_open:
        print(f"UDP {p:<5} open|filtered")

    if not stop_evt.is_set():
        print(f"\nTarama tamamlandı: {len(tcp_open)} TCP port açık, {len(udp_open)} UDP port open|filtered.")
        print(f"Süre: {time.time() - t0:.2f} saniye")

if __name__ == "__main__":
    main()
# port_scanner/fingerprint.py
import subprocess, platform, re

def os_guess(ip: str, timeout: int = 1) -> str:
    """
    Ping TTL değerine bakarak kaba OS tahmini – ek bağımlılık yok.
    """
    sys_name = platform.system().lower()
    if "darwin" in sys_name or "mac" in sys_name:
        cmd = ["ping", "-c", "1", ip]          # -c 1 yeterli
        ttl_re = re.compile(r"ttl=(\d+)", re.I)
    elif "win" in sys_name:
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        ttl_re = re.compile(r"TTL=(\d+)", re.I)
    else:  # Linux/BSD
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
        ttl_re = re.compile(r"ttl=(\d+)", re.I)

    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                      text=True, timeout=timeout + 1)
        m = ttl_re.search(out)
        if not m:
            return "OS tahmini yok"
        ttl = int(m.group(1))
        if ttl <= 64:
            os_name = "Linux/Unix"
        elif ttl <= 128:
            os_name = "Windows"
        else:
            os_name = "Ağ cihazı / yönlendirici"
        return f"{os_name} (TTL={ttl})"
    except subprocess.TimeoutExpired:
        return "Ping cevabı yok"