import argparse
import threading
import time
import sys
from scanner import scan_all_tcp, scan_all_udp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("-t", "--threads", type=int, default=50)
    ap.add_argument("--timeout", type=float, default=0.5)
    ap.add_argument("--no-udp", action="store_true", help="UDP taramasını kapat")
    ap.add_argument("--log-json")
    ap.add_argument("--log-csv")
    args = ap.parse_args()

    target = args.target
    stop_evt = threading.Event()

    t0 = time.time()
    tcp_open = []
    udp_open = []

    def tcp_job():
        print(f"[+] {target} TCP taraması başlıyor…")
        nonlocal tcp_open
        tcp_open, tcp_done = scan_all_tcp(target, args.threads, args.timeout, stop_evt)
        tcp_job.tcp_done = tcp_done

    def udp_job():
        print(f"[+] {target} UDP taraması başlıyor…")
        nonlocal udp_open
        udp_open, udp_done = scan_all_udp(target, args.threads, args.timeout, stop_evt)
        udp_job.udp_done = udp_done

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
        done += getattr(tcp_job, 'tcp_done', 0)
        if udp_thread:
            done += getattr(udp_job, 'udp_done', 0)
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
        print(f"\n[+] {target} taraması tamamlandı "
              f"({len(tcp_open)} TCP, {len(udp_open)} UDP) "
              f"({time.time()-t0:.2f} saniye)")

    if args.log_json:
        from logger import save_json
        save_json(args.log_json, tcp_open, udp_open)

    if args.log_csv:
        from logger import save_csv
        save_csv(args.log_csv, tcp_open, udp_open)


if __name__ == "__main__":
    main()
# port_scanner/logger.py
import json, csv
from typing import List, Tuple

def save_json(path: str, tcp_results: List[Tuple[int, str]], udp_results: List[int]):
    with open(path, "w") as fp:
        json.dump({
            "tcp": [{"port": p, "banner": b} for p, b in tcp_results],
            "udp": udp_results
        }, fp, indent=2)

def save_csv(path: str, tcp_results: List[Tuple[int, str]], udp_results: List[int]):
    with open(path, "w", newline="") as fp:
        w = csv.writer(fp)
        w.writerow(["proto", "port", "banner"])
        for p, b in tcp_results:
            w.writerow(["tcp", p, b])
        for p in udp_results:
            w.writerow(["udp", p, ""])