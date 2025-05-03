import argparse, time, signal, threading, os, sys
from threading import Event
from scanner import scan_all_tcp, scan_all_udp
from fingerprint import os_guess
from logger import save_json, save_csv

stop_evt = Event()


def sigint_handler(signum, frame):
    stop_evt.set()
    print("\n[!] Tarama durduruluyor…")
signal.signal(signal.SIGINT, sigint_handler)


def main():
    ap = argparse.ArgumentParser(description="Tam port tarayıcı + OS tahmini")
    ap.add_argument("ip", nargs="?", help="Hedef IP (boşsa sorulur)")
    ap.add_argument("-t", "--threads", type=int, default=400, help="Thread sayısı")
    ap.add_argument("--timeout", type=float, default=1.0, help="Socket timeout s")
    ap.add_argument("--no-udp", action="store_true", help="UDP taramasını kapat")
    ap.add_argument("--json", help="JSON çıktı dosyası")
    ap.add_argument("--csv", help="CSV  çıktı dosyası")
    args = ap.parse_args()

    target = args.ip.strip() if args.ip else input("Hedef IP: ").strip()

    t0 = time.time()
    tcp_open, udp_open = [], []

    def tcp_job():
        nonlocal tcp_open
        print(f"[+] {target} TCP taraması başlıyor…")
        tcp_open, tcp_done = scan_all_tcp(target, args.threads, args.timeout, stop_evt)
        return tcp_open, tcp_done

    def udp_job():
        nonlocal udp_open
        print(f"[+] {target} UDP taraması başlıyor…")
        udp_open, udp_done = scan_all_udp(target, args.threads, args.timeout, stop_evt)
        return udp_open, udp_done

    tcp_thread = threading.Thread(target=tcp_job, daemon=True)
    tcp_thread.start()

    udp_thread = None
    if not args.no_udp:
        udp_thread = threading.Thread(target=udp_job, daemon=True)
        udp_thread.start()

    total_ports = 65536 * (1 + (0 if args.no_udp else 1))
    while tcp_thread.is_alive() or (udp_thread and udp_thread.is_alive()):
        if stop_evt.is_set():
            break
        done = 0
        done += tcp_job.__closure__[0].cell_contents if 'tcp_done' in locals() else 0
        done += udp_job.__closure__[0].cell_contents if (udp_thread and 'udp_done' in locals()) else 0
        percent = done * 100 / total_ports
        sys.stdout.write(f"\r[+] İlerleme: {percent:6.2f}%")
        sys.stdout.flush()
        time.sleep(0.5)
    sys.stdout.write("\n")

    if not stop_evt.is_set():
        for p, b in tcp_open:
            first = b.splitlines()[0][:80] if b else ""
            print(f"TCP {p:<5} OPEN   {first}")
        for p in udp_open:
            print(f"UDP {p:<5} open|filtered")

        print("\n--- ÖZET ---")
        print(f"Açık TCP: {len(tcp_open)} | Açık/filtered UDP: {len(udp_open)}")
        print("OS:", os_guess(target))
    else:
        print("[!] Liste tamamlanmadı — tarama kullanıcı tarafından kesildi.")

    print(f"Süre: {time.time() - t0:.1f} s")

    # Otomatik log
    ts = int(time.time())
    base = f"scan_{target.replace('.', '_')}_{ts}"
    json_path = args.json or f"{base}.json"
    csv_path  = args.csv  or f"{base}.csv"
    save_json(json_path, tcp_open, udp_open)
    save_csv(csv_path,  tcp_open, udp_open)
    print(f"[+] JSON → {os.path.abspath(json_path)}")
    print(f"[+] CSV  → {os.path.abspath(csv_path)}")


if __name__ == "__main__":
    main()