import socket
import threading
from datetime import datetime
import argparse
from typing import Dict, List
import time

# Словарь с описанием популярных портов
COMMON_PORTS: Dict[int, str] = {
    20: "FTP (передача данных)",
    21: "FTP (управление)",
    22: "SSH (безопасный удаленный доступ)",
    23: "Telnet (небезопасный удаленный доступ)",
    25: "SMTP (электронная почта)",
    53: "DNS (система доменных имен)",
    80: "HTTP (веб-сайты)",
    110: "POP3 (получение почты)",
    143: "IMAP (доступ к почте)",
    443: "HTTPS (защищенный веб)",
    445: "SMB (общий доступ к файлам Windows)",
    3306: "MySQL (база данных)",
    3389: "RDP (удаленный рабочий стол Windows)",
    5432: "PostgreSQL (база данных)",
    8080: "HTTP Alternate (веб-прокси)",
    8443: "HTTPS Alternate",
}

def print_banner():
    """Вывод красивого баннера"""
    banner = """
╔════════════════════════════════════════════════════════════╗
║                    СКАНЕР ПОРТОВ v2.0                      ║
║              Security Research by yearningss               ║
║                                                            ║
║  GitHub: https://github.com/yearningss                     ║
║  Telegram: @yearningss                                     ║
║                                                            ║
║  Создан для анализа безопасности                           ║
╚════════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_progress(current: int, total: int, prefix: str = "Прогресс"):
    """Вывод прогресс-бара"""
    bar_length = 50
    filled_length = int(bar_length * current // total)
    bar = "█" * filled_length + "░" * (bar_length - filled_length)
    percent = current / total * 100
    print(f"\r{prefix}: |{bar}| {percent:.1f}% ", end="")
    if current == total:
        print()

def scan_port(target: str, port: int, open_ports: List[int]):
    """Сканирование отдельного порта"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
            service = get_service_name(port)
            description = COMMON_PORTS.get(port, "")
            if description:
                print(f"\n[+] Порт {port:5d}: {service:15s} - {description}")
            else:
                print(f"\n[+] Порт {port:5d}: {service:15s}")
        sock.close()
    except:
        pass

def get_service_name(port: int) -> str:
    """Получение имени службы по номеру порта"""
    try:
        service = socket.getservbyport(port)
        return service
    except:
        return "неизвестно"

def scan(target: str, start_port: int, end_port: int, threads: int = 100):
    """Основная функция сканирования"""
    open_ports: List[int] = []
    thread_list: List[threading.Thread] = []
    total_ports = end_port - start_port + 1
    scanned_ports = 0
    
    print(f"\n[*] Начинаем сканирование {target}")
    print(f"[*] Время начала: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n" + "=" * 60)

    try:
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(target, port, open_ports))
            thread_list.append(thread)
            thread.start()

            if len(thread_list) >= threads:
                for thread in thread_list:
                    thread.join()
                    scanned_ports += 1
                    print_progress(scanned_ports, total_ports)
                thread_list = []

        # Ждем завершения оставшихся потоков
        for thread in thread_list:
            thread.join()
            scanned_ports += 1
            print_progress(scanned_ports, total_ports)

    except KeyboardInterrupt:
        print("\n\n[!] Сканирование прервано пользователем")
        return

    print("\n" + "=" * 60)
    print(f"\n[*] Сканирование завершено!")
    print(f"[*] Время окончания: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if open_ports:
        print("\n[*] Сводка открытых портов:")
        print("=" * 60)
        print(f"{'Порт':^10} {'Служба':^15} {'Описание':<35}")
        print("-" * 60)
        for port in sorted(open_ports):
            service = get_service_name(port)
            description = COMMON_PORTS.get(port, "Нет описания")
            print(f"{port:^10} {service:^15} {description:<35}")
    else:
        print("\n[!] Открытых портов не найдено")

def print_footer():
    """Вывод информации об авторе"""
    footer = """
╔════════════════════════════════════════════════════════════╗
║  Разработано в рамках исследований информационной          ║
║  безопасности. Используйте только на системах, на которые  ║
║  у вас есть разрешение.                                    ║
║                                                            ║
║  По вопросам и предложениям:                               ║
║  GitHub: https://github.com/yearningss                     ║
║  Telegram: @yearningss                                     ║
╚════════════════════════════════════════════════════════════╝
"""
    print(footer)

def main():
    parser = argparse.ArgumentParser(
        description="Сканер портов с определением служб",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="IP адрес или домен для сканирования")
    parser.add_argument("-s", "--start", type=int, default=1, help="Начальный порт (по умолчанию: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="Конечный порт (по умолчанию: 1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Количество потоков (по умолчанию: 100)")
    
    args = parser.parse_args()
    
    print_banner()
    
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"[*] Целевой хост: {args.target} ({target_ip})")
    except socket.gaierror:
        print("[!] Ошибка: Невозможно получить IP адрес")
        return

    scan(target_ip, args.start, args.end, args.threads)
    print_footer()

if __name__ == "__main__":
    main() 