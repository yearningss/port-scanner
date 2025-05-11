import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
from datetime import datetime
import queue
import time
from typing import Dict, List
import json
import webbrowser


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

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Сканер Портов v2.0")
        self.root.geometry("800x600")
        self.root.configure(bg="#2b2b2b")
        
        self.queue = queue.Queue()
        
        self.scanning = False
        self.open_ports = []
        
        self.create_widgets()
        self.apply_styles()
        
        self.root.after(100, self.check_queue)

    def apply_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Primary.TButton',
                       background='#007bff',
                       foreground='white',
                       padding=10,
                       font=('Helvetica', 10))
        
        style.configure('Link.TLabel',
                       foreground='#007bff',
                       background='#2b2b2b',
                       font=('Helvetica', 9, 'underline'))
        
        style.configure('Custom.TEntry',
                       fieldbackground='#3b3b3b',
                       foreground='white',
                       padding=5)
        
        style.configure('Custom.Horizontal.TProgressbar',
                       troughcolor='#3b3b3b',
                       background='#007bff',
                       thickness=20)

    def create_widgets(self):
        banner_frame = tk.Frame(self.root, bg="#1b1b1b", height=40)
        banner_frame.pack(fill=tk.X, pady=(0, 10))
        
        dev_label = tk.Label(banner_frame, 
                          text="🛡️ Security Research by yearningss", 
                          bg="#1b1b1b", 
                          fg="#ffffff",
                          font=('Helvetica', 10))
        dev_label.pack(side=tk.LEFT, padx=20, pady=10)
        
        github_link = ttk.Label(banner_frame, 
                              text="GitHub: @yearningss", 
                              style='Link.TLabel',
                              cursor="hand2")
        github_link.pack(side=tk.RIGHT, padx=20, pady=10)
        github_link.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/yearningss"))

        input_frame = tk.Frame(self.root, bg="#2b2b2b", pady=20)
        input_frame.pack(fill=tk.X, padx=20)

        tk.Label(input_frame, text="IP адрес:", bg="#2b2b2b", fg="white").pack(side=tk.LEFT, padx=5)
        self.ip_entry = tk.Entry(input_frame, width=20, 
                               bg="#3b3b3b", fg="white",
                               insertbackground="white",
                               selectbackground="#007bff",
                               selectforeground="white")
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(input_frame, text="Начальный порт:", bg="#2b2b2b", fg="white").pack(side=tk.LEFT, padx=5)
        self.start_port_entry = tk.Entry(input_frame, width=7,
                                       bg="#3b3b3b", fg="white",
                                       insertbackground="white",
                                       selectbackground="#007bff",
                                       selectforeground="white")
        self.start_port_entry.insert(0, "1")
        self.start_port_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(input_frame, text="Конечный порт:", bg="#2b2b2b", fg="white").pack(side=tk.LEFT, padx=5)
        self.end_port_entry = tk.Entry(input_frame, width=7,
                                     bg="#3b3b3b", fg="white",
                                     insertbackground="white",
                                     selectbackground="#007bff",
                                     selectforeground="white")
        self.end_port_entry.insert(0, "1024")
        self.end_port_entry.pack(side=tk.LEFT, padx=5)

        for entry in [self.ip_entry, self.start_port_entry, self.end_port_entry]:
            entry.bind('<Control-v>', lambda e: self.paste_from_clipboard(e.widget))
            entry.bind('<Control-V>', lambda e: self.paste_from_clipboard(e.widget))
            entry.bind('<Control-c>', lambda e: self.copy_to_clipboard(e.widget))
            entry.bind('<Control-C>', lambda e: self.copy_to_clipboard(e.widget))
            entry.bind('<Control-x>', lambda e: self.cut_to_clipboard(e.widget))
            entry.bind('<Control-X>', lambda e: self.cut_to_clipboard(e.widget))
            entry.bind('<Control-a>', lambda e: self.select_all(e.widget))
            entry.bind('<Control-A>', lambda e: self.select_all(e.widget))
            
            entry.bind('<Button-3>', self.show_popup_menu)

        self.scan_button = ttk.Button(input_frame, text="Начать сканирование",
                                    command=self.start_scan, style='Primary.TButton')
        self.scan_button.pack(side=tk.LEFT, padx=20)

        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(self.root, variable=self.progress_var,
                                      maximum=100, style='Custom.Horizontal.TProgressbar')
        self.progress.pack(fill=tk.X, padx=20, pady=10)

        self.output_text = scrolledtext.ScrolledText(self.root, height=20,
                                                   bg="#3b3b3b", fg="white",
                                                   font=('Consolas', 10))
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        footer_frame = tk.Frame(self.root, bg="#1b1b1b")
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(footer_frame, text="Готов к сканированию",
                                   bg="#1b1b1b", fg="white")
        self.status_label.pack(side=tk.LEFT, pady=5, padx=20)
        
        telegram_link = ttk.Label(footer_frame, 
                                text="Telegram: @yearningss",
                                style='Link.TLabel',
                                cursor="hand2")
        telegram_link.pack(side=tk.RIGHT, pady=5, padx=20)
        telegram_link.bind("<Button-1>", lambda e: webbrowser.open("https://t.me/yearningss"))

        self.output_text.bind('<Button-3>', lambda e: self.show_popup_menu(e))
        self.output_text.bind('<Control-c>', lambda e: self.copy_to_clipboard(self.output_text))
        self.output_text.bind('<Control-C>', lambda e: self.copy_to_clipboard(self.output_text))
        self.output_text.bind('<Control-a>', lambda e: self.output_text.tag_add(tk.SEL, "1.0", tk.END))
        self.output_text.bind('<Control-A>', lambda e: self.output_text.tag_add(tk.SEL, "1.0", tk.END))

    def update_output(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)

    def scan_port(self, target: str, port: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = self.get_service_name(port)
                description = COMMON_PORTS.get(port, "")
                self.open_ports.append({
                    "port": port,
                    "service": service,
                    "description": description
                })
                message = f"[+] Порт {port:5d}: {service:15s}"
                if description:
                    message += f" - {description}"
                self.queue.put(("update_text", message))
            sock.close()
        except:
            pass

    def get_service_name(self, port: int) -> str:
        try:
            service = socket.getservbyport(port)
            return service
        except:
            return "неизвестно"

    def scan_ports(self):
        target = self.ip_entry.get()
        start_port = int(self.start_port_entry.get())
        end_port = int(self.end_port_entry.get())
        
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.queue.put(("error", "Ошибка: Невозможно получить IP адрес"))
            return

        total_ports = end_port - start_port + 1
        scanned = 0
        
        self.queue.put(("update_text", f"\n[*] Начинаем сканирование {target} ({target_ip})"))
        self.queue.put(("update_text", f"[*] Время начала: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
        self.queue.put(("update_text", "\n" + "=" * 60 + "\n"))

        active_threads = []
        max_threads = 100

        try:
            for port in range(start_port, end_port + 1):
                if not self.scanning:
                    break

                active_threads = [t for t in active_threads if t.is_alive()]
                
                while len(active_threads) >= max_threads:
                    active_threads = [t for t in active_threads if t.is_alive()]
                    time.sleep(0.01)
                
                thread = threading.Thread(target=self.scan_port, args=(target_ip, port))
                thread.daemon = True
                thread.start()
                active_threads.append(thread)
                
                scanned += 1
                if scanned % 10 == 0:
                    progress = (scanned / total_ports) * 100
                    self.queue.put(("update_progress", progress))

            for thread in active_threads:
                thread.join()

        except Exception as e:
            self.queue.put(("error", f"Ошибка при сканировании: {str(e)}"))
            return

        if self.scanning:
            self.queue.put(("update_text", "\n" + "=" * 60))
            self.queue.put(("update_text", f"\n[*] Сканирование завершено!"))
            self.queue.put(("update_text", f"[*] Время окончания: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
            
            if self.open_ports:
                self.queue.put(("update_text", "\n[*] Сводка открытых портов:"))
                self.queue.put(("update_text", "=" * 60))
                self.queue.put(("update_text", f"{'Порт':^10} {'Служба':^15} {'Описание':<35}"))
                self.queue.put(("update_text", "-" * 60))
                
                for port_info in sorted(self.open_ports, key=lambda x: x["port"]):
                    port = port_info["port"]
                    service = port_info["service"]
                    description = port_info["description"] or "Нет описания"
                    self.queue.put(("update_text", f"{port:^10} {service:^15} {description:<35}"))
            else:
                self.queue.put(("update_text", "\n[!] Открытых портов не найдено"))

        self.queue.put(("scan_complete", None))

    def start_scan(self):
        if not self.scanning:
            self.scanning = True
            self.open_ports = []
            self.scan_button.configure(text="Остановить")
            self.output_text.delete(1.0, tk.END)
            self.progress_var.set(0)
            self.status_label.configure(text="Сканирование...")
            
            threading.Thread(target=self.scan_ports, daemon=True).start()
        else:
            self.scanning = False
            self.scan_button.configure(text="Начать сканирование")
            self.status_label.configure(text="Сканирование остановлено")

    def check_queue(self):
        try:
            while True:
                message_type, message = self.queue.get_nowait()
                
                if message_type == "update_text":
                    self.update_output(message)
                elif message_type == "update_progress":
                    self.progress_var.set(message)
                elif message_type == "error":
                    self.update_output(f"\n[!] {message}")
                    self.scanning = False
                    self.scan_button.configure(text="Начать сканирование")
                    self.status_label.configure(text="Ошибка сканирования")
                elif message_type == "scan_complete":
                    self.scanning = False
                    self.scan_button.configure(text="Начать сканирование")
                    self.status_label.configure(text="Сканирование завершено")
                
                self.queue.task_done()
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.check_queue)

    def paste_from_clipboard(self, widget):
        try:
            widget.delete("sel.first", "sel.last")
        except:
            pass
        try:
            text = self.root.clipboard_get()
            widget.insert("insert", text)
        except:
            pass
        return "break"

    def copy_to_clipboard(self, widget):
        try:
            text = widget.selection_get()
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except:
            pass
        return "break"

    def cut_to_clipboard(self, widget):
        try:
            text = widget.selection_get()
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            widget.delete("sel.first", "sel.last")
        except:
            pass
        return "break"

    def select_all(self, widget):
        widget.select_range(0, tk.END)
        widget.icursor(tk.END)
        return "break"

    def show_popup_menu(self, event):
        widget = event.widget
        menu = tk.Menu(self.root, tearoff=0, bg='#2b2b2b', fg='white')
        menu.add_command(label="Вставить", command=lambda: self.paste_from_clipboard(widget))
        menu.add_command(label="Копировать", command=lambda: self.copy_to_clipboard(widget))
        menu.add_command(label="Вырезать", command=lambda: self.cut_to_clipboard(widget))
        menu.add_separator()
        menu.add_command(label="Выделить всё", command=lambda: self.select_all(widget))
        
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return "break"

def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 