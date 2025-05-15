import serial
import serial.tools.list_ports
import tkinter as tk
from tkinter import ttk
from tkinter import simpledialog, messagebox
import threading
import time
import json
import os
import customtkinter as ctk
from tkcalendar import DateEntry
# import pandas as pd
import math
import csv
import datetime
import pygame
from PIL import Image, ImageTk
import sqlite3
import hashlib
import sys

DB_FILE = "app_data.db"

def resource_path(relative_path):
    """ Dapatkan path absolut ke resource, berfungsi untuk mode dev dan untuk PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

pics_dir = resource_path('pics')
sound_dir = resource_path('sound')

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    else:
        salt = bytes.fromhex(salt)
    
    salted_password = salt + password.encode('utf-8')
    hashed = hashlib.sha256(salted_password).hexdigest()
    return hashed, salt.hex()

def verify_password(stored_password_hash, stored_salt_hex, provided_password):
    rehashed_password, _ = hash_password(provided_password, salt=stored_salt_hex)
    return rehashed_password == stored_password_hash

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        admin_pass_hash, admin_salt = hash_password("admin")
        cursor.execute("INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                       ('admin', admin_pass_hash, admin_salt, 'Administrator'))

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS presets (
            label TEXT PRIMARY KEY,
            seconds INTEGER NOT NULL
        )
    ''')
    cursor.execute("SELECT COUNT(*) FROM presets")
    if cursor.fetchone()[0] == 0:
        default_presets = {
            "1 Menit": 60, "5 Menit": 300, "30 Menit": 1800,
            "1 Jam": 3600, "2 Jam": 7200
        }
        for label, seconds in default_presets.items():
            cursor.execute("INSERT INTO presets (label, seconds) VALUES (?, ?)", (label, seconds))

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tariffs (
            tarif_key TEXT PRIMARY KEY, -- e.g., "Tarif 1"
            rate_per_hour INTEGER NOT NULL
        )
    ''')
    cursor.execute("SELECT COUNT(*) FROM tariffs")
    if cursor.fetchone()[0] == 0:
        for i in range(NUM_TVS):
            cursor.execute("INSERT INTO tariffs (tarif_key, rate_per_hour) VALUES (?, ?)",
                           (f"Tarif {i+1}", 0))
            
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS paket (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            durasi_menit INTEGER NOT NULL,
            harga INTEGER NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bonus_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            waktu_menit INTEGER NOT NULL,
            bonus_menit INTEGER NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cafe_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama TEXT NOT NULL,
            harga INTEGER NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS laporan_billing (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tv_nama TEXT NOT NULL,         -- e.g., "TV 1"
            tanggal TEXT NOT NULL,         -- Format YYYY-MM-DD
            waktu_mulai TEXT NOT NULL,     -- Format HH:MM:SS
            waktu_selesai TEXT NOT NULL,   -- Format HH:MM:SS
            durasi_detik INTEGER NOT NULL,
            biaya_rental INTEGER NOT NULL,
            paket_pilihan TEXT,
            cafe_items TEXT,               -- Daftar item dipisah semicolon atau JSON string
            cafe_cost INTEGER
        )
    ''')
            
    conn.commit()
    conn.close()

def load_users_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, salt, role FROM users")
    users_raw = cursor.fetchall()
    conn.close()
    return [{"id": u[0], "username": u[1], "role": u[4], "_password_hash": u[2], "_salt": u[3]} for u in users_raw]


def load_presets_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT label, seconds FROM presets")
    presets_db = cursor.fetchall()
    conn.close()
    return {label: int(seconds) for label, seconds in presets_db}

def load_tariffs_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT tarif_key, rate_per_hour FROM tariffs")
    tariffs_db = cursor.fetchall()
    conn.close()
    loaded_tariffs = {key: int(rate) for key, rate in tariffs_db}
    for i in range(NUM_TVS):
        key = f"Tarif {i+1}"
        if key not in loaded_tariffs:
            loaded_tariffs[key] = 0
    return loaded_tariffs

def load_paket_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT label, durasi_menit, harga FROM paket")
    paket_db = cursor.fetchall()
    conn.close()
    return [{"label": p[0], "durasi": p[1], "harga": p[2]} for p in paket_db]

def load_bonus_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT waktu_menit, bonus_menit FROM bonus_rules")
    bonus_db = cursor.fetchall()
    conn.close()
    return [{"waktu": b[0], "bonus": b[1]} for b in bonus_db]

def load_cafe_menu_from_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT nama, harga FROM cafe_items")
    menu_db = cursor.fetchall()
    conn.close()
    return [{"nama": item[0], "harga": item[1]} for item in menu_db]

def save_user_to_db(username, password, role):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    pass_hash, salt = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                       (username, pass_hash, salt, role))
        conn.commit()
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", f"Username '{username}' sudah digunakan.")
    finally:
        conn.close()

def update_user_in_db(original_username, new_username, password, role):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    pass_hash, salt = hash_password(password)
    try:
        cursor.execute("UPDATE users SET username=?, password_hash=?, salt=?, role=? WHERE username=?",
                       (new_username, pass_hash, salt, role, original_username))
        conn.commit()
    except sqlite3.IntegrityError:
         messagebox.showerror("Error", f"Username '{new_username}' mungkin sudah digunakan.")
    finally:
        conn.close()

def delete_user_from_db(username):
    if username.lower() == 'admin':
        messagebox.showwarning("Peringatan", "User 'admin' tidak boleh dihapus.")
        return
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()

def save_presets_to_db(presets_dict):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM presets")
    for label, seconds in presets_dict.items():
        if label != "Pilih Waktu":
             cursor.execute("INSERT INTO presets (label, seconds) VALUES (?, ?)", (label, int(seconds)))
    conn.commit()
    conn.close()

def save_tariffs_to_db(tariffs_dict):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tariffs")
    for key, rate in tariffs_dict.items():
        cursor.execute("INSERT INTO tariffs (tarif_key, rate_per_hour) VALUES (?, ?)", (key, int(rate)))
    conn.commit()
    conn.close()

def save_paket_to_db(paket_list):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM paket")
    for item in paket_list:
        cursor.execute("INSERT INTO paket (label, durasi_menit, harga) VALUES (?, ?, ?)",
                       (item['label'], int(item['durasi']), int(item['harga'])))
    conn.commit()
    conn.close()

def save_bonus_to_db(bonus_list):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM bonus_rules")
    for item in bonus_list:
        cursor.execute("INSERT INTO bonus_rules (waktu_menit, bonus_menit) VALUES (?, ?)",
                       (int(item['waktu']), int(item['bonus'])))
    conn.commit()
    conn.close()

def save_cafe_menu_to_db(menu_list):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cafe_items")
    for item in menu_list:
        cursor.execute("INSERT INTO cafe_items (nama, harga) VALUES (?, ?)",
                       (item['nama'], int(item['harga'])))
    conn.commit()
    conn.close()

LAPORAN_FILE = "laporan_billing.csv"
NUM_TVS = 24
SESSION_STATE_FILE = "active_sessions.json"
SAVE_INTERVAL_SECONDS = 30
current_user = None

init_db() 

pygame.mixer.init()

def play_sound(file_name_only):
    try:
        full_path = os.path.join(sound_dir, file_name_only)
        pygame.mixer.Sound(full_path).play()
    except Exception as e:
        print(f"❌ Gagal play: {full_path}. Error: {e}")

PRESET_TIMES = load_presets_from_db()
TARIF_PER_JAM = load_tariffs_from_db()
paket_data = load_paket_from_db()
bonus_data = load_bonus_from_db()

def load_cafe_menu():
    return load_cafe_menu_from_db()

def save_cafe_menu(menu):
    save_cafe_menu_to_db(menu)

def load_users():
    return load_users_from_db()

def get_available_port():
    ports = serial.tools.list_ports.comports()
    for port in ports:
        return port.device
    return None

port = get_available_port()
if port is None:
    messagebox.showerror("Error Serial", "Tidak ada port serial terdeteksi. Pastikan perangkat terhubung.")
    exit()

ser = None
try:
    ser = serial.Serial(port, 115200, timeout=1)
    time.sleep(1.5)

    num_off_attempts = 3
    delay_between_attempts = 0.1
    delay_between_relays = 0.05

    print("Memulai proses mematikan relay awal...")
    for i in range(NUM_TVS):
        relay_successfully_turned_off = False
        for attempt in range(num_off_attempts):
            try:
                off_command = f"{i},0\n"
                ser.write(off_command.encode())
                time.sleep(delay_between_attempts)
                relay_successfully_turned_off = True
                break
            except serial.SerialException as write_e:
                print(f"    Attempt {attempt + 1} GAGAL (SerialException) kirim OFF ke relay {i}: {write_e}")
                ser.close()
                time.sleep(0.5)
                ser.open()
                time.sleep(0.5)
            except Exception as write_e_other:
                print(f"    Attempt {attempt + 1} GAGAL (Exception) kirim OFF ke relay {i}: {write_e_other}")
                time.sleep(0.5)
            
            if attempt == num_off_attempts - 1 and not relay_successfully_turned_off:
                 print(f"    PERINGATAN: Gagal mengirim perintah OFF ke relay {i} setelah {num_off_attempts} percobaan.")

        time.sleep(delay_between_relays)
    print("Selesai proses mematikan relay awal.")

except serial.SerialException as open_e:
    messagebox.showerror("Error Serial", f"Gagal membuka port serial {port}: {open_e}\nAplikasi akan keluar.")
    exit()
except Exception as open_e_other:
    messagebox.showerror("Error Serial", f"Terjadi error tidak diketahui saat membuka port serial: {open_e_other}\nAplikasi akan keluar.")
    exit()

relay_vars = []
relay_labels = []
tarif_labels = []
timer_threads = [None] * NUM_TVS
option_menus = []
stop_flags = [threading.Event() for _ in range(NUM_TVS)]
active_session_data = [None] * NUM_TVS
stop_resume_buttons = []
all_relay_frames = []

def send_command(relay, state):
    global ser
    try:
        command = f"{relay},{1 if state else 0}\n"
        ser.write(command.encode())
        if not state:
            stop_flags[relay].set()
    except serial.SerialException as e:
        print(f"Error sending command to relay {relay}: {e}. Attempting to reopen port.")
        try:
            if ser and ser.is_open:
                ser.close()
            ser = serial.Serial(port, 115200, timeout=1)
            time.sleep(0.5)
            ser.write(command.encode())
            print(f"Command resent successfully after reopening port.")
        except Exception as e_reopen:
            print(f"Failed to resend command after reopening port: {e_reopen}")
    except Exception as e_other:
        print(f"An unexpected error occurred sending command to relay {relay}: {e_other}")

def countdown_and_turn_off(relay, total_delay_seconds, label_widget, choice_name, calculated_cost, base_duration_seconds, log_this_session=True):
    global active_session_data, root, all_relay_frames

    def countdown():
        session_info_at_start = active_session_data[relay]
        start_time = session_info_at_start.get("start_time", datetime.datetime.now()) if session_info_at_start else datetime.datetime.now()
        initial_session_total_duration = session_info_at_start.get("original_total_delay", total_delay_seconds) if session_info_at_start else total_delay_seconds

        stop_flags[relay].clear()
        remaining = total_delay_seconds
        last_save_time = time.time()

        played_5_min_warning = False
        played_1_min_warning = False
        tv_number = relay + 1

        current_tv_frame = all_relay_frames[relay] if 0 <= relay < len(all_relay_frames) else None

        try:
            while remaining > 0:
                if stop_flags[relay].is_set():
                    break

                if initial_session_total_duration >= (5 * 60) and remaining <= (5 * 60) and not played_5_min_warning:
                    warning_file_to_play = f"warning{tv_number}.mp3"
                    if not os.path.exists(os.path.join(sound_dir, warning_file_to_play)):
                        warning_file_to_play = "warning.mp3"
                    play_sound(warning_file_to_play)
                    played_5_min_warning = True
                
                if remaining <= (1 * 60) and not played_1_min_warning:
                    play_sound("satu.mp3")
                    played_1_min_warning = True

                h, m, s = remaining // 3600, (remaining % 3600) // 60, remaining % 60
                time_str = f"{h:02}:{m:02}:{s:02}"
                safe_update_label(label_widget, time_str)

                current_time = time.time()
                if log_this_session and session_info_at_start and not session_info_at_start.get("is_stopwatch", False) and current_time - last_save_time >= SAVE_INTERVAL_SECONDS:
                    if active_session_data[relay]:
                        save_active_sessions()
                        last_save_time = current_time
                    else:
                        break
                
                time.sleep(1)
                remaining -= 1

            end_time = datetime.datetime.now()

            if not stop_flags[relay].is_set() and remaining <= 0:
                play_sound("stop.mp3")
                time.sleep(0.5)
                send_command(relay, False)
                
                if log_this_session:
                    cafe_orders_to_log_final = []
                    if 0 <= relay < len(all_relay_frames):
                        current_tv_frame = all_relay_frames[relay]
                        if hasattr(current_tv_frame, 'cafe_orders'):
                            cafe_orders_to_log_final = list(current_tv_frame.cafe_orders) # Salin list

                    log_session_to_report(tv_index=relay, start_time=start_time, end_time=end_time, 
                                          logged_duration_seconds=base_duration_seconds, 
                                          choice_name=choice_name, cost=calculated_cost,
                                          cafe_orders_list=cafe_orders_to_log_final)
                    if root:
                        root.after(0, clear_cafe_orders_for_tv, relay)
                else:
                    if choice_name == "FREE" and root:
                        root.after(0, clear_cafe_orders_for_tv, relay)

        except Exception as e:
            print(f"Error in countdown for TV {tv_number}: {e}")
        finally:
            if not stop_flags[relay].is_set() or remaining <= 0 :
                safe_update_label(label_widget, "00:00:00")
                active_session_data[relay] = None 
                save_active_sessions()
                if current_tv_frame: current_tv_frame.clear_session_color()
                if 0 <= relay < len(relay_vars) and root and relay_vars[relay].get() != "Pilih Waktu":
                    if not stop_flags[relay].is_set():
                        root.after(0, lambda r=relay: relay_vars[r].set("Pilih Waktu"))

    thread = threading.Thread(target=countdown, name=f"CountdownThread-TV{relay+1}")
    thread.daemon = True
    thread.start()
    timer_threads[relay] = thread

class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Login")
        self.geometry("250x250")
        self.iconbitmap(resource_path(os.path.join('pics', 'login.ico')))

        self.users_data = load_users_from_db()

        ctk.CTkLabel(self, text="Username").pack(pady=5)
        self.entry_username = ctk.CTkEntry(self)
        self.entry_username.pack(pady=5)

        ctk.CTkLabel(self, text="Password").pack(pady=5)
        self.entry_password = ctk.CTkEntry(self, show="*")
        self.entry_password.pack(pady=5)

        self.btn_login = ctk.CTkButton(self, text="Login", command=self.try_login)
        self.btn_login.pack(pady=20)
        
        self.entry_password.bind("<Return>", lambda event: self.try_login())

        self.login_result = None

    def try_login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        
        user_found = None
        for user_record in self.users_data:
            if user_record['username'] == username:
                user_found = user_record
                break
        
        if user_found:
            stored_hash = user_found['_password_hash']
            stored_salt = user_found['_salt']
            if verify_password(stored_hash, stored_salt, password):
                self.login_result = {"username": user_found["username"], "role": user_found["role"]}
                self.destroy()
                return
        tk.messagebox.showerror("Login Gagal", "Username atau Password salah!")
        self.entry_password.delete(0, tk.END)

class UserManagementWindow(ctk.CTkToplevel):
    def __init__(self, parent_root_window):
        super().__init__(parent_root_window)
        self.title("Manajemen User")
        self.geometry("380x320")
        try:
            self.iconbitmap(resource_path(os.path.join(pics_dir, 'user_icon.ico')))
        except tk.TclError:
            print(f"Icon user_icon.ico tidak ditemukan atau error: {pics_dir}")
        
        self.transient(parent_root_window)
        self.grab_set()

        self.users = load_users_from_db()

        self.frame = ctk.CTkScrollableFrame(self, label_text="Daftar User")
        self.frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.btn_add = ctk.CTkButton(self, text="TAMBAH User", command=self.add_user)
        self.btn_add.pack(pady=5)

        self.reload_users_display()

    def reload_users_display(self):
        self.users = load_users_from_db()
        for widget in self.frame.winfo_children():
            widget.destroy()
        for i, user in enumerate(self.users):

            user_frame = ctk.CTkFrame(self.frame)
            user_frame.pack(fill="x", pady=2)

            ctk.CTkLabel(user_frame, text=user['username'], width=120).pack(side="left", padx=5)
            ctk.CTkLabel(user_frame, text=user['role'], width=100).pack(side="left", padx=5)
            
            btn_edit = ctk.CTkButton(user_frame, text="EDIT", width=50, command=lambda u=user: self.edit_user(u))
            btn_edit.pack(side="left", padx=5)
            
            btn_del_state = tk.NORMAL if user['username'].lower() != 'admin' else tk.DISABLED
            btn_del = ctk.CTkButton(user_frame, text="DELETE", width=60, command=lambda uname=user['username']: self.delete_user(uname), state=btn_del_state)
            btn_del.pack(side="left", padx=5)
            
    def add_user(self):
        UserEditor(self, self.reload_users_display) 

    def edit_user(self, user_data_to_edit):
        if user_data_to_edit['username'].lower() == 'admin' and (current_user is None or current_user.get('username').lower() != 'admin'):
             tk.messagebox.showwarning("Akses Ditolak", "User 'admin' tidak dapat diubah oleh user lain.")
             return
        UserEditor(self, self.reload_users_display, user_data_to_edit)

    def delete_user(self, username_to_delete):
        if username_to_delete.lower() == 'admin':
            tk.messagebox.showwarning("Peringatan", "User 'admin' tidak dapat dihapus.")
            return
        if tk.messagebox.askyesno("Konfirmasi", f"Yakin hapus user '{username_to_delete}' ini?"):
            delete_user_from_db(username_to_delete)
            self.reload_users_display()


class UserEditor(ctk.CTkToplevel):
    def __init__(self, parent_management_window, reload_callback, user_to_edit=None): 
        super().__init__(parent_management_window)
        self.title("User Editor" if user_to_edit else "Tambah User Baru")
        self.geometry("300x400")
        self.reload_callback = reload_callback
        self.user_to_edit_original_username = user_to_edit['username'] if user_to_edit else None

        self.transient(parent_management_window)
        self.grab_set()

        ctk.CTkLabel(self, text="Username").pack(pady=5)
        self.entry_username = ctk.CTkEntry(self)
        self.entry_username.pack(pady=5)

        ctk.CTkLabel(self, text="Password").pack(pady=5)
        self.entry_password = ctk.CTkEntry(self, show="*")
        self.entry_password.pack(pady=5)
        
        ctk.CTkLabel(self, text="Konfirmasi Password").pack(pady=5)
        self.entry_password_confirm = ctk.CTkEntry(self, show="*")
        self.entry_password_confirm.pack(pady=5)

        ctk.CTkLabel(self, text="Role").pack(pady=5)
        self.combo_role = ctk.CTkOptionMenu(self, values=["Administrator", "Kasir"])
        self.combo_role.pack(pady=5)

        ctk.CTkButton(self, text="SIMPAN", command=self.save_user_data).pack(pady=20)

        if user_to_edit:
            self.entry_username.insert(0, user_to_edit['username'])
            self.entry_password.configure(placeholder_text="Masukkan password baru jika ingin diubah")
            self.entry_password_confirm.configure(placeholder_text="Konfirmasi password baru")
            self.combo_role.set(user_to_edit['role'])
            
            if user_to_edit['username'].lower() == 'admin' and user_to_edit['role'] == 'Administrator':
                self.combo_role.configure(state=tk.DISABLED, values=['Administrator'])
                self.combo_role.set('Administrator')

    def save_user_data(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get()
        password_confirm = self.entry_password_confirm.get()
        role = self.combo_role.get()

        if not username:
            tk.messagebox.showerror("Error", "Username wajib diisi!", parent=self)
            return
        
        if not self.user_to_edit_original_username or password:
            if not password:
                tk.messagebox.showerror("Error", "Password wajib diisi untuk user baru atau jika ingin diubah!", parent=self)
                return
            if password != password_confirm:
                tk.messagebox.showerror("Error", "Password dan Konfirmasi Password tidak cocok!", parent=self)
                return
        
        if self.user_to_edit_original_username:
            if not password:
                 tk.messagebox.showerror("Error", "Password wajib diisi kembali saat mengedit user.", parent=self)
                 return

            update_user_in_db(self.user_to_edit_original_username, username, password, role)
        else:
            save_user_to_db(username, password, role)
        
        self.reload_callback()
        self.destroy()

def save_active_sessions():
    global active_session_data, relay_labels
    sessions_to_save = {}
    current_time = time.time()

    for i in range(NUM_TVS):
        session_info = active_session_data[i]
        if session_info and timer_threads[i] and timer_threads[i].is_alive() and not stop_flags[i].is_set():
            try:
                if not session_info.get("is_stopwatch", False) and session_info.get("log_session", True):
                    remaining_str = relay_labels[i].cget("text")
                    remaining_seconds = parse_time_string_to_seconds(remaining_str)
                    
                    if remaining_seconds > 0:
                        data_to_save = session_info.copy()
                        data_to_save['remaining_seconds_at_save'] = remaining_seconds
                        data_to_save['last_saved_timestamp'] = current_time
                        
                        if 'start_time' in data_to_save and isinstance(data_to_save['start_time'], datetime.datetime):
                            data_to_save['start_time_iso'] = data_to_save['start_time'].isoformat()
                            del data_to_save['start_time']
                        
                        sessions_to_save[str(i)] = data_to_save
            except Exception as e:
                print(f"Error preparing session for TV {i+1} to save: {e}")
                pass 
    try:
        with open(SESSION_STATE_FILE, "w") as f:
            json.dump(sessions_to_save, f, indent=4)
    except Exception as e:
        print(f"Error writing active sessions to file: {e}")

def resume_session(index):
    global active_session_data, relay_labels, relay_vars, stop_resume_buttons

    session_info = active_session_data[index]
    if not session_info or not session_info.get("is_paused", False):
        return

    remaining_seconds = session_info.get("current_remaining_seconds", 0)
    if remaining_seconds <= 0:
        active_session_data[index] = None
        relay_labels[index].configure(text="00:00:00")
        relay_vars[index].set("Pilih Waktu")
        if index < len(stop_resume_buttons):
            btn = stop_resume_buttons[index]
            btn.configure(text="OFF", command=lambda i=index: handle_stop_or_cancel(i), fg_color="#ff5555", hover_color="#dd3333")
        send_command(index, False)
        save_active_sessions()
        return

    original_choice = session_info.get('original_choice', 'Unknown')
    original_cost = session_info.get('original_cost', 0)
    original_base_delay = session_info.get('original_base_delay', 0)
    log_session_flag = session_info.get('log_session', True)
    
    session_info["is_paused"] = False 

    send_command(index, True)

    if index < len(stop_resume_buttons):
        btn = stop_resume_buttons[index]
        btn.configure(text="OFF", command=lambda i=index: handle_stop_or_cancel(i), fg_color="#ff5555", hover_color="#dd3333")

    countdown_and_turn_off(relay=index, total_delay_seconds=remaining_seconds, 
                           label_widget=relay_labels[index], choice_name=original_choice, 
                           calculated_cost=original_cost, base_duration_seconds=original_base_delay, 
                           log_this_session=log_session_flag)

def handle_stop_or_cancel(index):
    """Menangani klik tombol OFF (jika running/paused) atau RESUME (jika paused dan diubah jadi RESUME)."""
    global active_session_data, relay_labels, relay_vars, stop_resume_buttons, stop_flags

    session_info = active_session_data[index]

    current_tv_frame = all_relay_frames[index] if 0 <= index < len(all_relay_frames) else None

    if session_info and session_info.get("is_paused", False):
        active_session_data[index] = None
        safe_update_label(relay_labels[index], "00:00:00")
        relay_vars[index].set("Pilih Waktu")
        if index < len(stop_resume_buttons):
            btn = stop_resume_buttons[index]
            btn.configure(text="OFF", command=lambda i=index: handle_stop_or_cancel(i), fg_color="#ff5555", hover_color="#dd3333")
        if current_tv_frame: current_tv_frame.clear_session_color()
        send_command(index, False)
        save_active_sessions()

    elif timer_threads[index] and timer_threads[index].is_alive():
        stop_flags[index].set()
        send_command(index, False)

    else:
        safe_update_label(relay_labels[index], "00:00:00")
        relay_vars[index].set("Pilih Waktu")
        active_session_data[index] = None
        if current_tv_frame: current_tv_frame.clear_session_color()
        send_command(index, False)
        if index < len(stop_resume_buttons):
             btn = stop_resume_buttons[index]
             btn.configure(text="OFF", command=lambda i=index: handle_stop_or_cancel(i), fg_color="#ff5555", hover_color="#dd3333")
        save_active_sessions()

def load_and_resume_sessions():
    global active_session_data, relay_labels, relay_vars, stop_resume_buttons, all_relay_frames, root

    load_time = time.time()
    if not os.path.exists(SESSION_STATE_FILE):
        return

    saved_sessions = {}
    try:
        with open(SESSION_STATE_FILE, "r") as f:
            saved_sessions = json.load(f)
    except Exception as e:
        print(f"Error loading saved sessions from {SESSION_STATE_FILE}: {e}")
        if os.path.exists(SESSION_STATE_FILE):
            try: os.remove(SESSION_STATE_FILE)
            except: pass
        return

    for index_str, saved_data in saved_sessions.items():
        try:
            index = int(index_str)
            if not (0 <= index < NUM_TVS): continue

            if not isinstance(saved_data, dict) or \
               "last_saved_timestamp" not in saved_data or \
               "remaining_seconds_at_save" not in saved_data or \
               "original_choice" not in saved_data:
                continue

            last_saved = saved_data.get("last_saved_timestamp", 0)
            remaining_at_save = saved_data.get("remaining_seconds_at_save", 0)
            
            time_passed_since_save = load_time - last_saved if last_saved > 0 else remaining_at_save + 1
            current_remaining = int(remaining_at_save - round(time_passed_since_save))

            if current_remaining > 0:
                resumed_session_info = saved_data.copy()
                resumed_session_info["is_paused"] = True
                resumed_session_info["current_remaining_seconds"] = current_remaining
                
                if 'start_time_iso' in resumed_session_info:
                    try:
                        resumed_session_info['start_time'] = datetime.datetime.fromisoformat(resumed_session_info['start_time_iso'])
                        del resumed_session_info['start_time_iso']
                    except ValueError:
                        original_total_delay = resumed_session_info.get("original_total_delay", current_remaining)
                        seconds_elapsed = original_total_delay - current_remaining
                        resumed_session_info['start_time'] = datetime.datetime.now() - datetime.timedelta(seconds=seconds_elapsed)
                else:
                    original_total_delay = resumed_session_info.get("original_total_delay", current_remaining)
                    seconds_elapsed = original_total_delay - current_remaining
                    resumed_session_info['start_time'] = datetime.datetime.now() - datetime.timedelta(seconds=seconds_elapsed)


                active_session_data[index] = resumed_session_info

                h, m, s = current_remaining // 3600, (current_remaining % 3600) // 60, current_remaining % 60
                time_str = f"{h:02}:{m:02}:{s:02}"
                safe_update_label(relay_labels[index], time_str)
                relay_vars[index].set(saved_data.get('original_choice', 'Unknown'))

                if 0 <= index < len(all_relay_frames):
                    tv_frame_to_update = all_relay_frames[index]
                    saved_cafe_orders = resumed_session_info.get("cafe_orders_for_session", [])
                    if hasattr(tv_frame_to_update, 'cafe_orders'):
                        tv_frame_to_update.cafe_orders = list(saved_cafe_orders)
                        if hasattr(tv_frame_to_update, 'update_cafe_label') and hasattr(tv_frame_to_update, 'update_frame_color_by_order'):
                            tv_frame_to_update.update_cafe_label()
                            tv_frame_to_update.update_frame_color_by_order()
                
                if index < len(stop_resume_buttons):
                    btn = stop_resume_buttons[index]
                    btn.configure(text="RESUME", command=lambda i=index: resume_session(i), fg_color="#FFA000", hover_color="#FF8F00")
            
            else:
                if saved_data.get("log_session", False):
                    start_time_dt = None
                    if 'start_time_iso' in saved_data:
                        try: start_time_dt = datetime.datetime.fromisoformat(saved_data['start_time_iso'])
                        except: pass
                    
                    base_duration = saved_data.get("original_base_delay", 0)
                    if start_time_dt is None:
                        start_time_dt = datetime.datetime.now() - datetime.timedelta(seconds=base_duration)
                    
                    end_time_dt = start_time_dt + datetime.timedelta(seconds=base_duration)
                    cafe_orders_for_overdue = saved_data.get("cafe_orders_for_session", [])

                    log_session_to_report(
                        tv_index=index,
                        start_time=start_time_dt,
                        end_time=end_time_dt,
                        logged_duration_seconds=base_duration,
                        choice_name=saved_data.get('original_choice', 'Overdue'),
                        cost=saved_data.get('original_cost', 0),
                        cafe_orders_list=cafe_orders_for_overdue
                    )
                
                if active_session_data[index] is None:
                    try:
                        safe_update_label(relay_labels[index], "00:00:00")
                        relay_vars[index].set("Pilih Waktu")
                        if index < len(stop_resume_buttons):
                            btn = stop_resume_buttons[index]
                            btn.configure(text="OFF", command=lambda i=index: handle_stop_or_cancel(i), fg_color="#ff5555", hover_color="#dd3333")
                        if 0 <= index < len(all_relay_frames):
                            tv_frame_to_clean = all_relay_frames[index]
                            if hasattr(tv_frame_to_clean, 'cafe_orders'):
                                tv_frame_to_clean.cafe_orders.clear()
                                if hasattr(tv_frame_to_clean, 'update_cafe_label') and hasattr(tv_frame_to_clean, 'update_frame_color_by_order'):
                                    tv_frame_to_clean.update_cafe_label()
                                    tv_frame_to_clean.update_frame_color_by_order()
                    except Exception as e_clean: print(f"Error cleaning up GUI for overdue TV {index+1}: {e_clean}")
        except ValueError:
            continue
        except Exception as e_outer:
            continue
            
    if os.path.exists(SESSION_STATE_FILE):
        try:
            os.remove(SESSION_STATE_FILE)
        except OSError as e_del:
            print(f"Warning: Could not delete session state file {SESSION_STATE_FILE}: {e_del}")

def safe_update_label(widget, new_text):
    global root
    try:
        if root and root.winfo_exists() and widget and widget.winfo_exists():
            root.after(0, lambda w=widget, t=new_text: w.configure(text=t))
    except Exception as e:
        pass

def on_closing():
    """Fungsi yang dipanggil saat jendela ditutup."""

    stopped_threads = 0
    for i in range(NUM_TVS):
        if timer_threads[i] and timer_threads[i].is_alive():
            stop_flags[i].set()
            stopped_threads += 1
    
    if stopped_threads > 0:
        time.sleep(0.1)

    save_active_sessions()

    if ser and ser.is_open:
        print("Turning off all relays before exit...")
        for i in range(NUM_TVS):
            try:
                off_command = f"{i},0\n"
                ser.write(off_command.encode())
                time.sleep(0.02)
            except Exception as e:
                print(f"Error sending OFF to relay {i} on close: {e}")
        ser.close()
        print("Serial port closed.")
    
    if root:
        root.destroy()

def log_session_to_report(tv_index, start_time, end_time, logged_duration_seconds, choice_name, cost, cafe_orders_list=None):
    """Menyimpan detail sesi yang selesai, termasuk pesanan kafe, ke database SQLite."""
    if cafe_orders_list is None: cafe_orders_list = []

    cafe_items_str = ""
    cafe_total_cost = 0
    if cafe_orders_list:
        cafe_items_str = "; ".join([order['nama'] for order in cafe_orders_list])
        cafe_total_cost = sum(order.get('harga',0) for order in cafe_orders_list)

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO laporan_billing 
            (tv_nama, tanggal, waktu_mulai, waktu_selesai, durasi_detik, biaya_rental, paket_pilihan, cafe_items, cafe_cost)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            f"TV {tv_index + 1}",
            start_time.strftime('%Y-%m-%d'),
            start_time.strftime('%H:%M:%S'),
            end_time.strftime('%H:%M:%S'),
            logged_duration_seconds,
            cost,
            choice_name,
            cafe_items_str,
            cafe_total_cost
        ))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error SQLite saat menyimpan laporan untuk TV {tv_index + 1}: {e}")
    except Exception as e_gen:
        print(f"Error umum saat menyimpan laporan untuk TV {tv_index + 1}: {e_gen}")
    finally:
        if conn:
            conn.close()

def round_up_to_nearest_500(cost):
    """Membulatkan biaya ke atas ke kelipatan 500 terdekat. 0 tetap 0."""
    if cost <= 0: return 0
    
    try:
        cost_num = float(cost)
    except (ValueError, TypeError):
        return 0

    rounded_cost = math.ceil(cost_num / 500.0) * 500
    return int(rounded_cost)

def calculate_tariff_cost(tv_index, duration_seconds):
    """Menghitung biaya berdasarkan tarif TV dan durasi, lalu membulatkannya."""
    global TARIF_PER_JAM
    raw_cost = 0
    try:
        tarif_key = f"Tarif {tv_index + 1}"
        tarif_per_hour = int(TARIF_PER_JAM.get(tarif_key, 0))
        
        if tarif_per_hour > 0 and duration_seconds > 0:
            raw_cost = math.ceil((duration_seconds / 3600.0) * tarif_per_hour)
        else:
            raw_cost = 0
    except (ValueError, TypeError, KeyError) as e:
        raw_cost = 0

    final_cost = round_up_to_nearest_500(raw_cost)
    return final_cost

def refresh_option_menus():
    global paket_data, PRESET_TIMES, option_menus, relay_vars
    
    preset_options = list(PRESET_TIMES.keys()) 
    paket_options = [item.get("label", "") for item in paket_data if item.get("label")]

    initial_added_options = ["ON", "FREE", "MOVE TO"]

    non_default_options = initial_added_options + preset_options + list(dict.fromkeys(paket_options))
    combined_options = ["Pilih Waktu"] + list(dict.fromkeys(non_default_options))

    for i, menu in enumerate(option_menus):
        if menu and menu.winfo_exists():
            current_value = relay_vars[i].get()
            menu.configure(values=combined_options)
            
            if current_value in combined_options:
                relay_vars[i].set(current_value)
            else:
                relay_vars[i].set("Pilih Waktu")

def refresh_tarif_display():
    global tarif_labels, TARIF_PER_JAM
    for i, lbl in enumerate(tarif_labels):
        if lbl and lbl.winfo_exists():
            key = f"Tarif {i+1}"
            val = TARIF_PER_JAM.get(key, 0)
            try:
                lbl.configure(text=f"Rp{int(val)}")
            except (ValueError, TypeError):
                lbl.configure(text="Rp0")

def parse_time_string_to_seconds(time_str):
    """Mengubah string format HH:MM:SS menjadi total detik."""
    try:
        parts = time_str.split(':')
        if len(parts) == 3:
            h = int(parts[0])
            m = int(parts[1])
            s = int(parts[2])
            return h * 3600 + m * 60 + s
        else:
            return 0 
    except (ValueError, IndexError, AttributeError):
        return 0

def stopwatch_and_wait_for_stop(relay, label_widget):
    global active_session_data, root, all_relay_frames

    def stopwatch():
        session_info_at_start = active_session_data[relay]
        start_time = session_info_at_start.get("start_time", datetime.datetime.now()) if session_info_at_start else datetime.datetime.now()

        stop_flags[relay].clear()
        elapsed_seconds = 0

        current_tv_frame = all_relay_frames[relay] if 0 <= relay < len(all_relay_frames) else None

        try:
            while True:
                if stop_flags[relay].is_set():
                    break

                h = elapsed_seconds // 3600
                m = (elapsed_seconds % 3600) // 60
                s = elapsed_seconds % 60
                time_str = f"{h:02}:{m:02}:{s:02}"
                safe_update_label(label_widget, time_str)

                time.sleep(1)
                elapsed_seconds += 1
            
            end_time = datetime.datetime.now()
            final_elapsed_seconds = elapsed_seconds -1
            if final_elapsed_seconds < 0: final_elapsed_seconds = 0

            cost = calculate_tariff_cost(relay, final_elapsed_seconds)

            cafe_orders_to_log_final_sw = []
            if 0 <= relay < len(all_relay_frames):
                current_tv_frame = all_relay_frames[relay]
                if hasattr(current_tv_frame, 'cafe_orders'):
                    cafe_orders_to_log_final_sw = list(current_tv_frame.cafe_orders)

            log_session_to_report(
                tv_index=relay, start_time=start_time, end_time=end_time,
                logged_duration_seconds=final_elapsed_seconds, 
                choice_name="ON", cost=cost,
                cafe_orders_list=cafe_orders_to_log_final_sw
            )
            if root:
                root.after(0, clear_cafe_orders_for_tv, relay)

        except Exception as e:
            print(f"Error in stopwatch for TV {relay+1}: {e}")
        finally:
            safe_update_label(label_widget, "00:00:00")
            active_session_data[relay] = None 
            save_active_sessions()
            if current_tv_frame: current_tv_frame.clear_session_color()
            if 0 <= relay < len(relay_vars) and root:
                 root.after(0, lambda r=relay: relay_vars[r].set("Pilih Waktu"))

    thread = threading.Thread(target=stopwatch, name=f"StopwatchThread-TV{relay+1}")
    thread.daemon = True
    thread.start()
    timer_threads[relay] = thread

def on_time_selected(choice, i, label_widget):
    global root, paket_data, bonus_data, PRESET_TIMES, TARIF_PER_JAM, active_session_data, all_relay_frames, relay_vars

    current_tv_frame = all_relay_frames[i] if 0 <= i < len(all_relay_frames) else None

    if choice == "Pilih Waktu":
        if timer_threads[i] and timer_threads[i].is_alive():
            stop_flags[i].set()
        send_command(i, False)
        safe_update_label(relay_labels[i], "00:00:00")
        active_session_data[i] = None
        if current_tv_frame: current_tv_frame.clear_session_color()
        return

    is_thread_currently_running = timer_threads[i] and timer_threads[i].is_alive()

    current_tv_frame_on_select = all_relay_frames[i] if 0 <= i < len(all_relay_frames) else None
    cafe_orders_at_session_start_for_save_resume = []
    if current_tv_frame_on_select and hasattr(current_tv_frame_on_select, 'cafe_orders'):
        cafe_orders_at_session_start_for_save_resume = list(current_tv_frame_on_select.cafe_orders)

    if choice == "MOVE TO":
        source_index = i
        session_info_raw = active_session_data[source_index]

        if session_info_raw is None or (not is_thread_currently_running and not session_info_raw.get("is_paused", False)):
            tk.messagebox.showinfo("Pindah Sesi", f"Tidak ada sesi aktif di TV {source_index + 1} untuk dipindahkan.", parent=root)
            if relay_vars[source_index].get() != "Pilih Waktu":
                relay_vars[source_index].set("Pilih Waktu")
            if not is_thread_currently_running:
                send_command(source_index, False)
            return

        session_data_for_move_window = session_info_raw.copy()

        if not session_data_for_move_window.get("is_paused", False) and is_thread_currently_running:
            try:
                current_time_str = relay_labels[source_index].cget("text")
                remaining_now = parse_time_string_to_seconds(current_time_str)
                session_data_for_move_window["current_remaining_seconds_on_move_init"] = remaining_now
            except Exception as e:
                session_data_for_move_window["current_remaining_seconds_on_move_init"] = session_data_for_move_window.get('original_total_delay', 0)
        
        try:
            move_window = MoveToWindow(master=root, source_index=source_index, session_data_copy=session_data_for_move_window)
            move_window.grab_set()
        except Exception as e:
            print(f"Error opening MoveToWindow: {e}")
            original_choice_before_move = session_info_raw.get("original_choice", "Pilih Waktu")
            relay_vars[source_index].set(original_choice_before_move)
        return

    if is_thread_currently_running:
        stop_flags[i].set()
        if timer_threads[i] is not None:
            timer_threads[i].join(timeout=0.2)
    
    active_session_data[i] = None
    if current_tv_frame: current_tv_frame.clear_session_color()

    if choice == "ON":
        send_command(i, True)
        active_session_data[i] = {
            "start_time": datetime.datetime.now(), "original_choice": "ON",
            "is_stopwatch": True, "log_session": True,
            "cafe_orders_for_session": cafe_orders_at_session_start_for_save_resume
        }
        if current_tv_frame: current_tv_frame.set_session_color(COLOR_FRAME_SESSION_ON)
        stopwatch_and_wait_for_stop(i, label_widget)
        return

    elif choice == "FREE":
        free_duration_seconds = 300
        send_command(i, True)
        active_session_data[i] = {
            "start_time": datetime.datetime.now(), "original_choice": "FREE",
            "is_stopwatch": False, "original_total_delay": free_duration_seconds,
            "original_base_delay": free_duration_seconds, "original_cost": 0,
            "log_session": False,
            "cafe_orders_for_session": cafe_orders_at_session_start_for_save_resume
        }
        if current_tv_frame: current_tv_frame.clear_session_color()
        countdown_and_turn_off(
            relay=i, total_delay_seconds=free_duration_seconds, label_widget=label_widget,
            choice_name="FREE", calculated_cost=0, base_duration_seconds=free_duration_seconds,
            log_this_session=False
        )
        return
    
    else:
        base_delay_seconds = 0
        chosen_duration_minutes = 0
        is_paket = False
        paket_harga = 0

        if choice in PRESET_TIMES:
            base_delay_seconds = PRESET_TIMES[choice]
            chosen_duration_minutes = base_delay_seconds // 60
        else:
            found_in_paket = False
            for paket_item in paket_data:
                if paket_item.get("label") == choice:
                    try:
                        chosen_duration_minutes = int(paket_item.get("durasi", 0))
                        base_delay_seconds = chosen_duration_minutes * 60
                        paket_harga = int(paket_item.get("harga", 0))
                        is_paket = True
                        found_in_paket = True
                        break 
                    except (ValueError, TypeError, KeyError) as e:
                        if 0 <= i < len(relay_vars): relay_vars[i].set("Pilih Waktu")
                        send_command(i, False)
                        if current_tv_frame: current_tv_frame.clear_session_color()
                        return
            
            if not found_in_paket:
                if 0 <= i < len(relay_vars): relay_vars[i].set("Pilih Waktu")
                send_command(i, False)
                return

        if chosen_duration_minutes <= 0 and base_delay_seconds <= 0:
            if 0 <= i < len(relay_vars): relay_vars[i].set("Pilih Waktu")
            send_command(i, False)
            if current_tv_frame: current_tv_frame.clear_session_color()
            return

        applicable_bonus_minutes = 0
        if not is_paket:
            best_match_threshold_minutes = -1
            for rule in bonus_data:
                try:
                    rule_threshold_str = str(rule.get('waktu', ''))
                    rule_bonus_str = str(rule.get('bonus', ''))
                    
                    if rule_threshold_str.isdigit() and rule_bonus_str.isdigit():
                        rule_threshold_minutes = int(rule_threshold_str)
                        rule_bonus_amount_minutes = int(rule_bonus_str)
                        
                        if chosen_duration_minutes >= rule_threshold_minutes and rule_threshold_minutes > best_match_threshold_minutes:
                            applicable_bonus_minutes = rule_bonus_amount_minutes
                            best_match_threshold_minutes = rule_threshold_minutes
                except Exception as e_bonus:
                    print(f"Error processing bonus rule {rule}: {e_bonus}")
                    continue

        bonus_delay_seconds = applicable_bonus_minutes * 60
        total_delay_seconds = base_delay_seconds + bonus_delay_seconds

        calculated_cost = paket_harga if is_paket else calculate_tariff_cost(i, base_delay_seconds)

        if total_delay_seconds > 0:
            session_info = {
                "start_time": datetime.datetime.now(), "original_choice": choice,
                "is_stopwatch": False, "original_total_delay": total_delay_seconds,
                "original_base_delay": base_delay_seconds,
                "original_cost": calculated_cost,
                "log_session": True,
                "cafe_orders_for_session": cafe_orders_at_session_start_for_save_resume
            }
            active_session_data[i] = session_info
            send_command(i, True)
            if current_tv_frame: current_tv_frame.set_session_color(COLOR_FRAME_SESSION_PRESET)
            
            countdown_and_turn_off(
                relay=i, total_delay_seconds=total_delay_seconds, label_widget=label_widget,
                choice_name=choice, calculated_cost=calculated_cost,
                base_duration_seconds=base_delay_seconds,
                log_this_session=True
            )
        else:
            label_widget.configure(text="00:00:00")
            send_command(i, False)
            active_session_data[i] = None
            if 0 <= i < len(relay_vars): relay_vars[i].set("Pilih Waktu")
            if current_tv_frame: current_tv_frame.clear_session_color()

class CafeWindow(ctk.CTkToplevel):
    def __init__(self, parent_root_window):
        super().__init__(parent_root_window)
        self.title("Pengaturan Menu Kafe")
        self.geometry("380x500")
        try:
            self.iconbitmap(resource_path(os.path.join(pics_dir, 'cafe_icon.ico')))
        except tk.TclError:
            print(f"Icon cafe_icon.ico tidak ditemukan atau error: {pics_dir}")

        self.transient(parent_root_window)
        self.grab_set() 

        self.menu_data_from_db = load_cafe_menu_from_db()

        self.frame_scroll = ctk.CTkScrollableFrame(self, label_text="🍽️ Daftar Menu Kafe")
        self.frame_scroll.pack(fill="both", expand=True, padx=10, pady=10)

        self.entries_ui = []
        self._populate_menu_entries()

        btn_add = ctk.CTkButton(self, text="Tambah Menu Baru", command=lambda: self._add_menu_entry_ui("", ""))
        btn_add.pack(pady=(5,2))

        btn_save = ctk.CTkButton(self, text="SIMPAN SEMUA PERUBAHAN MENU", command=self.save_menu_to_storage)
        btn_save.pack(pady=(2,10))
        
        self.protocol("WM_DELETE_WINDOW", self.on_cafe_window_close)

    def _populate_menu_entries(self):
        for widget in self.frame_scroll.winfo_children():
            widget.destroy()
        self.entries_ui = []
        
        for item_db in self.menu_data_from_db: 
            self._add_menu_entry_ui(item_db['nama'], str(item_db['harga']))

    def _add_menu_entry_ui(self, nama_val="", harga_val=""):
        entry_frame = ctk.CTkFrame(self.frame_scroll)
        entry_frame.pack(fill="x", pady=2)

        entry_nama = ctk.CTkEntry(entry_frame, width=180, placeholder_text="Nama Item")
        entry_nama.insert(0, nama_val)
        entry_nama.pack(side="left", padx=(5,2))

        entry_harga = ctk.CTkEntry(entry_frame, width=80, placeholder_text="Harga")
        entry_harga.insert(0, harga_val)
        entry_harga.pack(side="left", padx=(2,5))

        btn_del = ctk.CTkButton(entry_frame, text="Hapus", width=60, fg_color="tomato",
                                command=lambda frame_to_remove=entry_frame: self._remove_menu_entry_ui(frame_to_remove))
        btn_del.pack(side="right", padx=5)

        self.entries_ui.append({'frame': entry_frame, 'nama_entry': entry_nama, 'harga_entry': entry_harga})

    def _remove_menu_entry_ui(self, frame_to_remove):
        self.entries_ui = [e for e in self.entries_ui if e['frame'] != frame_to_remove]
        frame_to_remove.destroy()

    def save_menu_to_storage(self):
        updated_menu_list = []
        valid_data = True
        for entry_ui_dict in self.entries_ui:
            nama = entry_ui_dict['nama_entry'].get().strip()
            harga_str = entry_ui_dict['harga_entry'].get().strip()

            if nama and harga_str:
                if harga_str.isdigit():
                    updated_menu_list.append({"nama": nama, "harga": int(harga_str)})
                else:
                    messagebox.showerror("Input Salah", f"Harga untuk '{nama}' harus berupa angka.", parent=self)
                    valid_data = False
                    break
            elif nama or harga_str :
                 messagebox.showwarning("Input Kurang", f"Nama dan Harga harus diisi untuk item '{nama or harga_str}'. Item ini tidak akan disimpan.", parent=self)
        
        if valid_data:
            save_cafe_menu_to_db(updated_menu_list)
            self.menu_data_from_db = updated_menu_list
            messagebox.showinfo("Disimpan", "Menu kafe berhasil disimpan ke database.", parent=self)
            self.destroy()
    
    def on_cafe_window_close(self):
        self.destroy()

class OrderWindow(ctk.CTkToplevel):
    def __init__(self, parent_root_window, main_tv_frame): 
        super().__init__(parent_root_window)
        self.main_tv_frame = main_tv_frame 
        self.title(f"Order Kafe untuk {main_tv_frame.nama}") 
        self.geometry("280x400") 

        self.transient(parent_root_window)
        self.grab_set()

        self.menu_available = load_cafe_menu_from_db()
        self.selected_items_to_order = []

        self.frame_scroll_order = ctk.CTkScrollableFrame(self, label_text="🍽️ Pilih Menu untuk Dipesan")
        self.frame_scroll_order.pack(fill="both", expand=True, padx=10, pady=10)

        self.checkbox_vars_map = {}
        if not self.menu_available:
            ctk.CTkLabel(self.frame_scroll_order, text="Menu kafe kosong.\nSilakan atur di Setting.").pack(pady=20)
        else:
            for item in self.menu_available:
                item_name = item['nama']
                item_price = item['harga']
                var = ctk.BooleanVar()
                
                for existing_order in self.main_tv_frame.cafe_orders:
                    if existing_order['nama'] == item_name:
                        var.set(True)
                        break

                chk = ctk.CTkCheckBox(self.frame_scroll_order, 
                                      text=f"{item_name} - Rp {item_price:,}".replace(",","."), 
                                      variable=var)
                chk.pack(anchor="w", padx=5, pady=3)
                self.checkbox_vars_map[item_name] = (var, item_price)

        btn_order_action = ctk.CTkButton(self, text="TAMBAHKAN PESANAN", command=self.process_order)
        btn_order_action.pack(pady=10)

    def process_order(self):
        newly_selected_for_this_instance = []
        for item_name, (var, price) in self.checkbox_vars_map.items():
            if var.get():
                newly_selected_for_this_instance.append({"nama": item_name, "harga": price})
        
        self.main_tv_frame.cafe_orders.clear()
        for item_to_add in newly_selected_for_this_instance:
            self.main_tv_frame.cafe_orders.append(item_to_add)
        
        if newly_selected_for_this_instance:
             play_sound("ding.mp3")

        if hasattr(self.main_tv_frame, 'update_cafe_label'):
            self.main_tv_frame.update_cafe_label()
        if hasattr(self.main_tv_frame, 'update_frame_color_by_order'):
            self.main_tv_frame.update_frame_color_by_order()
            
        if active_session_data[self.main_tv_frame.tv_index]:
            active_session_data[self.main_tv_frame.tv_index]["cafe_orders_for_session"] = list(self.main_tv_frame.cafe_orders)
            save_active_sessions()

        self.destroy()

def clear_cafe_orders_for_tv(tv_index):
    global all_relay_frames, root
    if 0 <= tv_index < len(all_relay_frames):
        frame_tv = all_relay_frames[tv_index]
        if hasattr(frame_tv, 'cafe_orders') and \
           hasattr(frame_tv, 'update_cafe_label') and \
           hasattr(frame_tv, 'update_frame_color_by_order'):
            
            frame_tv.cafe_orders.clear()
            frame_tv.update_cafe_label() 
            frame_tv.update_frame_color_by_order()

class MoveToWindow(ctk.CTkToplevel):
    def __init__(self, master, source_index, session_data_copy):
        super().__init__(master)
        self.master_window = master
        self.source_index = source_index
        self.source_tv_num = source_index + 1
        self.session_snapshot = session_data_copy       
        self.title(f"Pindah Sesi dari TV {self.source_tv_num}")
        self.geometry("450x350")
        self.original_source_choice_on_menu = relay_vars[self.source_index].get() 

        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        title_label = ctk.CTkLabel(main_frame, text=f"Pilih TV Tujuan untuk Sesi dari TV {self.source_tv_num}:", font=ctk.CTkFont(size=14, weight="bold"))
        title_label.pack(pady=(5, 15))

        dest_button_frame = ctk.CTkFrame(main_frame)
        dest_button_frame.pack(fill="both", expand=True)

        tv_found = False
        cols = 5
        idle_tv_count = 0
        for dest_index in range(NUM_TVS):
            if dest_index != self.source_index and active_session_data[dest_index] is None:
                tv_found = True
                row = idle_tv_count // cols
                col = idle_tv_count % cols
                dest_button_frame.grid_columnconfigure(col, weight=1)
                btn = ctk.CTkButton(dest_button_frame, text=f"TV {dest_index + 1}", height=40, command=lambda d_idx=dest_index: self.confirm_and_select_destination(d_idx))
                btn.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
                idle_tv_count += 1

        if not tv_found:
            no_tv_label = ctk.CTkLabel(dest_button_frame, text="Tidak ada TV tujuan yang tersedia (idle).", text_color="orange")
            no_tv_label.pack(pady=20)

        cancel_button = ctk.CTkButton(main_frame, text="BATAL PINDAH", command=self.cancel_move_action, fg_color="gray")
        cancel_button.pack(pady=(10, 5), side="bottom")

        self.protocol("WM_DELETE_WINDOW", self.cancel_move_action)

        self.remaining_seconds_at_move_initiation = 0
        if self.session_snapshot.get("is_paused", False):
            self.remaining_seconds_at_move_initiation = self.session_snapshot.get("current_remaining_seconds", 0)
        elif timer_threads[self.source_index] and timer_threads[self.source_index].is_alive():
            try:
                source_label_widget = relay_labels[self.source_index]
                time_str = source_label_widget.cget("text")
                self.remaining_seconds_at_move_initiation = parse_time_string_to_seconds(time_str)
            except Exception:
                self.remaining_seconds_at_move_initiation = self.session_snapshot.get('original_total_delay', 0)
        else:
            self.remaining_seconds_at_move_initiation = 0

    def confirm_and_select_destination(self, destination_index):
        current_remaining_for_move = 0
        source_session_info = active_session_data[self.source_index]

        if source_session_info and source_session_info.get("is_paused"):
            current_remaining_for_move = source_session_info.get("current_remaining_seconds", 0)
        elif timer_threads[self.source_index] and timer_threads[self.source_index].is_alive():
            try:
                current_remaining_for_move = parse_time_string_to_seconds(relay_labels[self.source_index].cget("text"))
            except:
                current_remaining_for_move = self.remaining_seconds_at_move_initiation 
        else:
             tk.messagebox.showwarning("Pindah Gagal", f"Sesi di TV {self.source_tv_num} sudah tidak aktif.", parent=self)
             self.cancel_move_action()
             return

        if current_remaining_for_move <= 0:
            tk.messagebox.showinfo("Pindah Info", f"Tidak ada waktu tersisa di TV {self.source_tv_num} untuk dipindahkan.", parent=self)
            handle_stop_or_cancel(self.source_index)
            self.cancel_move_action()
            return

        if messagebox.askyesno("Konfirmasi Pindah", 
                               f"Pindahkan sesi dari TV {self.source_tv_num} ke TV {destination_index + 1} dengan sisa waktu sekitar {current_remaining_for_move // 60} menit?",
                               parent=self):
            
            data_to_actually_move = self.session_snapshot.copy()
            if "is_paused" in data_to_actually_move: del data_to_actually_move["is_paused"]
            if "current_remaining_seconds" in data_to_actually_move: del data_to_actually_move["current_remaining_seconds"]
            
            success = perform_move_session_logic(self.source_index, destination_index, 
                                                 data_to_actually_move, current_remaining_for_move)
            if success:
                self.destroy()
            else:
                relay_vars[self.source_index].set(self.original_source_choice_on_menu)

    def cancel_move_action(self):
        try:
            if 0 <= self.source_index < len(relay_vars):
                relay_vars[self.source_index].set(self.original_source_choice_on_menu)
        except Exception as e:
            pass
        self.destroy()

def perform_move_session_logic(source_idx, dest_idx, session_data_base, actual_remaining_seconds):
    """Fungsi inti untuk logika pemindahan sesi."""
    global active_session_data, relay_labels, stop_flags, relay_vars, all_relay_frames

    source_tv_frame = all_relay_frames[source_idx] if 0 <= source_idx < len(all_relay_frames) else None
    dest_tv_frame = all_relay_frames[dest_idx] if 0 <= dest_idx < len(all_relay_frames) else None

    if not isinstance(session_data_base, dict) or not session_data_base:
         try:
             relay_vars[source_idx].set("Pilih Waktu"); send_command(source_idx, False)
         except: pass
         messagebox.showerror("Pindah Gagal", "Data sesi sumber tidak valid.", parent=root)
         return False

    if active_session_data[dest_idx] is not None:
        messagebox.showwarning("Pindah Gagal", f"TV {dest_idx + 1} sudah tidak idle. Pilih TV lain.", parent=root)
        return False

    if actual_remaining_seconds <= 0:
         messagebox.showinfo("Pindah Info", f"Tidak ada waktu tersisa di TV {source_idx + 1} untuk dipindahkan.", parent=root)
         handle_stop_or_cancel(source_idx)
         return False

    stop_flags[source_idx].set()
    time.sleep(0.05)
    send_command(source_idx, False)
    safe_update_label(relay_labels[source_idx], "00:00:00")
    relay_vars[source_idx].set("Pilih Waktu")
    active_session_data[source_idx] = None
    if source_tv_frame: source_tv_frame.clear_session_color()
    
    moved_cafe_orders = []
    source_frame = all_relay_frames[source_idx] if 0 <= source_idx < len(all_relay_frames) else None
    if source_frame and hasattr(source_frame, 'cafe_orders'):
        moved_cafe_orders = list(source_frame.cafe_orders)
        source_frame.cafe_orders.clear()
        if hasattr(source_frame, 'update_cafe_label') and hasattr(source_frame, 'update_frame_color_by_order'):
            source_frame.update_cafe_label()
            source_frame.update_frame_color_by_order()

    session_data_for_dest = session_data_base.copy()
    session_data_for_dest["cafe_orders_for_session"] = moved_cafe_orders
    session_data_for_dest["start_time"] = datetime.datetime.now()
    if "is_paused" in session_data_for_dest: del session_data_for_dest["is_paused"]
    if "current_remaining_seconds" in session_data_for_dest: del session_data_for_dest["current_remaining_seconds"]
    if "current_remaining_seconds_on_move_init" in session_data_for_dest: del session_data_for_dest["current_remaining_seconds_on_move_init"]

    dest_frame = all_relay_frames[dest_idx] if 0 <= dest_idx < len(all_relay_frames) else None
    if dest_frame and hasattr(dest_frame, 'cafe_orders'):
        dest_frame.cafe_orders = list(moved_cafe_orders)
        if hasattr(dest_frame, 'update_cafe_label') and hasattr(dest_frame, 'update_frame_color_by_order'):
            dest_frame.update_cafe_label()
            dest_frame.update_frame_color_by_order()

    send_command(dest_idx, True)
    
    original_choice_moved = session_data_for_dest.get('original_choice', 'Moved Session')
    original_cost_moved = session_data_for_dest.get('original_cost', 0)
    original_base_delay_moved = session_data_for_dest.get('original_base_delay', actual_remaining_seconds)
    log_session_flag_moved = session_data_for_dest.get('log_session', True)

    relay_vars[dest_idx].set(original_choice_moved)
    active_session_data[dest_idx] = session_data_for_dest

    if original_choice_moved == "ON":
        if dest_tv_frame: dest_tv_frame.set_session_color(COLOR_FRAME_SESSION_ON)
    elif original_choice_moved != "FREE":
        if dest_tv_frame: dest_tv_frame.set_session_color(COLOR_FRAME_SESSION_PRESET)
    else:
        if dest_tv_frame: dest_tv_frame.clear_session_color()
    
    countdown_and_turn_off(
        relay=dest_idx,
        total_delay_seconds=actual_remaining_seconds,
        label_widget=relay_labels[dest_idx],
        choice_name=original_choice_moved,
        calculated_cost=original_cost_moved,
        base_duration_seconds=original_base_delay_moved,
        log_this_session=log_session_flag_moved
    )
    
    messagebox.showinfo("Pindah Berhasil", f"Sesi dari TV {source_idx+1} berhasil dipindah ke TV {dest_idx+1}.", parent=root)
    save_active_sessions()
    return True

class LaporanWindow(ctk.CTkToplevel):
    def __init__(self, master=None, user=None):
        super().__init__(master)
        self.title("Laporan Billing Rental")
        self.geometry("1150x650")
        try:
            self.iconbitmap(resource_path(os.path.join(pics_dir, 'laporan.ico')))
        except tk.TclError: print("Icon laporan.ico tidak dapat dimuat.")
        
        self.transient(master)
        self.grab_set()
        self.user = user

        self._build_ui_laporan()
        
        today_date = datetime.date.today()
        self.start_date_entry.set_date(today_date)
        self.end_date_entry.set_date(today_date)
        self._apply_filter_laporan()

    def _build_ui_laporan(self):
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        main_frame.rowconfigure(3, weight=1)
        main_frame.columnconfigure(0, weight=1)

        ctk.CTkLabel(main_frame, text="Riwayat Transaksi Billing", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, sticky="ew", pady=(5, 10))

        filter_frame = ctk.CTkFrame(main_frame)
        filter_frame.grid(row=1, column=0, sticky="ew", pady=(0, 5), padx=5)

        today = datetime.date.today()

        ctk.CTkLabel(filter_frame, text="Tanggal Mulai:").pack(side="left", padx=(5, 2), pady=5)
        self.start_date_entry = DateEntry(filter_frame, width=12, background='darkblue', foreground='white', borderwidth=2, date_pattern='y-mm-dd', maxdate=today)
        self.start_date_entry.pack(side="left", padx=(0, 10), pady=5)
        self.start_date_entry.set_date(today)

        ctk.CTkLabel(filter_frame, text="Tanggal Selesai:").pack(side="left", padx=(10, 2), pady=5)
        self.end_date_entry = DateEntry(filter_frame, width=12, background='darkblue', foreground='white', borderwidth=2, date_pattern='y-mm-dd', maxdate=today)
        self.end_date_entry.pack(side="left", padx=(0, 10), pady=5)
        self.end_date_entry.set_date(today)

        ctk.CTkButton(filter_frame, text="🔍 Filter Data", command=self._apply_filter_laporan).pack(side="left", padx=5, pady=5)
        ctk.CTkButton(filter_frame, text="📋 Tampilkan Semua", command=self._show_all_reports_laporan).pack(side="left", padx=5, pady=5)

        shortcut_frame = ctk.CTkFrame(main_frame)
        shortcut_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10), padx=5)

        for label, range_key in [
            ("Hari Ini", "today"), ("Kemarin", "yesterday"),
            ("Bulan Ini", "this_month"), ("Bulan Lalu", "last_month")
        ]:
            ctk.CTkButton(shortcut_frame, text=label, width=90,
                          command=lambda key=range_key: self._set_date_range_and_filter_laporan(key)).pack(
                side="left", padx=5, pady=2)

        table_frame = ctk.CTkFrame(main_frame)
        table_frame.grid(row=3, column=0, sticky="nsew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure("Treeview", background="#2A2D2E", foreground="white", fieldbackground="#343638", rowheight=25)
        style.configure("Treeview.Heading", background="#3C3F41", foreground="white", font=('Helvetica', 10, 'bold'))
        style.map("Treeview", background=[("selected", "#1F6AA5")])

        columns = ("No", "TV", "Tanggal", "Mulai", "Selesai", "Durasi", "Biaya", "Paket/Pilihan", "Cafe_Items", "Cafe_Cost")
        headings = {
            "No": "No", "TV": "TV", "Tanggal": "Tanggal", "Mulai": "Waktu Mulai", "Selesai": "Waktu Selesai",
            "Durasi": "Durasi (Menit)", "Biaya": "Biaya Rental (Rp)", "Paket/Pilihan": "Paket/Non", 
            "Cafe_Items": "Pesanan Kafe", "Cafe_Cost": "Total Kafe (Rp)"
        }
        widths = {
            "No": 35, "TV": 50, "Tanggal": 90, "Mulai": 80, "Selesai": 80, 
            "Durasi": 90, "Biaya": 120, "Paket/Pilihan": 120, "Cafe_Items": 180, "Cafe_Cost": 110
        }

        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=headings[col], anchor=tk.W)
            self.tree.column(col, width=widths[col], anchor=tk.W, stretch=(tk.YES if col not in ["No", "TV"] else tk.NO))

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky='ns')
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        hsb.grid(row=1, column=0, sticky='ew')
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')

        bottom_frame = ctk.CTkFrame(main_frame)
        bottom_frame.grid(row=4, column=0, sticky="ew", pady=(5, 0))

        self.btn_delete_laporan = ctk.CTkButton(bottom_frame, text="❌ Hapus Semua Laporan", 
                                                command=self.delete_all_reports_laporan, 
                                                fg_color="#D32F2F", hover_color="#B71C1C")
        self.btn_delete_laporan.pack(side="left", pady=5, padx=10)

        if self.user and self.user.get('role') != "Administrator":
            self.btn_delete_laporan.configure(state="disabled", command=self.show_access_denied_laporan)
        
        self.total_cafe_label = ctk.CTkLabel(bottom_frame, text="Total Kafe: Rp 0", font=ctk.CTkFont(size=12, weight="bold"))
        self.total_cafe_label.pack(side="right", pady=5, padx=10)
        self.total_rental_label = ctk.CTkLabel(bottom_frame, text="Total Rental: Rp 0", font=ctk.CTkFont(size=12, weight="bold"))
        self.total_rental_label.pack(side="right", pady=5, padx=5)

    def _apply_filter_laporan(self):
        start_date = self.start_date_entry.get_date()
        end_date = self.end_date_entry.get_date()
        if start_date > end_date:
            messagebox.showwarning("Filter Tanggal Salah", "Tanggal Mulai tidak boleh lebih besar dari Tanggal Selesai.", parent=self)
            return
        self.load_report_data_laporan(start_date_filter=start_date, end_date_filter=end_date)

    def _show_all_reports_laporan(self):
        self.load_report_data_laporan()
        today = datetime.date.today()
        self.start_date_entry.set_date(today.replace(day=1)) 
        self.end_date_entry.set_date(today)

    def _set_date_range_and_filter_laporan(self, preset_range):
        today = datetime.date.today()
        start_date, end_date = today, today

        if preset_range == "yesterday":
            start_date = end_date = today - datetime.timedelta(days=1)
        elif preset_range == "this_month":
            start_date = today.replace(day=1)
        elif preset_range == "last_month":
            last_month_end = today.replace(day=1) - datetime.timedelta(days=1)
            start_date = last_month_end.replace(day=1)
            end_date = last_month_end
        
        self.start_date_entry.set_date(start_date)
        self.end_date_entry.set_date(end_date)
        self._apply_filter_laporan()

    def load_report_data_laporan(self, start_date_filter=None, end_date_filter=None):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        total_biaya_rental = 0
        total_biaya_cafe = 0
        displayed_rows_count = 0

        query = "SELECT tv_nama, tanggal, waktu_mulai, waktu_selesai, durasi_detik, biaya_rental, paket_pilihan, cafe_items, cafe_cost FROM laporan_billing"
        conditions = []
        params = []

        if start_date_filter: 
            conditions.append("tanggal >= ?")
            params.append(start_date_filter.strftime('%Y-%m-%d'))
        if end_date_filter:
            conditions.append("tanggal <= ?")
            params.append(end_date_filter.strftime('%Y-%m-%d'))

        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY id DESC" 

        conn = None 
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            all_rows_from_db = cursor.fetchall()
            
            for row_data_tuple in all_rows_from_db:
                row_data = {
                    'TV': row_data_tuple[0], 'Tanggal': row_data_tuple[1], 'Mulai': row_data_tuple[2],
                    'Selesai': row_data_tuple[3], 'Durasi_Detik': row_data_tuple[4], 'Biaya': row_data_tuple[5],
                    'Paket/Pilihan': row_data_tuple[6], 'Cafe_Items': row_data_tuple[7], 'Cafe_Cost': row_data_tuple[8]
                }
                
                displayed_rows_count += 1
                durasi_detik_val = int(row_data.get('Durasi_Detik', 0))
                durasi_menit_display = math.ceil(durasi_detik_val / 60)
                
                biaya_rental_val = int(row_data.get('Biaya', 0))
                cafe_cost_val = int(row_data.get('Cafe_Cost', 0) or 0) 

                total_biaya_rental += biaya_rental_val
                total_biaya_cafe += cafe_cost_val

                self.tree.insert('', tk.END, values=(
                    displayed_rows_count,
                    row_data.get('TV', ''),
                    row_data.get('Tanggal', ''),
                    row_data.get('Mulai', ''),
                    row_data.get('Selesai', ''),
                    f"{durasi_menit_display} Menit",
                    f"Rp {biaya_rental_val:,}".replace(",", "."),
                    row_data.get('Paket/Pilihan', ''),
                    row_data.get('Cafe_Items', ''),
                    f"Rp {cafe_cost_val:,}".replace(",", ".")
                ))
        except sqlite3.Error as e:
            messagebox.showerror("Error Database", f"Tidak dapat membaca data laporan dari database: {e}", parent=self)
        except Exception as e_gen:
            messagebox.showerror("Error Umum", f"Terjadi error saat memuat laporan: {e_gen}", parent=self)
        finally:
            if conn:
                conn.close()

        self.total_rental_label.configure(text=f"Total Rental: Rp {total_biaya_rental:,}".replace(",", "."))
        self.total_cafe_label.configure(text=f"Total Kafe: Rp {total_biaya_cafe:,}".replace(",", "."))

    def delete_all_reports_laporan(self):
        if messagebox.askyesno("Konfirmasi Hapus", "YAKIN ingin menghapus SEMUA data laporan dari database? Tindakan ini TIDAK DAPAT DIBATALKAN.", icon='warning', parent=self):
            conn = None
            try:
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM laporan_billing")
                conn.commit()
                messagebox.showinfo("Laporan Dihapus", "Semua data laporan telah berhasil dihapus dari database.", parent=self)
            except sqlite3.Error as e:
                messagebox.showerror("Gagal Hapus", f"Tidak dapat menghapus data laporan dari database: {e}", parent=self)
            except Exception as e_gen:
                 messagebox.showerror("Error Umum", f"Terjadi error saat menghapus laporan: {e_gen}", parent=self)
            finally:
                if conn:
                    conn.close()
        
            today_date = datetime.date.today()
            self.start_date_entry.set_date(today_date)
            self.end_date_entry.set_date(today_date)
            self.load_report_data_laporan(start_date_filter=today_date, end_date_filter=today_date)

    def show_access_denied_laporan(self):
        tk.messagebox.showwarning("Akses Ditolak", "Anda tidak memiliki izin untuk melakukan tindakan ini.", parent=self)

def open_settings():
    settings_window = ctk.CTkToplevel(root)
    settings_window.title("PENGATURAN APLIKASI")
    settings_window.geometry("1400x650")
    settings_window.iconbitmap(resource_path(os.path.join(pics_dir, 'setting.ico')))
    settings_window.transient(root)
    settings_window.grab_set()

    container = ctk.CTkFrame(settings_window, corner_radius=15)
    container.pack(fill="both", expand=True, padx=15, pady=10)
    container.grid_columnconfigure((0, 1, 2, 3), weight=1)
    container.grid_rowconfigure(0, weight=1)
    
    waktu_frame_outer = ctk.CTkFrame(container, corner_radius=10)
    waktu_frame_outer.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=5)
    ctk.CTkLabel(waktu_frame_outer, text="🛠 Waktu Preset", font=("Helvetica", 14, "bold")).pack(pady=(10,5))

    time_list_scroll_frame = ctk.CTkScrollableFrame(waktu_frame_outer, width=250, height=200, corner_radius=10)
    time_list_scroll_frame.pack(pady=5, fill="both", expand=True, padx=10)
    
    preset_ui_entries = []

    def refresh_preset_time_list_ui():
        nonlocal preset_ui_entries
        for entry_dict in preset_ui_entries:
            if entry_dict['frame'].winfo_exists(): entry_dict['frame'].destroy()
        preset_ui_entries = []

        current_presets_for_ui = PRESET_TIMES.copy()

        for label, seconds in current_presets_for_ui.items():
            if label == "Pilih Waktu": continue
            add_single_preset_ui_entry(label, str(seconds // 60))
    
    def add_single_preset_ui_entry(label_val="", minutes_val=""):
        nonlocal preset_ui_entries
        row_frame = ctk.CTkFrame(time_list_scroll_frame)
        row_frame.pack(pady=2, padx=5, fill="x")
        
        label_e = ctk.CTkEntry(row_frame, width=120, placeholder_text="Label Waktu")
        if label_val: label_e.insert(0, label_val)
        label_e.pack(side="left", padx=2)
        
        minutes_e = ctk.CTkEntry(row_frame, width=60, placeholder_text="Menit")
        if minutes_val: minutes_e.insert(0, minutes_val)
        minutes_e.pack(side="left", padx=2)
        
        del_btn = ctk.CTkButton(row_frame, text="Hapus", width=25, fg_color="tomato", command=lambda rf=row_frame: remove_ui_entry_from_list(rf, preset_ui_entries))
        del_btn.pack(side="right", padx=2)
        preset_ui_entries.append({'frame': row_frame, 'label_entry': label_e, 'minutes_entry': minutes_e})

    refresh_preset_time_list_ui()

    ctk.CTkButton(waktu_frame_outer, text="Tambah Waktu Preset Baru", command=lambda: add_single_preset_ui_entry()).pack(pady=10)

    tarif_container_outer = ctk.CTkFrame(container, corner_radius=10)
    tarif_container_outer.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
    ctk.CTkLabel(tarif_container_outer, text="🪙 Tarif per Jam", font=("Helvetica", 14, "bold")).pack(pady=(10,5))

    global_tarif_frame = ctk.CTkFrame(tarif_container_outer, width=180, height=200)
    global_tarif_frame.pack(pady=5, fill="x", padx=10)
    ctk.CTkLabel(global_tarif_frame, text="Set Tarif Global (Rp):").pack(side="left", padx=5)
    global_tarif_entry_widget = ctk.CTkEntry(global_tarif_frame, width=80, placeholder_text="e.g. 5000")
    global_tarif_entry_widget.pack(side="left", padx=5)

    tarif_scroll_inner_frame = ctk.CTkScrollableFrame(tarif_container_outer, corner_radius=10, width=180, height=200)
    tarif_scroll_inner_frame.pack(pady=5, fill="both", expand=True, padx=10)
    
    tarif_ui_entries_widgets = []

    def set_global_tarif_action():
        value_str = global_tarif_entry_widget.get()
        if value_str.isdigit():
            val_int = int(value_str)
            for i in range(NUM_TVS):
                if i < len(tarif_ui_entries_widgets) and tarif_ui_entries_widgets[i].winfo_exists():
                    tarif_ui_entries_widgets[i].delete(0, tk.END)
                    tarif_ui_entries_widgets[i].insert(0, str(val_int))
        else:
            messagebox.showerror("Error", "Masukkan angka yang valid untuk tarif global.", parent=settings_window)
    
    ctk.CTkButton(global_tarif_frame, text="SET", command=set_global_tarif_action, width=50).pack(side="left", padx=5)

    for i in range(NUM_TVS):
        row_f = ctk.CTkFrame(tarif_scroll_inner_frame)
        row_f.pack(pady=2, padx=5, fill="x")
        ctk.CTkLabel(row_f, text=f"TV {i+1}: Rp", width=60, anchor="w").pack(side="left")
        entry_w = ctk.CTkEntry(row_f, width=100)
        entry_w.insert(0, str(TARIF_PER_JAM.get(f"Tarif {i+1}", 0))) 
        entry_w.pack(side="left", padx=5)
        tarif_ui_entries_widgets.append(entry_w)

    paket_frame_outer = ctk.CTkFrame(container, corner_radius=10)
    paket_frame_outer.grid(row=0, column=2, sticky="nsew", padx=(5,10), pady=5)
    ctk.CTkLabel(paket_frame_outer, text="📦 Paket Diskon", font=("Helvetica", 14, "bold")).pack(pady=(10,5))
    
    paket_list_scroll_frame = ctk.CTkScrollableFrame(paket_frame_outer, corner_radius=10, width=270, height=200)
    paket_list_scroll_frame.pack(pady=5, fill="both", expand=True, padx=10)

    paket_ui_entries = []

    def refresh_paket_list_ui():
        nonlocal paket_ui_entries
        for entry_dict in paket_ui_entries:
            if entry_dict['frame'].winfo_exists(): entry_dict['frame'].destroy()
        paket_ui_entries = []
        for item_db in paket_data:
            add_single_paket_ui_entry(item_db.get("label",""), str(item_db.get("durasi","")), str(item_db.get("harga","")))

    def add_single_paket_ui_entry(label_val="", durasi_val="", harga_val=""):
        nonlocal paket_ui_entries
        row_f = ctk.CTkFrame(paket_list_scroll_frame)
        row_f.pack(fill="x", pady=2, padx=5)

        label_e = ctk.CTkEntry(row_f, width=120, placeholder_text="Label Paket")
        if label_val: label_e.insert(0, label_val)
        label_e.pack(side="left", padx=2)

        durasi_e = ctk.CTkEntry(row_f, width=40, placeholder_text="Menit")
        if durasi_val: durasi_e.insert(0, durasi_val)
        durasi_e.pack(side="left", padx=2)

        harga_e = ctk.CTkEntry(row_f, width=50, placeholder_text="Harga (Rp)")
        if harga_val: harga_e.insert(0, harga_val)
        harga_e.pack(side="left", padx=2)

        del_btn = ctk.CTkButton(row_f, text="Hapus", width=25, fg_color="tomato", command=lambda rf=row_f: remove_ui_entry_from_list(rf, paket_ui_entries))
        del_btn.pack(side="right", padx=2)
        paket_ui_entries.append({'frame':row_f, 'label_e':label_e, 'durasi_e':durasi_e, 'harga_e':harga_e})
        
    refresh_paket_list_ui()
    ctk.CTkButton(paket_frame_outer, text="Tambah Paket Baru", command=lambda: add_single_paket_ui_entry()).pack(pady=10)

    bonus_frame_outer = ctk.CTkFrame(container, corner_radius=10, width=250, height=200)
    bonus_frame_outer.grid(row=0, column=3, sticky="nsew", padx=(5,10), pady=5)
    ctk.CTkLabel(bonus_frame_outer, text="🎁 Bonus Waktu", font=("Helvetica", 14, "bold")).pack(pady=(10,5))

    bonus_list_scroll_frame = ctk.CTkScrollableFrame(bonus_frame_outer, corner_radius=10, width=250, height=200)
    bonus_list_scroll_frame.pack(pady=5, fill="both", expand=True, padx=10)

    bonus_ui_entries = []
    
    def refresh_bonus_list_ui():
        nonlocal bonus_ui_entries
        for entry_dict in bonus_ui_entries:
            if entry_dict['frame'].winfo_exists(): entry_dict['frame'].destroy()
        bonus_ui_entries = []
        for item_db in bonus_data:
            add_single_bonus_ui_entry(str(item_db.get("waktu","")), str(item_db.get("bonus","")))

    def add_single_bonus_ui_entry(waktu_val="", bonus_val=""):
        nonlocal bonus_ui_entries
        row_f = ctk.CTkFrame(bonus_list_scroll_frame)
        row_f.pack(fill="x", pady=2, padx=5)

        ctk.CTkLabel(row_f, text="Waktu").pack(side="left")
        waktu_e = ctk.CTkEntry(row_f, width=50, placeholder_text="Menit")
        if waktu_val: waktu_e.insert(0, waktu_val)
        waktu_e.pack(side="left", padx=2)

        bonus_e = ctk.CTkEntry(row_f, width=50, placeholder_text="Menit")
        if bonus_val: bonus_e.insert(0, bonus_val)
        bonus_e.pack(side="left", padx=2)
        ctk.CTkLabel(row_f, text="Bonus").pack(side="left")

        del_btn = ctk.CTkButton(row_f, text="Hapus", width=25, fg_color="tomato", command=lambda rf=row_f: remove_ui_entry_from_list(rf, bonus_ui_entries))
        del_btn.pack(side="right", padx=5)
        bonus_ui_entries.append({'frame':row_f, 'waktu_e':waktu_e, 'bonus_e':bonus_e})

    refresh_bonus_list_ui()
    ctk.CTkButton(bonus_frame_outer, text="Tambah Aturan Bonus Baru", command=lambda: add_single_bonus_ui_entry()).pack(pady=10)
    
    def remove_ui_entry_from_list(frame_to_remove, list_of_ui_dicts):
        for i, entry_dict in enumerate(list_of_ui_dicts):
            if entry_dict['frame'] == frame_to_remove:
                if frame_to_remove.winfo_exists(): frame_to_remove.destroy()
                list_of_ui_dicts.pop(i)
                break
    
    ctk.CTkButton(settings_window, text="💾 SIMPAN SEMUA PENGATURAN KE DATABASE", 
                  command=lambda: save_all_settings_from_ui(
                                        settings_window, 
                                        preset_ui_entries, 
                                        tarif_ui_entries_widgets, 
                                        paket_ui_entries, 
                                        bonus_ui_entries), 
                  height=35, font=ctk.CTkFont(weight="bold")).pack(pady=(10,15), padx=10, fill="x")

def save_all_settings_from_ui(window_ref, preset_entries_ui, tarif_entries_ui, paket_entries_ui, bonus_entries_ui):
    global PRESET_TIMES, TARIF_PER_JAM, paket_data, bonus_data
    
    new_presets = {}
    valid_presets = True
    for preset_dict_ui in preset_entries_ui:
        label = preset_dict_ui['label_entry'].get().strip()
        minutes_str = preset_dict_ui['minutes_entry'].get().strip()
        if label and minutes_str:
            if minutes_str.isdigit() and int(minutes_str) > 0:
                new_presets[label] = int(minutes_str) * 60
            else:
                messagebox.showerror("Input Preset Salah", f"Menit untuk '{label}' harus angka positif.", parent=window_ref)
                valid_presets = False; break
    if not valid_presets: return
    save_presets_to_db(new_presets)
    PRESET_TIMES = new_presets

    new_tariffs = {}
    valid_tariffs = True
    for i, tarif_entry_widget_ui in enumerate(tarif_entries_ui):
        tarif_key = f"Tarif {i+1}"
        rate_str = tarif_entry_widget_ui.get().strip()
        if rate_str.isdigit():
            new_tariffs[tarif_key] = int(rate_str)
        else:
            messagebox.showerror("Input Tarif Salah", f"Tarif untuk TV {i+1} harus berupa angka.", parent=window_ref)
            valid_tariffs = False; break
    if not valid_tariffs: return
    save_tariffs_to_db(new_tariffs)
    TARIF_PER_JAM = new_tariffs

    new_paket_list = []
    valid_paket = True
    for paket_dict_ui in paket_entries_ui:
        label = paket_dict_ui['label_e'].get().strip()
        durasi_str = paket_dict_ui['durasi_e'].get().strip()
        harga_str = paket_dict_ui['harga_e'].get().strip()
        if label and durasi_str and harga_str:
            if durasi_str.isdigit() and int(durasi_str) > 0 and harga_str.isdigit() and int(harga_str) >= 0:
                new_paket_list.append({"label": label, "durasi": int(durasi_str), "harga": int(harga_str)})
            else:
                messagebox.showerror("Input Paket Salah", f"Durasi/Harga untuk paket '{label}' tidak valid.", parent=window_ref)
                valid_paket = False; break
    if not valid_paket: return
    save_paket_to_db(new_paket_list)
    paket_data = new_paket_list

    new_bonus_list = []
    valid_bonus = True
    for bonus_dict_ui in bonus_entries_ui:
        waktu_str = bonus_dict_ui['waktu_e'].get().strip()
        bonus_str = bonus_dict_ui['bonus_e'].get().strip()
        if waktu_str and bonus_str:
            if waktu_str.isdigit() and int(waktu_str) > 0 and bonus_str.isdigit() and int(bonus_str) >= 0:
                new_bonus_list.append({"waktu": int(waktu_str), "bonus": int(bonus_str)})
            else:
                messagebox.showerror("Input Bonus Salah", f"Menit minimal atau bonus untuk aturan '{waktu_str} menit' tidak valid.", parent=window_ref)
                valid_bonus = False; break
    if not valid_bonus: return
    save_bonus_to_db(new_bonus_list)
    bonus_data = new_bonus_list

    refresh_option_menus()
    refresh_tarif_display()
    
    messagebox.showinfo("Pengaturan Disimpan", "Semua pengaturan telah disimpan ke database.", parent=window_ref)
    window_ref.destroy()

COLOR_FRAME_SESSION_PRESET = "#3498db"
COLOR_FRAME_SESSION_ON = "#2ecc71"
COLOR_FRAME_CAFE_ORDER = "#e67e22"
_color_frame_idle_default_value = None

def start_app():
    global _color_frame_idle_default_value 
    global current_user, root, status_bar_label, stop_resume_buttons, all_relay_frames 

    login = LoginWindow()
    login.mainloop()

    if login.login_result:
        current_user = login.login_result
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue") 
        root = ctk.CTk(fg_color='#00284d')
        root.title("Billing Rental Playstation E2")
        root.attributes('-fullscreen', True)
        
        def toggle_fullscreen(event=None):
            is_fullscreen = root.attributes('-fullscreen')
            root.attributes('-fullscreen', not is_fullscreen)
            if not is_fullscreen:
                 root.geometry("1400x850")

        root.bind("<F11>", toggle_fullscreen)
        root.bind("<Escape>", toggle_fullscreen)

        try:
            root.iconbitmap(resource_path(os.path.join(pics_dir, 'title.ico')))
        except tk.TclError: print("Icon title.ico tidak dapat dimuat.")

        if _color_frame_idle_default_value is None: 
            temp_frame_for_color = ctk.CTkFrame(root) 
            _color_frame_idle_default_value = temp_frame_for_color.cget("fg_color")
            temp_frame_for_color.destroy()
            if not _color_frame_idle_default_value: 
                _color_frame_idle_default_value = "#2b2b2b"

        title_text_box = ctk.CTkTextbox(root, width=450, height=30, wrap="word", border_width=3, font=("Helvetica", 24, "bold"), activate_scrollbars=False)
        title_text_box.insert("1.0", "     BILLING RENTAL PLAYSTATION E2     ")
        title_text_box.configure(state="disabled") 
        title_text_box.pack(pady=15, padx=5, anchor="center") 
        title_text_box.configure(fg_color='#00284d') 

        status_bar_frame = ctk.CTkFrame(root, height=25, corner_radius=0)
        status_bar_frame.pack(side="bottom", fill="x", pady=(2,0), padx=0)
        status_bar_label = ctk.CTkLabel(status_bar_frame, text="F11: Fullscreen | Esc: Keluar Fullscreen", anchor="w", font=ctk.CTkFont(size=11))
        status_bar_label.pack(side="left", fill="x", padx=10, pady=2)
        
        top_status_frame = ctk.CTkFrame(root, fg_color="#00284d") 
        top_status_frame.pack(fill="x", padx=10, pady=(0, 5)) 

        left_status_frame = ctk.CTkFrame(top_status_frame, fg_color="#00284d")
        left_status_frame.pack(side="left", padx=10)
        ctk.CTkLabel(left_status_frame, text=f"Login sebagai: {current_user['username']} ({current_user['role']})", 
                     anchor="w", font=("Helvetica", 14, "bold")).pack(anchor="w")
        date_label_widget = ctk.CTkLabel(left_status_frame, text=datetime.datetime.now().strftime("%A, %d %B %Y"), 
                                     anchor="w", font=("Helvetica", 14, "bold")) 
        date_label_widget.pack(anchor="w")

        clock_label_widget = ctk.CTkLabel(top_status_frame, text="00:00:00", 
                                      anchor="e", font=("Helvetica", 16, "bold")) 
        clock_label_widget.pack(side="right", padx=10)

        def update_clock_and_date():
            now_time = datetime.datetime.now().strftime("%H:%M:%S")
            now_date = datetime.datetime.now().strftime("%A, %d %B %Y") 
            if clock_label_widget.winfo_exists(): clock_label_widget.configure(text=now_time)
            if date_label_widget.winfo_exists() and date_label_widget.cget("text") != now_date : 
                date_label_widget.configure(text=now_date) 
            if root.winfo_exists(): root.after(1000, update_clock_and_date) 

        update_clock_and_date() 

        center_frame_outer = ctk.CTkFrame(root, fg_color="#00284d") 
        center_frame_outer.pack(fill="both", expand=True)
        center_frame_outer.grid_rowconfigure(0, weight=1)
        center_frame_outer.grid_columnconfigure(0, weight=1)

        inner_frame_content = ctk.CTkFrame(center_frame_outer, fg_color="#00284d")
        inner_frame_content.grid(row=0, column=0) 
        
        side_nav_frame = ctk.CTkFrame(inner_frame_content, fg_color="#00284d", width=100) 
        side_nav_frame.grid(row=0, column=0, sticky="ns", padx=(0,10))
        side_nav_frame.grid_propagate(False) 

        def logout_app():
            for i in range(NUM_TVS):
                if timer_threads[i] and timer_threads[i].is_alive():
                    stop_flags[i].set()
            time.sleep(0.1) 
            save_active_sessions() 
            
            if ser and ser.is_open: 
                for i in range(NUM_TVS):
                    try: ser.write(f"{i},0\n".encode()) ; time.sleep(0.02)
                    except: pass
                ser.close()
            
            if root: root.destroy()
            sys.exit() 

        button_size = (60,60) 
        btn_setting = ctk.CTkButton(side_nav_frame, image=ctk.CTkImage(Image.open(resource_path("pics/setting.png")), size=button_size), text="", width=70, height=70, command=open_settings)
        btn_setting.pack(pady=10, padx=10)

        btn_laporan = ctk.CTkButton(side_nav_frame, image=ctk.CTkImage(Image.open(resource_path("pics/laporan.png")), size=button_size), text="", width=70, height=70, command=lambda: LaporanWindow(root, current_user))
        btn_laporan.pack(pady=10, padx=10)

        btn_cafe = ctk.CTkButton(side_nav_frame, image=ctk.CTkImage(Image.open(resource_path("pics/cafe_icon.png")), size=button_size), text="", width=70, height=70, command=lambda: CafeWindow(root))
        btn_cafe.pack(pady=10, padx=10)

        btn_user_mgmt = ctk.CTkButton(side_nav_frame, image=ctk.CTkImage(Image.open(resource_path("pics/user_icon.png")), size=button_size), text="", width=70, height=70, command=lambda: UserManagementWindow(root))
        btn_user_mgmt.pack(pady=10, padx=10)

        btn_logout_app = ctk.CTkButton(side_nav_frame, image=ctk.CTkImage(Image.open(resource_path("pics/login.png")), size=button_size), text="", width=70, height=70, command=logout_app)
        btn_logout_app.pack(pady=10, padx=10)
        
        main_tv_display_frame = ctk.CTkFrame(inner_frame_content, fg_color="#6e7070") 
        main_tv_display_frame.grid(row=0, column=1, sticky="nsew")

        if current_user['role'] != "Administrator":
            btn_setting.configure(state="disabled")
            btn_user_mgmt.configure(state="disabled")
            btn_cafe.configure(state="disabled")

        relay_vars.clear(); relay_labels.clear(); tarif_labels.clear()
        option_menus.clear(); stop_resume_buttons.clear(); all_relay_frames.clear()

        num_cols_tv = 8 
        tv_frame_width = 160
        tv_frame_height = 210 

        def _update_frame_color_logic_for_tv(frame_instance_ref):
            default_color = _color_frame_idle_default_value
            
            if frame_instance_ref.cafe_orders:
                frame_instance_ref.configure(fg_color=COLOR_FRAME_CAFE_ORDER)
            elif frame_instance_ref.current_session_type_color:
                frame_instance_ref.configure(fg_color=frame_instance_ref.current_session_type_color)
            else:
                frame_instance_ref.configure(fg_color=default_color)

        for i in range(NUM_TVS):
            row_idx = i // num_cols_tv
            col_idx = i % num_cols_tv

            relay_frame_instance = ctk.CTkFrame(main_tv_display_frame, width=tv_frame_width, height=tv_frame_height, border_color="#888888", border_width=2)
            relay_frame_instance.grid(row=row_idx, column=col_idx, padx=6, pady=5)
            relay_frame_instance.grid_propagate(False)
            all_relay_frames.append(relay_frame_instance)

            relay_frame_instance.original_fg_color = _color_frame_idle_default_value 
            
            relay_frame_instance.nama = f"TV {i+1}"
            relay_frame_instance.cafe_orders = []
            relay_frame_instance.tv_index = i
            relay_frame_instance.current_session_type_color = None
            
            def create_cafe_label_updater(frame_obj, logic_func):
                def updater():
                    total_items = len(frame_obj.cafe_orders)
                    if total_items > 0:
                        total_cost = sum(item.get('harga',0) for item in frame_obj.cafe_orders)
                        formatted_cost = f"{total_cost:,}".replace(",", ".")
                        if frame_obj.cafe_order_summary_label.winfo_exists():
                             frame_obj.cafe_order_summary_label.configure(text=f"Rp{formatted_cost} ({total_items} item)")
                    else:
                        if frame_obj.cafe_order_summary_label.winfo_exists():
                             frame_obj.cafe_order_summary_label.configure(text="")
                    logic_func(frame_obj)
                return updater

            def create_color_updater_proxy(frame_obj, logic_func):
                def updater():
                    logic_func(frame_obj)
                return updater

            def create_session_color_setter(frame_obj, logic_func):
                def setter(color_to_set):
                    setattr(frame_obj, 'current_session_type_color', color_to_set)
                    logic_func(frame_obj)
                return setter

            def create_session_color_clearer(frame_obj, logic_func):
                def clearer():
                    setattr(frame_obj, 'current_session_type_color', None)
                    logic_func(frame_obj)
                return clearer

            relay_frame_instance.update_cafe_label = create_cafe_label_updater(relay_frame_instance, _update_frame_color_logic_for_tv)
            relay_frame_instance.update_frame_color_by_order = create_color_updater_proxy(relay_frame_instance, _update_frame_color_logic_for_tv)
            relay_frame_instance.set_session_color = create_session_color_setter(relay_frame_instance, _update_frame_color_logic_for_tv)
            relay_frame_instance.clear_session_color = create_session_color_clearer(relay_frame_instance, _update_frame_color_logic_for_tv)
            
            header_row_frame = ctk.CTkFrame(relay_frame_instance) 
            header_row_frame.pack(pady=(8, 4), padx=5, fill="x") 

            tv_title_label = ctk.CTkLabel(header_row_frame, text=f"TV {i+1}", font=("Helvetica", 16, "bold"))
            tv_title_label.pack(side="left", padx=(10,0)) 

            current_tarif_label = ctk.CTkLabel(header_row_frame, text="Rp0", font=("Helvetica", 12)) 
            current_tarif_label.pack(side="right", padx=(0,10)) 
            tarif_labels.append(current_tarif_label)

            frame_timer_display_box = ctk.CTkFrame(relay_frame_instance, border_color="#888888", border_width=1)
            frame_timer_display_box.pack(pady=2, padx=5, fill="x")
            timer_countdown_label = ctk.CTkLabel(frame_timer_display_box, text="00:00:00", font=("Digital-7 Mono", 24, "bold")) 
            timer_countdown_label.pack(pady=1, padx=10) 
            relay_labels.append(timer_countdown_label)

            time_var = tk.StringVar(value="Pilih Waktu") 
            relay_vars.append(time_var)
            initial_menu_values = ["Pilih Waktu"] 
            time_option_menu = ctk.CTkOptionMenu(relay_frame_instance, variable=time_var, values=initial_menu_values, width=tv_frame_width-20, command=lambda choice, current_i=i, lbl=timer_countdown_label: on_time_selected(choice, current_i, lbl))
            time_option_menu.pack(pady=(3,2)) 
            option_menus.append(time_option_menu)
            
            cafe_summary_label_frame = ctk.CTkFrame(relay_frame_instance) 
            cafe_summary_label_frame.pack(pady=(1,1), padx=5, fill="x", ipady=0) 
            
            actual_cafe_summary_label = ctk.CTkLabel(cafe_summary_label_frame, text="", font=("Helvetica", 9, "italic"), anchor="w")
            actual_cafe_summary_label.pack(side="left", padx=5, pady=0) 
            relay_frame_instance.cafe_order_summary_label = actual_cafe_summary_label
            
            action_buttons_frame = ctk.CTkFrame(relay_frame_instance) 
            action_buttons_frame.pack(pady=(2,5), padx=5)

            order_btn = ctk.CTkButton(action_buttons_frame, text="ORDER", width=(tv_frame_width-30)//2, height=28, command=lambda current_rf=relay_frame_instance: OrderWindow(root, current_rf))
            order_btn.pack(side="left", padx=(0,5))

            stop_btn = ctk.CTkButton(action_buttons_frame, text="OFF", width=(tv_frame_width-30)//2, height=28, command=lambda current_i=i: handle_stop_or_cancel(current_i), fg_color="#ff5555", hover_color="#dd3333")
            stop_btn.pack(side="right", padx=(5,0))
            stop_resume_buttons.append(stop_btn)

            relay_frame_instance.update_cafe_label()

        refresh_tarif_display()
        refresh_option_menus()
        load_and_resume_sessions()
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()
    else:
        print("Login gagal atau dibatalkan. Aplikasi tidak dimulai.")

if __name__ == "__main__":
    start_app()
