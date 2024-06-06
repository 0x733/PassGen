import tkinter as tk
from tkinter import messagebox
import random
import string
import bcrypt
from zxcvbn import zxcvbn
from datetime import datetime, timedelta

# Kullanıcıların parolalarını ve son parola değiştirme tarihlerini saklamak için bir sözlük oluşturalım
passwords = {}
last_password_change_dates = {}

# Oturum süresi (saniye cinsinden)
SESSION_TIMEOUT = 300  # Örneğin, 5 dakika

# Kullanıcı oturum başlangıç zamanını saklamak için bir sözlük oluşturalım
session_start_times = {}

# Kullanıcıların telefon numaralarını ve doğrulama kodlarını saklamak için bir sözlük oluşturalım
phone_numbers = {}
verification_codes = {}

def generate_password(length):
    # Parolayı oluştururken büyük harf, küçük harf, rakam ve özel karakter kullanalım
    chars = string.ascii_letters + string.digits + string.punctuation
    # Parolayı rastgele seçilen karakterlerle oluşturalım
    password = ''.join(random.choice(chars) for _ in range(length))
    return password

def hash_password(password):
    # Parolayı bcrypt ile hashleyelim
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password

def save_password(username, password):
    hashed_password = hash_password(password)
    passwords[username] = hashed_password
    last_password_change_dates[username] = datetime.now()
    messagebox.showinfo("Başarılı", "Parola başarıyla kaydedildi.")

def update_password(username, old_password, new_password):
    if verify_password(username, old_password):
        save_password(username, new_password)
        messagebox.showinfo("Başarılı", "Parola başarıyla güncellendi.")
    else:
        messagebox.showerror("Hata", "Eski parola doğrulanamadı. Parola güncellenemedi.")

def verify_password(username, password):
    hashed_password = passwords.get(username)
    if hashed_password:
        # Kayıtlı parola varsa, girilen parola ile karşılaştıralım
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    else:
        return False

def generate_verification_code():
    # Rastgele bir 6 haneli doğrulama kodu oluşturalım
    return ''.join(random.choices(string.digits, k=6))

def send_verification_code(phone_number, code):
    # Doğrulama kodunu kullanıcıya SMS ile göndermek için bir simülasyon yapabiliriz
    print(f"Telefon numarasına {phone_number} doğrulama kodu gönderildi: {code}")

def start_session(username):
    session_start_times[username] = datetime.now()

def end_session(username):
    session_start_times.pop(username, None)
    messagebox.showinfo("Oturum Sonlandı", "Oturum süreniz doldu. Lütfen tekrar giriş yapın.")

def check_session():
    current_time = datetime.now()
    for username, start_time in session_start_times.items():
        elapsed_time = current_time - start_time
        if elapsed_time.total_seconds() >= SESSION_TIMEOUT:
            end_session(username)
            break
    root.after(1000, check_session)

def login_button_clicked():
    username = username_entry.get()
    password = password_entry.get()
    verification_code = verification_code_entry.get()
    
    if verify_password(username, password):
        if verification_codes.get(username) == verification_code:
            start_session(username)
            messagebox.showinfo("Başarılı Giriş", "Oturum başarıyla başlatıldı.")
        else:
            messagebox.showerror("Hata", "Doğrulama kodu yanlış.")
    else:
        messagebox.showerror("Hata", "Kullanıcı adı veya parola hatalı.")

def request_verification_code_button_clicked():
    username = username_entry.get()
    phone_number = phone_number_entry.get()
    code = generate_verification_code()
    send_verification_code(phone_number, code)
    verification_codes[username] = code
    messagebox.showinfo("Başarılı", "Doğrulama kodu telefonunuza gönderildi.")

root = tk.Tk()
root.title("Parola Yöneticisi")

# Kullanıcı adı giriş alanı
username_label = tk.Label(root, text="Kullanıcı Adı:")
username_label.grid(row=0, column=0, padx=5, pady=5)
username_entry = tk.Entry(root)
username_entry.grid(row=0, column=1, padx=5, pady=5)

# Parola giriş alanı
password_label = tk.Label(root, text="Parola:")
password_label.grid(row=1, column=0, padx=5, pady=5)
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=1, column=1, padx=5, pady=5)

# Doğrulama kodu giriş alanı
verification_code_label = tk.Label(root, text="Doğrulama Kodu:")
verification_code_label.grid(row=2, column=0, padx=5, pady=5)
verification_code_entry = tk.Entry(root)
verification_code_entry.grid(row=2, column=1, padx=5, pady=5)

# Telefon numarası giriş alanı
phone_number_label = tk.Label(root, text="Telefon Numarası:")
phone_number_label.grid(row=3, column=0, padx=5, pady=5)
phone_number_entry = tk.Entry(root)
phone_number_entry.grid(row=3, column=1, padx=5, pady=5)

# Giriş yap düğmesi
login_button = tk.Button(root, text="Giriş Yap", command=login_button_clicked)
login_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

# Doğrulama kodu iste düğmesi
request_verification_code_button = tk.Button