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

# Oturum süresi ve oturum süresi sonlandırma
SESSION_TIMEOUT = 300  # 5 dakika
session_timer = None

# Günlük dosyası oluştur
import logging
logging.basicConfig(filename='password_manager.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def log_event(event):
    # Belirli bir olayı günlüğe kaydet
    logging.info(event)

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
    log_event(f"Password saved for user: {username}")

def update_password(username, old_password, new_password):
    if verify_password(username, old_password):
        save_password(username, new_password)
        messagebox.showinfo("Başarılı", "Parola başarıyla güncellendi.")
        log_event(f"Password updated for user: {username}")
    else:
        messagebox.showerror("Hata", "Eski parola doğrulanamadı. Parola güncellenemedi.")
        log_event(f"Failed to update password for user: {username} - Incorrect old password")

def verify_password(username, password):
    hashed_password = passwords.get(username)
    if hashed_password:
        # Kayıtlı parola varsa, girilen parola ile karşılaştıralım
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    else:
        return False

def generate_password_button_clicked():
    length = int(length_entry.get())
    generated_password = generate_password(length)
    generated_password_var.set(generated_password)

    # Parola analizi yapalım
    analysis = zxcvbn(generated_password)
    score = analysis['score']
    suggestions = analysis['feedback']['suggestions']

    if score < 3:
        messagebox.showwarning("Parola Zayıf", "Oluşturulan parola zayıf. Lütfen daha güçlü bir parola seçin.")
        messagebox.showinfo("Öneriler", "\n".join(suggestions))

def save_password_button_clicked():
    username = username_entry.get()
    password = password_entry.get()
    save_password(username, password)

def update_password_button_clicked():
    username = username_entry.get()
    old_password = old_password_entry.get()
    new_password = new_password_entry.get()
    update_password(username, old_password, new_password)

def login(username, password):
    if verify_password(username, password):
        return True
    else:
        return False

def login_button_clicked():
    username = username_entry.get()
    password = password_entry.get()
    if login(username, password):
        messagebox.showinfo("Başarılı", "Giriş başarılı.")
        log_event(f"Successful login for user: {username}")
        # Oturum başlatıldığında oturum süresi kontrolünü başlat
        start_session_timer()
    else:
        messagebox.showerror("Hata", "Kullanıcı adı veya parola hatalı.")
        log_event(f"Failed login attempt for user: {username}")

def logout_due_to_inactivity():
    # Belirli bir süre boyunca işlem yapılmazsa oturumu sonlandır
    messagebox.showinfo("Bilgi", "Oturum süreniz dolduğu için oturumunuz sonlandırıldı.")
    log_event("User logged out due to inactivity")
    end_session()

def end_session():
    # Oturumu sonlandır
    # Kullanıcı adı ve parola alanlarını temizle
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    # Oturum süresi kontrolünü durdur
    root.after_cancel(session_timer)

def start_session_timer():
    # Oturum süresi kontrolünü başlat
    global session_timer
    session_timer = root.after(SESSION_TIMEOUT * 1000, logout_due_to_inactivity)

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

# Giriş düğmesi
login_button = tk.Button(root, text="Giriş Yap", command=login_button_clicked)
login_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

root.mainloop()