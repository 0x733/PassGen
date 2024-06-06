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
    if verify_password(username, password):
        start_session(username)
        messagebox.showinfo("Başarılı Giriş", "Oturum başarıyla başlatıldı.")
    else:
        messagebox.showerror("Hata", "Kullanıcı adı veya parola hatalı.")

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

# Oturum açma düğmesi
login_button = tk.Button(root, text="Giriş Yap", command=login_button_clicked)
login_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

# Parola uzunluğu giriş alanı
length_label = tk.Label(root, text="Parola Uzunluğu:")
length_label.grid(row=3, column=0, padx=5, pady=5)
length_entry = tk.Entry(root)
length_entry.grid(row=3, column=1, padx=5, pady=5)

# Parola oluşturma düğmesi
generate_password_button = tk.Button(root, text="Parola Oluştur", command=generate_password_button_clicked)
generate_password_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

# Oluşturulan parola etiketi
generated_password_var = tk.StringVar()
generated_password_label = tk.Label(root, textvariable=generated_password_var)
generated_password_label.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

# Parola kaydetme düğmesi
save_password_button = tk.Button(root, text="Parolayı Kaydet", command=save_password_button_clicked)
save_password_button.grid(row=6, column=0, columnspan=2, padx=5, pady=5)

# Parola güncelleme düğmesi
update_password_button = tk.Button(root, text="Parolayı Güncelle", command=update_password_button_clicked)
update_password_button.grid(row=7, column=0, columnspan=2, padx=5, pady=5)

# Oturum süresi kontrolü
check_session()
root.mainloop()
