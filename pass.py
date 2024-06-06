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

# Oturum süresi için varsayılan değeri tanımlayalım (saniye cinsinden)
DEFAULT_SESSION_TIMEOUT = 300  # 5 dakika

# Kullanıcıların oturum sürelerini saklamak için bir sözlük oluşturalım
session_timeouts = {}

max_login_attempts = 3
login_attempts = {}

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

def login(username, password):
    if username in passwords:
        if verify_password(username, password):
            # Kullanıcı girişi başarılı olduğunda oturum süresini güncelleyelim
            login_attempts.pop(username, None)
            update_session_timeout(username)
            messagebox.showinfo("Başarılı", "Giriş başarıyla yapıldı.")
        else:
            # Kullanıcı adı doğru ancak parola yanlışsa giriş denemesini kaydedelim
            if username in login_attempts:
                login_attempts[username] += 1
            else:
                login_attempts[username] = 1

            if login_attempts[username] >= max_login_attempts:
                # Belirli bir sayıda başarısız giriş denemesi olduğunda hesabı kilitliyoruz
                messagebox.showerror("Hesap Kilitli", "Çok fazla başarısız giriş denemesi. Hesap kilitlendi.")
                # Hesabı kilitlediğimizde oturum süresini sıfırlayalım
                reset_session_timeout(username)
            else:
                messagebox.showerror("Hatalı Giriş", "Parola yanlış. Lütfen tekrar deneyin.")
    else:
        messagebox.showerror("Hatalı Giriş", "Kullanıcı bulunamadı.")

def login_button_clicked():
    username = username_entry.get()
    password = password_entry.get()
    login(username, password)

def reset_session_timeout(username):
    session_timeouts[username] = None

def update_session_timeout(username):
    session_timeouts[username] = datetime.now() + timedelta(seconds=DEFAULT_SESSION_TIMEOUT)

def check_session():
    current_time = datetime.now()
    for username, session_timeout in session_timeouts.items():
        if session_timeout and current_time > session_timeout:
            # Oturum süresi dolmuş kullanıcıları uyar
            messagebox.showwarning("Oturum Süresi Dolmuş", f"{username} kullanıcısının oturum süresi doldu.")
            reset_session_timeout(username)

def check_password_expiry():
    current_time = datetime.now()
    for username, last_change_date in last_password_change_dates.items():
        expiry_date = last_change_date + timedelta(days=90)  # Parola değişim süresi 90 gün
        if current_time > expiry_date:
            # Parolası geçerliliğini yitiren kullanıcıları uyar
            messagebox.showwarning("Parola Süresi Dolmuş", f"{username} kullanıcısının parolasının süresi doldu. Parolanızı güncelleyin.")

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
login_button.grid(row=2, column=0, columnspan=2, padx=5, pady=    5)

# Kullanıcı girişi düğmesi
login_button = tk.Button(root, text="Giriş Yap", command=login_button_clicked)
login_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

# Oturum süresi kontrolü
root.after(1000, check_session)

# Parola geçerliliği kontrolü
root.after(1000, check_password_expiry)

root.mainloop()