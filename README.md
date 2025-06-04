# 🌙 Ayana File Manager

**Ayana File Manager** adalah file manager berbasis web (PHP) dengan tampilan modern dark mode. Didesain untuk memudahkan pengelolaan file langsung dari browser, tanpa perlu akses FTP atau SSH.

---

## 🖼️ Preview

### 📁 Dashboard File Manager
![Preview File Manager](https://yourdomain.com/screenshots/ayana-dashboard.png)

### ⚙️ Panel Settings & Logging
![Preview Settings Panel](https://yourdomain.com/screenshots/ayana-settings.png)

---

## 🚀 Fitur Utama

- ⚫ **Dark Mode Interface** — Nyaman di mata.
- 📤 **Upload Files (Drag & Drop)** — Praktis & cepat.
- 📁 **Manajemen File Lengkap** — Buat, hapus, edit, rename file & folder.
- 🗜️ **Zip / Unzip** — Kompres dan ekstrak langsung di dashboard.
- 🧮 **Multi-Select** — Pilih banyak file sekaligus.
- 📝 **Editor Kode Terintegrasi** — Edit file langsung via browser.
- 🔍 **Deteksi Potensi Shell/Backdoor** — Tandai file mencurigakan secara otomatis.
- ⚙️ **Settings Lanjutan & Logging** — Konfigurasi log ke Discord, Telegram, Email.
- 🔐 **Enkripsi Konfigurasi Log** — Data tersimpan aman dengan passphrase terenkripsi.
- 🖥️ **Terminal Mode (opsional)** — Jalankan perintah terminal via web (gunakan dengan hati-hati).

---

## ⚙️ Settings Panel

Di menu **Settings**, tersedia fitur penting untuk keamanan & logging:

### 🔐 Enkripsi Logging
- Enkripsi pengaturan log menggunakan passphrase (`LOG_CONFIG_ENCRYPTION_PASSPHRASE`).
- Disarankan segera mengganti passphrase default dengan yang kuat & unik.
- File konfigurasi log (`config_log.json`) hanya dapat dibaca jika passphrase sesuai.

### 📋 Opsi Logging Real-Time
Aktifkan log aktivitas secara otomatis ke:
- ✅ **Discord** (Webhook)
- ✅ **Telegram**
- ✅ **Email**

> Log ini bisa digunakan untuk memantau perubahan, upload file, hingga potensi akses berbahaya.

---

## 🛡️ Deteksi File Berbahaya (Shell/Backdoor)

Sistem akan otomatis:
- Mendeteksi file mencurigakan berdasarkan pola umum seperti `eval`, `system`, `base64_decode`.
- Menampilkan ikon ⚠️ dan highlight warna khusus di tabel file.
- Memberi catatan keamanan di bagian bawah halaman:

> "Fitur deteksi potensi kode berbahaya (shell/backdoor) bersifat dasar dan hanya berdasarkan pola string sederhana. Ini BUKAN solusi keamanan menyeluruh..."

Tetap lakukan pengecekan manual jika ditemukan file mencurigakan.

---

## 📦 Instalasi

1. Upload semua file ke server (misalnya: `htdocs/ayana`).
2. Akses via browser:  
   - Lokal: `http://localhost/ayana`  
   - Online: `https://yourdomain.com/ayana`
3. (Opsional) Edit konfigurasi keamanan & passphrase di file `config.php`.

---

## 📜 Lisensi

Open-source untuk keperluan pribadi. Hubungi developer untuk penggunaan komersial.

---

## 🤝 Kontribusi

Silakan fork dan kirim pull request untuk kontribusi fitur atau perbaikan bug.
