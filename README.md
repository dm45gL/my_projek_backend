📚 Tugas Mata Kuliah: Analisis & Pengujian Sistem IF7A

Mata Kuliah: Analisis & Pengujian Sistem

Ketua Kelompok: Dimas Galih laksono

Anggota:
- SENDIRIAN

📝 Deskripsi Proyek
Repositori ini berisi artefak, dokumen, dan kode yang berkaitan dengan tugas mata kuliah Analisis & Pengujian Sistem. Proyek ini bertujuan untuk melakukan penjualan VPS, Hosting dan reseler domain, projek ini di buat menggunakan expresJS dan juga typescrip, dan menggunakan database PostgreSQL, program ini di buat dengan tujuan hypervisor otomatios dengan penerapan paymentgetway yang tersinkronisasi.

📝 Desain Proyek (Unified Modeling System)

## 1. Use Case

### SysAdmin (Teknis & Infrastruktur)
- Integrasi API: Proxmox, WHM, SSL, Domain.
- Uji koneksi API real-time.
- Sinkronisasi template VM & paket hosting.
- CRUD Produk VPS/Hosting: CPU, RAM, Disk, Rate Limit, Template OS, Paket WHM.
- Monitoring Infrastruktur: status global, resource node Proxmox.
- Manajemen layanan global & backup storage.

### User Bisnis (Harga & Pemasaran)
- Manajemen harga produk & domain.
- CRUD kode promo.
- CRUD konten: banner, testimonial, halaman statis.

### User Keuangan (Transaksi & Laporan)
- Manajemen transaksi & invoice (Midtrans/Xendit).
- Laporan keuangan & analisis produk terlaris.
- Otomasi billing: suspend 3 hari, terminate 15 hari setelah jatuh tempo.

### Client (Portal & Storefront)
- Register/Login JWT, 2FA opsional.
- Cek domain & harga real-time.
- Onboarding: profil & billing wajib.
- Checkout & payment gateway, riwayat invoice.

---

## 2. Sequence Diagram

### CRUD Produk VPS (SysAdmin)
```mermaid
sequenceDiagram
    SysAdmin->>WebApp: Login & Pilih Produk
    WebApp->>Backend: CRUD Produk
    Backend->>DB: Simpan Data
    DB->>Backend: Konfirmasi
    Backend->>WebApp: Status Success
    WebApp->>SysAdmin: Tampilkan Status

%% Client Checkout & Payment
sequenceDiagram
    Client->>WebApp: Pilih Produk
    WebApp->>Backend: Validasi Produk & Harga
    Backend->>ProxmoxWHM_API: Cek Resource
    ProxmoxWHM_API->>Backend: Konfirmasi
    Backend->>WebApp: Tampilkan Invoice
    Client->>WebApp: Bayar Invoice
    WebApp->>PaymentGateway: Kirim Payment Request
    PaymentGateway->>Backend: Webhook Status Pembayaran
    Backend->>DB: Update Status Invoice
    Backend->>WebApp: Konfirmasi Paid
    WebApp->>Client: Tampilkan Invoice Paid

%% Monitoring Infrastruktur
sequenceDiagram
    SysAdmin->>WebApp: Request Status
    WebApp->>Backend: Fetch Data Node
    Backend->>ProxmoxWHM_API: Request Metrics
    ProxmoxWHM_API->>Backend: Return Metrics
    Backend->>WebApp: Dashboard Realtime
    WebApp->>SysAdmin: Tampilkan Status

%% Client Onboarding & Checkout
flowchart TD
    A[Start] --> B[Isi Profil & Billing]
    B --> C{Valid?}
    C -- No --> B
    C -- Yes --> D[Verifikasi Email & 2FA]
    D --> E[Pilih Produk]
    E --> F[Checkout & Payment]
    F --> G{Payment Success?}
    G -- No --> H[Tunggu / Reminder]
    G -- Yes --> I[Generate VPS/Hosting & Aktivasi]
    I --> J[End]

%% Otomasi Billing
flowchart TD
    A[Start] --> B[Cek Invoice Jatuh Tempo]
    B --> C{>3 hari unpaid?}
    C -- Yes --> D[Suspend Layanan]
    C -- No --> E[Biarkan Aktif]
    D --> F{>15 hari unpaid?}
    F -- Yes --> G[Terminate Layanan]
    F -- No --> H[End]
    E --> H
    G --> H

%% CRUD Produk VPS
flowchart TD
    A[Start] --> B[Login SysAdmin]
    B --> C[Pilih CRUD Produk]
    C --> D[Input Spesifikasi & Asosiasi Template/Paket]
    D --> E[Simpan ke DB]
    E --> F[Tampilkan Status Success/Error]
    F --> G[End]


📝 Arsitektur Proyek (Unified Modeling System)
arsitektur pada projek saya kali ini menggunakan typescrip dan express js untuk backend nya, lalu saya menggunakan postgresql database utama dan menggunakan redis sebagai database transite dan midlware otp
untuk jwt menggunakan HS256, menggunakan smtp untuk mengirim otp, dll

📝 Tech Stack
Jelaskan Contoh Tech Stack yang digunakan.
FE: Vue + typescrip
BE: Express + Tyepscrip
Database: postgresql, redis
Service: whm, proxmox, vmware, ESXi 



