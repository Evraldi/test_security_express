# Express Security Testing

Proyek ini adalah aplikasi Express.js yang mengimplementasikan praktik keamanan terbaik dan dilengkapi dengan pengujian keamanan yang komprehensif.

## Fitur Keamanan

Aplikasi ini mengimplementasikan berbagai fitur keamanan:

- **Autentikasi JWT** - Menggunakan JSON Web Tokens dengan algoritma RS256 (asimetris)
- **Perlindungan CSRF** - Implementasi token CSRF untuk mencegah serangan Cross-Site Request Forgery
- **Validasi Input** - Validasi input yang ketat menggunakan express-validator
- **Sanitasi Data** - Sanitasi data untuk mencegah serangan XSS
- **Rate Limiting** - Pembatasan jumlah permintaan untuk mencegah serangan brute force
- **Secure Cookies** - Cookie dengan flag HttpOnly, Secure, dan SameSite
- **Password Hashing** - Hashing password menggunakan bcrypt
- **Security Headers** - Header keamanan seperti Helmet untuk melindungi dari berbagai serangan
- **Error Handling** - Penanganan error yang aman tanpa mengungkapkan informasi sensitif

## Struktur Proyek

```
├── config/                 # Konfigurasi aplikasi
├── controllers/            # Controller untuk menangani logika bisnis
├── middlewares/            # Middleware untuk autentikasi, validasi, dll.
├── models/                 # Model data
├── prisma/                 # Konfigurasi Prisma ORM
├── public/                 # File statis
├── routes/                 # Definisi rute API
├── services/               # Layanan bisnis
├── tests/                  # Pengujian
│   ├── e2e/                # Pengujian end-to-end
│   ├── penetration/        # Pengujian penetrasi
│   ├── security/           # Pengujian keamanan
│   └── unit/               # Pengujian unit
├── .env.example            # Contoh file environment
├── .gitignore              # File yang diabaikan oleh Git
├── for_test.js             # Setup untuk pengujian
├── generate-keys.js        # Script untuk menghasilkan kunci RSA
├── package.json            # Dependensi dan script
├── server.js               # Entry point aplikasi
└── README.md               # Dokumentasi proyek
```

## Pengujian Keamanan

Proyek ini dilengkapi dengan berbagai jenis pengujian keamanan:

### 1. Pengujian Keamanan Dasar

Pengujian keamanan dasar memverifikasi implementasi praktik keamanan terbaik:

- Security Headers
- Content Security Policy
- XSS Protection
- CSRF Protection
- SQL Injection Protection
- Input Validation
- Content-Type Validation
- HTTP Method Validation

### 2. Pengujian End-to-End (E2E)

Pengujian E2E memverifikasi keamanan aplikasi secara keseluruhan:

- Registrasi dengan validasi password yang kuat
- Login dengan perlindungan terhadap brute force
- Perlindungan CSRF
- Sanitasi input untuk mencegah XSS
- Perlindungan terhadap SQL injection
- Manajemen sesi yang aman
- Logout yang aman

### 3. Pengujian Penetrasi

Pengujian penetrasi mensimulasikan berbagai serangan terhadap aplikasi:

- Serangan SQL Injection
- Serangan XSS (Cross-Site Scripting)
- Serangan CSRF (Cross-Site Request Forgery)
- Serangan Brute Force
- Manipulasi Token JWT
- Serangan Header Injection

### 4. Pengujian Token dan Cookie

Pengujian token dan cookie memverifikasi keamanan token JWT dan cookie:

- Algoritma JWT yang aman
- Klaim JWT yang esensial
- Tidak ada informasi sensitif dalam token
- Cookie dengan atribut keamanan yang tepat
- Pembersihan cookie pada logout
- Manajemen sesi yang aman

## Cara Menjalankan

### Prasyarat

- Node.js (v14 atau lebih baru)
- npm atau yarn
- Database PostgreSQL (atau SQLite untuk pengujian)

### Instalasi

1. Clone repositori:
   ```bash
   git clone https://github.com/yourusername/express-security-testing.git
   cd express-security-testing
   ```

2. Instal dependensi:
   ```bash
   npm install
   ```

3. Salin file `.env.example` ke `.env` dan sesuaikan:
   ```bash
   cp .env.example .env
   ```

4. Generate kunci RSA untuk JWT:
   ```bash
   npm run generate-keys
   ```

5. Jalankan migrasi database:
   ```bash
   npx prisma migrate dev
   ```

### Menjalankan Aplikasi

```bash
npm run dev
```

Aplikasi akan berjalan di `http://localhost:3000`.

### Menjalankan Pengujian

#### Semua Pengujian

```bash
npm test
```

#### Pengujian Keamanan

```bash
npm run test:security
```

#### Pengujian End-to-End

```bash
npm run test:e2e
```

#### Pengujian Penetrasi

```bash
npm run test:pentest
```

#### Pengujian dengan Coverage

```bash
npm run test:coverage
```

## Praktik Keamanan Terbaik

### Autentikasi

- Gunakan algoritma hashing yang kuat (bcrypt) untuk password
- Implementasikan validasi password yang kuat
- Gunakan token JWT dengan algoritma RS256 (asimetris)
- Tetapkan masa berlaku token yang wajar
- Implementasikan refresh token untuk pengalaman pengguna yang lebih baik

### Perlindungan CSRF

- Gunakan token CSRF untuk semua permintaan modifikasi (POST, PUT, DELETE)
- Implementasikan Double Submit Cookie Pattern
- Gunakan SameSite cookies untuk perlindungan tambahan

### Perlindungan XSS

- Sanitasi semua input pengguna
- Implementasikan Content Security Policy (CSP)
- Gunakan HttpOnly cookies untuk mencegah akses JavaScript ke cookie sensitif
- Escape output di sisi klien

### Perlindungan SQL Injection

- Gunakan ORM (Prisma) untuk query database
- Gunakan parameterized queries
- Validasi dan sanitasi input

### Rate Limiting

- Implementasikan rate limiting untuk endpoint sensitif (login, register)
- Gunakan sliding window untuk rate limiting yang lebih efektif
- Implementasikan exponential backoff untuk login yang gagal

### Security Headers

- Gunakan Helmet untuk mengatur header keamanan
- Implementasikan Content Security Policy (CSP)
- Gunakan Strict-Transport-Security (HSTS)
- Gunakan X-Content-Type-Options: nosniff
- Gunakan X-Frame-Options: DENY

## Lisensi

[MIT](LICENSE)
