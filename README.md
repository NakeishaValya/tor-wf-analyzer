# Website Fingerprinting Feature Extraction Tool

Tool Python untuk mengekstrak fitur jaringan dari file `.pcapng` untuk tugas Machine Learning website fingerprinting.

## 📋 Fitur Utama

- **Membaca Multiple PCAPNG Files**: Memproses semua file `.pcapng` dari satu direktori
- **Ekstraksi Fitur**: Menghitung total bytes masuk/keluar dan jumlah paket
- **Filtering IP Packets**: Otomatis memfilter paket non-IP
- **Automatic Class Labeling**: Memetakan nama file ke label kelas secara otomatis
- **CSV Export**: Mengekspor hasil ke format CSV menggunakan pandas
- **Detailed Logging**: Log lengkap dengan progress tracking
- **Error Handling**: Penanganan error yang robust untuk file yang rusak

## 🚀 Quick Start

### 1. Instalasi Dependensi

```bash
pip install -r requirements.txt
```

### 2. Persiapan Data

Buat direktori `pcapng_data` dan tempatkan file `.pcapng` Anda:

```bash
mkdir pcapng_data
# Copy atau move file .pcapng ke direktori ini
```

### 3. Jalankan Script

```bash
python extract_features.py
```

### 4. Hasil Output

File `features.csv` akan dibuat dengan kolom:
- `filename`: Nama file pcapng
- `class_label`: Label website/kelas
- `total_incoming_bytes`: Total byte masuk
- `total_outgoing_bytes`: Total byte keluar
- `total_packets`: Total jumlah paket
- `total_bytes`: Total byte (masuk + keluar)

## 📊 Contoh Output

```csv
filename,class_label,total_incoming_bytes,total_outgoing_bytes,total_packets,total_bytes
example.com_001.pcapng,example.com,5234,2841,156,8075
example.com_002.pcapng,example.com,6123,3012,189,9135
google.com_001.pcapng,google.com,15234,8923,412,24157
```

## 🌐 Konfigurasi IP Lokal (PENTING!)

Untuk **deteksi arah paket yang akurat**, set IP lokal laptop Anda:

### Quick Setup

**Windows:**
```bash
ipconfig  # Cari IPv4 Address, contoh: 192.168.1.100
```

**Linux/Mac:**
```bash
ifconfig  # atau hostname -I
```

Kemudian edit [extract_features.py](extract_features.py#L46) atau gunakan command-line:

```bash
# Metode 1: Edit langsung di script (line ~46)
LOCAL_IP = "192.168.1.100"  # Ganti dengan IP Anda

# Metode 2: Pass via command line
python extract_features.py ./pcapng_data ./features.csv 192.168.1.100
```

**📌 Lihat [IP_CONFIGURATION.md](IP_CONFIGURATION.md) untuk panduan lengkap**

## 🔧 Penggunaan Advanced

### Dengan Directory Custom

```bash
python extract_features.py ./my_pcap_files ./output.csv
```

### Post-processing dengan Pandas

Lihat `example_usage.py` untuk berbagai contoh:
- Menambah fitur yang dihitung
- Analisis per class label
- Train/Test split untuk ML
- Statistik deskriptif

```bash
python example_usage.py
```

## 🎯 Use Cases

### 1. Website Fingerprinting Classification
```python
from sklearn.ensemble import RandomForestClassifier
import pandas as pd

df = pd.read_csv('features.csv')
X = df[['total_incoming_bytes', 'total_outgoing_bytes', 'total_packets']]
y = df['class_label']

clf = RandomForestClassifier()
clf.fit(X, y)
```

### 2. Anomaly Detection
```python
from sklearn.ensemble import IsolationForest

df = pd.read_csv('features.csv')
X = df[['total_incoming_bytes', 'total_outgoing_bytes', 'total_packets']]

detector = IsolationForest(contamination=0.1)
anomalies = detector.fit_predict(X)
```

### 3. Traffic Pattern Analysis
```python
df = pd.read_csv('features.csv')
# Hitung rasio incoming/outgoing
df['io_ratio'] = df['total_incoming_bytes'] / df['total_outgoing_bytes']
# Hitung rata-rata ukuran paket
df['avg_pkt_size'] = df['total_bytes'] / df['total_packets']
```

## 📁 Struktur Direktori

```
tor-wf-analyzer/
├── extract_features.py      # Script utama (447 lines)
├── example_usage.py         # Contoh penggunaan advanced
├── requirements.txt         # Dependensi Python
├── SETUP.md                 # Panduan setup lengkap (Bahasa Indonesia)
├── README.md                # File ini
└── pcapng_data/             # Direktori data input (buat sendiri)
    ├── website1_001.pcapng
    ├── website1_002.pcapng
    ├── website2_001.pcapng
    └── ...
```

## ⚙️ Konfigurasi

### Mengubah Fungsi Class Label Mapping

Edit `get_class_label()` di `extract_features.py`:

```python
def get_class_label(self, filename: str) -> str:
    # Contoh: "facebook_trace_001.pcapng" -> "facebook"
    import re
    name = filename.replace('.pcapng', '').replace('.pcap', '')
    label = re.sub(r'_trace_\d+$', '', name)  # Hapus "_trace_001"
    return label
```

### Mengubah Heuristik Incoming/Outgoing

Edit `_is_incoming_packet()` untuk logika custom:

```python
def _is_incoming_packet(self, packet) -> bool:
    # Custom logic berdasarkan kebutuhan Anda
    # Contoh: gunakan MAC address, subnet lokal, etc.
    pass
```

## 🔍 Troubleshooting

| Masalah | Solusi |
|---------|--------|
| `tshark not found` | Install Wireshark dari https://www.wireshark.org/ |
| `ModuleNotFoundError: pyshark` | `pip install -r requirements.txt` |
| `Permission denied` | Linux: `sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/dumpcap` |
| File tidak terdeteksi | Pastikan file `.pcapng` di direktori yang benar |
| Memory error pada file besar | Script menggunakan `keep_packets=False` untuk efisiensi |

## 📚 Dokumentasi

- [SETUP.md](SETUP.md) - Panduan setup lengkap (Bahasa Indonesia)
- [extract_features.py](extract_features.py) - Dokumentasi kode inline
- [example_usage.py](example_usage.py) - 5 contoh penggunaan berbeda

## 📦 Dependencies

- **pyshark** (0.6) - Interface Python untuk tshark
- **pandas** (>=1.3.0) - Data manipulation dan CSV export
- **numpy** (>=1.21.0) - Numerical computing
- **Wireshark** - Diperlukan oleh pyshark (install terpisah)

## 🎓 Untuk Penelitian

Script ini cocok untuk:
- Website Fingerprinting dalam Tor
- Traffic Analysis dan Classification
- Network Pattern Recognition
- Privacy-related Research
- Encrypted Traffic Analysis

## 📝 Catatan Penting

1. **Accuracy incoming/outgoing**: Heuristik saat ini berbasis port number. Untuk hasil lebih akurat:
   - Configure subnet lokal
   - Gunakan packet flow metadata
   - Combine dengan traffic direction info

2. **Performa**: Script dioptimasi untuk file besar dengan `keep_packets=False`

3. **Privasi**: Pastikan Anda memiliki izin untuk menganalisis traffic yang dikumpulkan

## 📄 Lisensi

Script ini tersedia untuk penggunaan akademik dan penelitian.

## 👤 Author

Created for Website Fingerprinting ML Research

---

**Last Updated**: Juni 2024  
**Python Version**: 3.7+  
**Status**: Production Ready ✓