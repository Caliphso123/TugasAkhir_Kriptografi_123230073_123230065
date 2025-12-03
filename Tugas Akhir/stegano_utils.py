from PIL import Image
import numpy as np
from io import BytesIO
import struct

# --- Utilitas Biner ---
def byte_to_bit(byte_data: bytes) -> np.ndarray:
    """Konversi bytes menjadi array bit (0 atau 1)."""
    # np.frombuffer mengkonversi bytes menjadi array uint8
    # np.unpackbits mengkonversi setiap byte menjadi 8 bit terpisah
    return np.unpackbits(np.frombuffer(byte_data, dtype=np.uint8))

def bit_to_byte(bit_array: np.ndarray) -> bytes:
    """Konversi array bit kembali menjadi bytes."""
    # np.packbits mengemas 8 bit menjadi 1 byte
    return np.packbits(bit_array).tobytes()

# --- 1. ENCODE (Sembunyikan Pesan) ---
def encode_stegano(carrier_image_bytes: bytes, encrypted_secret_data: bytes) -> bytes:
    """
    Sembunyikan data terenkripsi (bytes) ke dalam LSB gambar pembawa.
    Menggunakan PNG untuk menghindari kompresi yang merusak LSB.
    """
    try:
        # Buka gambar dari bytes, konversi ke RGB
        img = Image.open(BytesIO(carrier_image_bytes)).convert("RGB")
    except Exception as e:
        raise ValueError(f"Gagal membuka atau memproses gambar pembawa: {e}")

    pixels = np.array(img, dtype=np.uint8)
    
    # 1. Hitung Kapasitas dan Header
    total_bits = pixels.size
    data_length = len(encrypted_secret_data)
    header_bytes = struct.pack('>I', data_length)
    data_to_hide = header_bytes + encrypted_secret_data
    bits_needed = len(data_to_hide) * 8

    if bits_needed > total_bits:
        raise ValueError(f"Gambar terlalu kecil. Dibutuhkan {bits_needed} bits, tersedia {total_bits} bits.")

    # 2. Konversi data ke array bit
    data_bits = byte_to_bit(data_to_hide)
    
    # 3. Sembunyikan Data di LSB
    flat_pixels = pixels.flatten()
    
    # KRITIS: CAST KE INT16 UNTUK MENGHINDARI 'OUT OF BOUNDS FOR UINT8'
    # Operasi bitwise di NumPy terkadang bisa menyebabkan integer underflow (nilai negatif)
    # yang dilarang oleh uint8.
    flat_pixels_int16 = flat_pixels.astype(np.int16) 
    
    data_bits_uint8 = data_bits.astype(np.uint8)

    # Operasi LSB:
    # 1) & ~1: Hapus LSB lama (memastikan LSB adalah 0)
    # 2) | data_bits_uint8: Tambahkan bit data rahasia
    flat_pixels_int16[:bits_needed] = (flat_pixels_int16[:bits_needed] & ~1) | data_bits_uint8

    # 4. Bentuk kembali gambar
    
    # KRITIS: CLIPPING DAN KONVERSI KEMBALI KE UINT8
    # Memotong nilai di antara 0 dan 255 (meskipun seharusnya tidak ada out-of-bounds 
    # setelah operasi LSB, ini adalah langkah pengamanan terbaik), lalu konversi ke uint8.
    new_pixels_flat = np.clip(flat_pixels_int16, 0, 255).astype(np.uint8)
    
    # Bentuk array kembali ke dimensi asli
    new_pixels = new_pixels_flat.reshape(pixels.shape)
    new_img = Image.fromarray(new_pixels, 'RGB')
    
    # Simpan kembali ke bytes (wajib PNG)
    output = BytesIO()
    new_img.save(output, format='PNG') 
    return output.getvalue()


# --- 2. DECODE (Ekstrak Pesan) ---
def decode_stegano(stegano_image_bytes: bytes) -> bytes:
    """Ekstrak data terenkripsi (bytes) dari LSB gambar."""
    
    try:
        img = Image.open(BytesIO(stegano_image_bytes)).convert("RGB")
    except Exception as e:
        raise ValueError(f"Gagal membuka atau memproses gambar stegano: {e}")

    pixels = np.array(img, dtype=np.uint8)
    flat_pixels = pixels.flatten()
    
    # 1. Ekstrak Header (32 bits = 4 bytes) untuk Panjang Data
    header_bits = flat_pixels[:32] & 1 # Ambil 32 LSB
    header_bytes = bit_to_byte(header_bits)
    
    # Konversi 4 bytes header menjadi integer panjang data
    data_length = struct.unpack('>I', header_bytes)[0]
    
    if data_length == 0:
        return b"" # Tidak ada data tersembunyi

    # 2. Ekstrak Data Terenkripsi
    data_start_bit = 32
    data_end_bit = data_start_bit + (data_length * 8)
    
    if data_end_bit > flat_pixels.size:
        raise ValueError("Gambar rusak atau data tidak sepenuhnya tersimpan.")

    # Ambil bit data terenkripsi dari LSB piksel
    encrypted_data_bits = flat_pixels[data_start_bit:data_end_bit] & 1
    
    # Konversi bit kembali ke bytes
    encrypted_secret_data = bit_to_byte(encrypted_data_bits)
    
    return encrypted_secret_data