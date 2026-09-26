
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time


def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    """Ma hoa chuoi plaintext bang AES-CBC, tra ve IV + ciphertext."""
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ct_bytes = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return iv + ct_bytes


def aes_decrypt(data: bytes, key: bytes) -> str:
    """Giai ma du lieu (IV + ciphertext) da duoc ma hoa boi ham aes_encrypt."""
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode("utf-8")


def main():
    # AES-128: key dai 16 byte (128 bit). Doi thanh 24/32 byte de dung AES-192/AES-256.
    key = get_random_bytes(16)
    message = "Day la thong diep bi mat can ma hoa bang AES!"

    print(" DEMO CAI DAT AES ")
    print(f"Ban ro       : {message}")
    print(f"Khoa AES-128 (hex): {key.hex()}")

    start = time.perf_counter()
    encrypted = aes_encrypt(message, key)
    enc_time_ms = (time.perf_counter() - start) * 1000
    print(f"Ban ma (hex) : {encrypted.hex()}")
    print(f"Thoi gian ma hoa  : {enc_time_ms:.4f} ms")

    start = time.perf_counter()
    decrypted = aes_decrypt(encrypted, key)
    dec_time_ms = (time.perf_counter() - start) * 1000
    print(f"Ban ro giai ma    : {decrypted}")
    print(f"Thoi gian giai ma : {dec_time_ms:.4f} ms")

    assert decrypted == message, "Giai ma khong khop voi ban ro goc!"
    print("\nKet qua: Ma hoa/giai ma thanh cong, du lieu khop 100%.")


if __name__ == "__main__":
    main()