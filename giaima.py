import base64
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
import zlib

# Hàm tạo khóa AES từ mật khẩu và salt
def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Hàm chuyển nhị phân thành chuỗi
def bits_to_text(bits):
    return ''.join([chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)])

# Kiểm tra checksum khi giải mã
def verify_checksum(decoded_message):
    try:
        message, checksum = decoded_message.rsplit('|', 1)
        if str(zlib.crc32(message.encode())) == checksum:
            return message
        else:
            raise ValueError("Thông điệp đã bị thay đổi!")
    except Exception:
        raise ValueError("Lỗi xác minh checksum!")

# Giải mã thông điệp
def decrypt_message(cipher_suite, encrypted_message):
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode())  # Giải mã Base64
    return cipher_suite.decrypt(encrypted_bytes).decode()

# Hàm giải mã thông điệp từ ảnh
def decode_image(encoded_img_path, cipher_suite):
    # Mở ảnh đã mã hóa
    img = Image.open(encoded_img_path)
    img = img.convert("RGB")
    encoded_pixels = img.load()

    binary_message = ""
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = encoded_pixels[x, y]
            binary_message += format(r, '08b')[-1]
            binary_message += format(g, '08b')[-1]
            binary_message += format(b, '08b')[-1]
            if binary_message[-16:] == "1111111111111110":
                break

    # Loại bỏ chuỗi dừng và chuyển về dạng chuỗi
    binary_message = binary_message[:-16]
    encrypted_message = bits_to_text(binary_message)

    # Giải mã thông điệp và xác minh checksum
    decrypted_message = decrypt_message(cipher_suite, encrypted_message)
    return verify_checksum(decrypted_message)

# Sử dụng chương trình giải mã
if __name__ == "__main__":
    # Nhập mật khẩu và sinh khóa
    password = input("Nhập mật khẩu của bạn: ")
    salt = b'some_salt'  # Salt cố định (nên trùng với salt khi mã hóa)
    key = generate_key_from_password(password, salt)
    cipher_suite = Fernet(key)

    # Nhập đường dẫn đến ảnh chứa thông điệp mã hóa
    encoded_image_path = input("Nhập đường dẫn đến ảnh chứa thông điệp đã mã hóa: ")

    try:
        # Giải mã thông điệp từ ảnh
        decoded_message = decode_image(encoded_image_path, cipher_suite)
        print("Thông điệp đã giải mã:", decoded_message)
    except Exception as e:
        print("Lỗi trong quá trình giải mã:", e)
