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

# Hàm chuyển đổi chuỗi thành nhị phân
def text_to_bits(text):
    return ''.join([format(ord(i), "08b") for i in text])

# Hàm chuyển nhị phân thành chuỗi
def bits_to_text(bits):
    return ''.join([chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)])

# Thêm checksum vào thông điệp
def add_checksum(message):
    checksum = zlib.crc32(message.encode())
    return f"{message}|{checksum}"

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

# Mã hóa thông điệp
def encrypt_message(cipher_suite, message):
    encrypted_bytes = cipher_suite.encrypt(message.encode())
    return base64.urlsafe_b64encode(encrypted_bytes).decode()  # Chuyển thành Base64 để đảm bảo ASCII

# Giải mã thông điệp
def decrypt_message(cipher_suite, encrypted_message):
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode())  # Giải mã Base64
    return cipher_suite.decrypt(encrypted_bytes).decode()

# Kiểm tra dung lượng khả dụng của ảnh
def can_encode_message(img, message):
    max_bits = img.width * img.height * 3  # 3 kênh màu (R, G, B)
    message_bits = len(text_to_bits(message)) + 16  # Thêm 16 bit cho điểm dừng
    return message_bits <= max_bits

# Hàm nhúng thông điệp vào ảnh
def encode_image(img_path, secret_message, cipher_suite, output_path="encoded_image.png"):
    # Mã hóa và thêm checksum
    encoded_message = encrypt_message(cipher_suite, add_checksum(secret_message))
    binary_message = text_to_bits(encoded_message) + '1111111111111110'  # Thêm chuỗi dừng

    # Mở ảnh và chuyển sang chế độ RGB
    img = Image.open(img_path)
    img = img.convert("RGB")
    encoded_pixels = img.load()

    # Kiểm tra dung lượng trước khi nhúng
    if not can_encode_message(img, encoded_message):
        raise ValueError("Thông điệp quá dài để nhúng vào ảnh!")

    # Nhúng thông điệp vào từng pixel
    data_index = 0
    for y in range(img.height):
        for x in range(img.width):
            if data_index < len(binary_message):
                r, g, b = encoded_pixels[x, y]
                r = int(format(r, '08b')[:-1] + binary_message[data_index], 2)
                data_index += 1
                if data_index < len(binary_message):
                    g = int(format(g, '08b')[:-1] + binary_message[data_index], 2)
                    data_index += 1
                if data_index < len(binary_message):
                    b = int(format(b, '08b')[:-1] + binary_message[data_index], 2)
                    data_index += 1
                encoded_pixels[x, y] = (r, g, b)
            else:
                break

    # Lưu ảnh đã nhúng thông điệp
    img.save(output_path)
    print(f"Đã mã hóa thông điệp vào ảnh và lưu tại {output_path}")

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

# Sử dụng các hàm để mã hóa và giải mã thông điệp
if __name__ == "__main__":
    # Nhập mật khẩu và sinh khóa
    password = input("Nhập mật khẩu của bạn: ")
    salt = b'some_salt'  # Nên lưu salt cố định để giải mã được
    key = generate_key_from_password(password, salt)
    cipher_suite = Fernet(key)

    secret_message = "Xin chào, nhóm mình là nhóm 32!"
    input_image_path = "D:/HOCTAP/KI 7 nam 4(2024-2025)/An_ninh_mang/image_foothball.jpg"
    output_image_path = "encoded_image.png"

    # Nhúng thông điệp vào ảnh
    encode_image(input_image_path, secret_message, cipher_suite, output_image_path)

    # Giải mã thông điệp từ ảnh
    decoded_message = decode_image(output_image_path, cipher_suite)
    print("Thông điệp đã giải mã:", decoded_message)
