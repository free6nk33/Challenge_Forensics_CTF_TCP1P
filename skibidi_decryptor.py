import struct
import zstandard as zstd
from Crypto.Cipher import AES
from PIL import Image
import numpy as np

def read_skibidi_file(filename):
    """Reads a .skibidi file and returns the header and pixel data."""
    print(f"[DEBUG] Opening file: {filename}")

    with open(filename, 'rb') as f:
        # Read the magic number
        magic_number = f.read(4).decode('ascii')
        if magic_number != "SKB1":
            raise ValueError(f"Invalid magic number: {magic_number}")

        print(f"[DEBUG] Magic Number: {magic_number}")

        # Read width, height, channels, compression method
        width = struct.unpack('<I', f.read(4))[0]
        height = struct.unpack('<I', f.read(4))[0]
        channels = struct.unpack('B', f.read(1))[0]
        compression_method = struct.unpack('B', f.read(1))[0]

        print(f"[DEBUG] Width: {width}, Height: {height}, Channels: {channels}, Compression Method: {compression_method}")

        # Read AES Key and IV
        aes_key = f.read(32)  # AES key (256 bits)
        aes_iv = f.read(12)   # IV should be 12 bytes for AES-GCM

        print(f"[DEBUG] AES Key Read: {aes_key.hex()}")
        print(f"[DEBUG] AES IV Read: {aes_iv.hex()}")

        # Now read the encrypted data size
        encrypted_data = f.read()  # Read the rest of the file
        print(f"[DEBUG] Encrypted Data Size Read: {len(encrypted_data)} bytes")

        # The auth tag is expected to be the last 16 bytes of the encrypted data
        auth_tag = encrypted_data[-16:]  # Last 16 bytes
        encrypted_data = encrypted_data[:-16]  # The rest is the encrypted data

        return width, height, channels, compression_method, aes_key, aes_iv, encrypted_data, auth_tag

def decrypt_data(encrypted_data, aes_key, aes_iv, auth_tag):
    """Decrypts the given data using AES-GCM."""
    print(f"[DEBUG] Starting decryption.")
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_iv)

    # Decrypt the data
    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        cipher.verify(auth_tag)  # Verify using the authentication tag
        print("[DEBUG] Decryption verified successfully.")
    except ValueError as e:
        print(f"[ERROR] Decryption verification failed: {e}")
        raise

    print(f"[DEBUG] Decrypted Data Size: {len(decrypted_data)} bytes")
    return decrypted_data

def decompress_data(compressed_data):
    """Decompresses the given data using Zstandard."""
    print(f"[DEBUG] Starting decompression.")
    dctx = zstd.ZstdDecompressor()
    decompressed_data = b""

    # Decompress in chunks
    with dctx.stream_reader(compressed_data) as reader:
        while True:
            chunk = reader.read()
            if not chunk:
                break
            decompressed_data += chunk

    print(f"[DEBUG] Decompressed Data Size: {len(decompressed_data)} bytes")
    return decompressed_data

def save_image(decompressed_data, width, height, channels):
    """Saves the decompressed pixel data as an image."""
    image_array = np.frombuffer(decompressed_data, dtype=np.uint8)

    if channels == 1:  # Grayscale
        image_array = image_array.reshape((height, width))
        image = Image.fromarray(image_array, 'L')
    elif channels == 3:  # RGB
        image_array = image_array.reshape((height, width, 3))
        image = Image.fromarray(image_array, 'RGB')
    elif channels == 4:  # RGBA
        image_array = image_array.reshape((height, width, 4))
        image = Image.fromarray(image_array, 'RGBA')
    else:
        raise ValueError(f"Unsupported number of channels: {channels}")

    image.save('output_image.png')
    print("[INFO] Image saved as output_image.png")

def main():
    input_filename = 'suisei.skibidi'
    
    print(f"[INFO] Starting process for file: {input_filename}")

    # Step 1: Read the .skibidi file
    width, height, channels, compression_method, aes_key, aes_iv, encrypted_data, auth_tag = read_skibidi_file(input_filename)

    # Step 2: Decrypt the pixel data
    decrypted_data = decrypt_data(encrypted_data, aes_key, aes_iv, auth_tag)

    # Step 3: Decompress the pixel data
    if compression_method == 1:  # Assuming 1 means Zstandard
        pixel_data = decompress_data(decrypted_data)
    else:
        raise ValueError("Unsupported compression method.")
    
    print(f"[INFO] Successfully read and decrypted the .skibidi file.")
    print(f"[INFO] Image dimensions: {width}x{height}, Channels: {channels}")

    # Step 4: Save the image
    save_image(pixel_data, width, height, channels)

if __name__ == "__main__":
    main()
