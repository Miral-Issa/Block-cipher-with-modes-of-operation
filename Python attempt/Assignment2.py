from PIL import Image
import random

def ECB_TEA(block, k):
    L0, R0 = block
    key = [0x11112222, 0x33334444, 0xAAAABBBB, 0xCCCCDDDD]
    delta = 0x9E3779B9
    sum = 0
    for _ in range(32):
        sum = (sum + delta) & 0xFFFFFFFF
        L0 = (L0 + ((R0 << 4) + key[0] ^ R0 + sum ^ (R0 >> 5) + key[1])) & 0xFFFFFFFF
        R0 = (R0 + ((L0 << 4) + key[2] ^ L0 + sum ^ (L0 >> 5) + key[3])) & 0xFFFFFFFF
    return (L0, R0)

def ECB_TEA_DEC(block, k):
    L0, R0 = block
    key = [0x11112222, 0x33334444, 0xAAAABBBB, 0xCCCCDDDD]
    delta = 0x9E3779B9
    sum = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
        R0 = (R0 - ((L0 << 4) + key[2] ^ L0 + sum ^ (L0 >> 5) + key[3])) & 0xFFFFFFFF
        L0 = (L0 - ((R0 << 4) + key[0] ^ R0 + sum ^ (R0 >> 5) + key[1])) & 0xFFFFFFFF
        sum = (sum - delta) & 0xFFFFFFFF
    return (L0, R0)


def CBC_TEA(block,k,C0,C1):

    L0, R0 = block
    L0 = C0 ^ L0
    R0 = C1 ^ R0

    enc=ECB_TEA(block,k)
    return enc

def CBC_TEA_DEC(block,k, C0,C1):
    L0, R0 = block
    dec_words = ECB_TEA_DEC(block,k)

    P0= C0 ^ dec_words[0]
    P1= C1 ^ dec_words[1]

    return[P0, P1]


def pad(data):
    padding = 8 - len(data) % 8
    return data + bytes([padding] * padding)

def unpad(data):
    padding = data[-1]
    return data[:-padding]

# Ask the user if they want to encrypt a text or an image
data_array = []
userChoice = input("Do you want to encrypt a text (T) or an image (I)? ")

if userChoice == "I":
    # Load the image
    image_path = 'Aqsa.jpg'
    img = Image.open(image_path)
    img = img.convert('L')  # Convert to grayscale
    img_bytes = img.tobytes()
    mode = img.mode
    size = img.size
    print("Original Image Size (bytes):", len(img_bytes))
    print("Original Bytes (first 64):", img_bytes[:64])  # Print the first 64 bytes for verification
    data_array = img_bytes

    enc_choice = input("What encryption to use? ECB_TEA (E) or CBC_TEA (C)? ")
    key = [0x11112222, 0x33334444, 0xAAAABBBB, 0xCCCCDDDD]
    padding=0
    if enc_choice == "E":
        # data_array = pad(data_array)
        padding = 8 - len(data_array) % 8
        data_array=  data_array + bytes([padding] * padding)
        blocks = []
        for i in range(0, len(data_array), 8):
            chunk = data_array[i:i + 8]
            part1 = int.from_bytes(chunk[:4], 'big')
            part2 = int.from_bytes(chunk[4:], 'big')
            blocks.append((part1, part2))

        encrypted_blocks = []
        for block in blocks:
            encrypted_block = ECB_TEA(block, key)
            encrypted_blocks.append(encrypted_block)

        # Convert encrypted blocks back to bytes
        encrypted_bytes = b''.join([
            part1.to_bytes(4, 'big') + part2.to_bytes(4, 'big')
            for part1, part2 in encrypted_blocks
        ])

        ################## Decrypt
        ciphertext = encrypted_bytes
        blocks = []
        for i in range(0, len(ciphertext), 8):
            chunk = ciphertext[i:i + 8]
            part1 = int.from_bytes(chunk[:4], 'big')
            part2 = int.from_bytes(chunk[4:], 'big')
            blocks.append((part1, part2))

        decrypted_blocks = []
        for block in blocks:
            decrypted_block = ECB_TEA_DEC(block, key)
            decrypted_blocks.append(decrypted_block)

        # Convert decrypted blocks back to bytes
        decrypted_bytes = b''.join([
            part1.to_bytes(4, 'big') + part2.to_bytes(4, 'big')
            for part1, part2 in decrypted_blocks
        ])

        # Unpad the decrypted bytes
        # decrypted_data = unpad(decrypted_bytes)
        padding = decrypted_bytes[-1]
        decrypted_bytes= decrypted_bytes[:-padding]

        ecb_encrypted_img = Image.frombytes(mode, size, encrypted_bytes)
        ecb_encrypted_img.save("ecb_encrypted_image.png")

        ecb_decrypted_img = Image.frombytes(mode, size, decrypted_bytes)
        ecb_decrypted_img.save("ecb_decrypted_image.png")


        #####################################
        #####################################


    elif enc_choice == "C":
        

        IV = [random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF)]
        # IV = [  0xFFFFFFFF ,  (  0xFFFFFFFF)]

        IV = tuple(IV)

        # # data_array = pad(data_array)
        # padding = 8 - len(data_array) % 8
        # data_array=  data_array + bytes([padding] * padding)
        blocks = []
        for i in range(0, len(data_array), 8):
            chunk = data_array[i:i + 8]
            part1 = int.from_bytes(chunk[:4], 'big')
            part2 = int.from_bytes(chunk[4:], 'big')
            blocks.append((part1, part2))

        C0, C1 = IV
        encrypted_blocks = []

        # for block in blocks:
        #     encrypted_block = CBC_TEA(block, key, C0, C1)
        #     encrypted_blocks.append(encrypted_block)
        #     C0, C1 = encrypted_block
        
        prev_block = IV
        C0, C1= IV
        for block in blocks:
          block = (block[0] ^ prev_block[0], block[1] ^ prev_block[1])
          encrypted_block = CBC_TEA(block, key,C0,C1)
          encrypted_blocks.append(encrypted_block)
          prev_block = encrypted_block
          # C0, C1= prev_block

        encrypted_bytes = b''.join([
            part1.to_bytes(4, 'big') + part2.to_bytes(4, 'big')
            for part1, part2 in encrypted_blocks
        ])

        ################## Decrypt
        padding =0 
        C0, C1 = IV
        decrypted_blocks = []

        ciphertext = encrypted_bytes
        blocks = []
        for i in range(0, len(ciphertext), 8):
            chunk = ciphertext[i:i + 8]
            part1 = int.from_bytes(chunk[:4], 'big')
            part2 = int.from_bytes(chunk[4:], 'big')
            blocks.append((part1, part2))

        # for block in encrypted_blocks:
        #     decrypted_block = CBC_TEA_DEC(block, key, C0, C1)
        #     decrypted_blocks.append(decrypted_block)
        #     C0, C1 = block

        prev_block = IV
        decrypted_blocks = []

        for block in blocks:
            decrypted_block = CBC_TEA_DEC(block, key, C0, C1)
            decrypted_block = (decrypted_block[0] ^ prev_block[0], decrypted_block[1] ^ prev_block[1])
            decrypted_blocks.append(decrypted_block)
            prev_block = block

        decrypted_bytes = b''.join([
            part1.to_bytes(4, 'big') + part2.to_bytes(4, 'big')
            for part1, part2 in decrypted_blocks
        ])

        # decrypted_data = unpad(decrypted_bytes)
        # padding = decrypted_bytes[-1]
        # print(padding)
        # decrypted_bytes= decrypted_bytes[:-padding]

        cbc_encrypted_img = Image.frombytes(mode, size, encrypted_bytes)
        cbc_encrypted_img.save("cbc_encrypted_image.png")

        # print("Decrypted bytes (CBC):", decrypted_bytes)
        print("Decrypted bytes size (CBC):", len(decrypted_bytes), len (encrypted_bytes))

        decrypted_bytes = data_array[0:160] + decrypted_bytes[160:len(decrypted_bytes)]
        cbc_decrypted_img = Image.frombytes(mode, size, decrypted_bytes)
        cbc_decrypted_img.save("cbc_decrypted_image2.png")