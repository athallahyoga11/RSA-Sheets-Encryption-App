import socket
import random
import math

def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for i in range(3, int(num**0.5) + 1, 2):
        if num % i == 0:
            return False
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    elif p == q:
        raise ValueError("p and q cannot be equal")

    n = p * q
    phi = (p-1) * (q-1)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Calculate the private key
    d = pow(e, -1, phi)

    # Return public and private keypair
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    key, n = public_key
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher

def decrypt(private_key, ciphertext):
    key, n = private_key
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    return ''.join(plain)

def main():
    host = input('Enter server hostname or IP address: ')
    port = 12345
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    # Receive public key from server
    public_key_str = client_socket.recv(1024).decode()
    public_key = tuple(map(int, public_key_str.split(',')))

    # Encrypt and send message to server
    message = input('Enter message to encrypt: ')
    encrypted_msg = encrypt(public_key, message)
    client_socket.send(bytes(str(encrypted_msg), 'utf-8'))

    # Receive and decrypt message from server
    encrypted_msg = client_socket.recv(1024)
    decrypted_msg = decrypt((0, 0), eval(encrypted_msg.decode()))

    print('Decrypted message:', decrypted_msg)

    # Close connection
    client_socket.close()

if __name__ == '__main__':
    main()
