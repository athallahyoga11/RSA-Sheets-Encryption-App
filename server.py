import socket
import threading
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

class P2PServer:
    def __init__(self):
        self.host = socket.gethostname()
        self.port = 12345
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.clients = {}

        # Generate public and private keypair
        p = 17
        q = 19
        self.public_key, self.private_key = generate_keypair(p, q)

    def handle_client(self, conn, addr):
        # Register new client
        self.clients[addr] = conn

        # Send public key to client
        public_key_str = str(self.public_key[0]) + ',' + str(self.public_key[1])
        conn.send(public_key_str.encode())

        # Receive and decrypt message from client
        encrypted_msg = conn.recv(1024)
        decrypted_msg = decrypt(self.private_key, encrypted_msg.decode())

        # Send encrypted message back to client
        encrypted_msg = encrypt(self.public_key, decrypted_msg)
        conn.send(bytes(str(encrypted_msg), 'utf-8'))

        # Close connection
        conn.close()
        del self.clients[addr]

    def start(self):
        print('Server started')
        while True:
            conn, addr = self.server_socket.accept()
            print('New connection from', addr)
            client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            client_thread.start()

def main():
    p2p_server = P2PServer()
    p2p_server.start()

if __name__ == '__main__':
    main()
