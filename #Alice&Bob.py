from sympy import isprime, nextprime
from datetime import datetime
import hashlib
import os
import random
def generate_prime(bits=1024):
    start = random.getrandbits(bits)
    return nextprime(start)
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a
def lcm(a, b):
    return (a * b) // gcd(a, b)
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1
def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m
def sha256(data: bytes):
    return hashlib.sha256(data).digest()
def mgf1(seed: bytes, length: int):
    counter = 0
    output = b""
    while len(output) < length:
        c = counter.to_bytes(4, "big")
        output += sha256(seed + c)
        counter += 1
    return output[:length]
def oaep_encode(message: bytes, k: int, label: bytes = b""):
    hLen = 32
    if len(message) > k - 2 * hLen - 2:
        raise ValueError("Message too long")
    lHash = sha256(label)
    ps = b"\x00" * (k - len(message) - 2 * hLen - 2)
    db = lHash + ps + b"\x01" + message
    seed = os.urandom(hLen)
    db_mask = mgf1(seed, k - hLen - 1)
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))
    seed_mask = mgf1(masked_db, hLen)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))
    return b"\x00" + masked_seed + masked_db
def oaep_decode(encoded: bytes, k: int, label: bytes = b""):
    hLen = 32
    masked_seed = encoded[1:hLen + 1]
    masked_db = encoded[hLen + 1:]
    seed_mask = mgf1(masked_db, hLen)
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, k - hLen - 1)
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))
    lHash = sha256(label)
    if lHash != db[:hLen]:
        raise ValueError("Decoding error (label mismatch)")
    rest = db[hLen:]
    separator = rest.find(b"\x01")
    if separator == -1:
        raise ValueError("Invalid OAEP structure")
    return rest[separator + 1:]
class RSA:
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.__private_key = 0
        self.public_key = (0, 0)
    def validate(self):
        if not isprime(self.p) or not isprime(self.q):
            raise ValueError("p and q must both be prime")
        if self.p == self.q:
            raise ValueError("p and q must be distinct")
    def generate_keys(self, e=65537):
        n = self.p * self.q
        carmichael_lambda_n = lcm(self.p - 1, self.q - 1)
        if e <= 1 or e >= carmichael_lambda_n or gcd(e, carmichael_lambda_n) != 1:
            raise ValueError("Invalid e")
        d = mod_inverse(e, carmichael_lambda_n)
        self.__private_key = d
        self.public_key = (n, e)
    def encryption(self, message: str):
        n, e = self.public_key
        k = (n.bit_length() + 7) // 8
        if k <= 66:
            raise ValueError("RSA modulus too small for OAEP")
        padded = oaep_encode(message.encode(), k)
        m = int.from_bytes(padded, byteorder="big")
        if m >= n:
            raise ValueError("Message too large for modulus")
        return pow(m, e, n)
    def decryption(self, ciphertext: int):
        n = self.public_key[0]
        d = self.__private_key
        m = pow(ciphertext, d, n)
        k = (n.bit_length() + 7) // 8
        padded = m.to_bytes(k, byteorder="big")
        return oaep_decode(padded, k).decode()
class Person:
    def __init__(self, name: str, p: int, q: int):
        self.name = name
        self.rsa = RSA(p, q)
        self.rsa.validate()
        self.rsa.generate_keys()
        self.inbox = {}
    def receive(self, sender: str, ciphertext: int):
        decrypted = self.rsa.decryption(ciphertext)
        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        self.inbox[timestamp] = { "from": sender,  "message": decrypted}
        print(f"  [{timestamp}] {self.name} received from {sender}: {decrypted}")
    def show_inbox(self):
        print(f"\n── {self.name}'s Inbox ──────────────────")
        if not self.inbox:
            print("  No messages yet.")
        for timestamp, entry in self.inbox.items():
            print(f"  [{timestamp}] From {entry['from']}: {entry['message']}")
class Graph:
    def __init__(self):
        self.connections = {}
    def add_vertex(self, vertex):
        if vertex not in self.connections:
            self.connections[vertex] = []
    def add_edge(self, obj, targ):
        self.add_vertex(obj)
        self.add_vertex(targ)
        self.connections[obj].append(targ)
        self.connections[targ].append(obj)
class Messaging(Graph):
    def __init__(self):
        super().__init__()
        self.people = {}
    def new_person(self, person: Person):
        self.people[person.name] = person
        self.add_vertex(person.name)
    def add_person_to_contact(self, person1: str, person2: str):
        self.add_edge(person1, person2)
    def send_message(self, sender: str, recipients: list, message: str):
        print(f"\n{sender} sending message...")
        for recipient in recipients:
            if recipient in self.connections[sender]:
                recipient_rsa = self.people[recipient].rsa
                ciphertext = recipient_rsa.encryption(message)
                print(f"  Encrypted ciphertext for {recipient}: {str(ciphertext)[:40]}...")
                self.people[recipient].receive(sender, ciphertext)
            else:
                print(f"  {sender} and {recipient} are not contacts")
    def show_all_inboxes(self):
        for person in self.people.values():
            person.show_inbox()
print("Generating primes for Alice...")
p1 = generate_prime(1024)
q1 = generate_prime(1024)
print("Generating primes for Bob...")
p2 = generate_prime(1024)
q2 = generate_prime(1024)
print("Setting up users...")
alice = Person("Alice", p1, q1)
bob   = Person("Bob",   p2, q2)
m = Messaging()
m.new_person(alice)
m.new_person(bob)
m.add_person_to_contact("Alice", "Bob")
m.send_message("Alice", ["Bob"], "Hello Bob, this is a secret message!")
m.send_message("Bob", ["Alice"], "Hey Alice, got your message!")
m.show_all_inboxes()

