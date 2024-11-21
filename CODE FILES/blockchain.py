import hashlib
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash=None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash or self.calculate_hash()

    def calculate_hash(self):
        value = str(self.index) + str(self.previous_hash) + str(self.timestamp) + json.dumps(self.data)
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 2
        self.current_transactions = []

    def create_genesis_block(self):
        return Block(0, "0", int(time.time()), "Genesis Block")

    def proof_of_work(self, last_hash):
        nonce = 0
        while self.valid_proof(last_hash, nonce) is False:
            nonce += 1
        return nonce

    def valid_proof(self, last_hash, nonce):
        guess = f"{last_hash}{nonce}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:self.difficulty] == "0" * self.difficulty

    def new_transaction(self, sender, recipient, amount, signature):
        transaction_data = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'signature': signature.hex()  # Store signature as hexadecimal string
        }
        self.current_transactions.append(transaction_data)
    
    def new_block(self, proof):
        last_block = self.chain[-1]
        block = Block(
            index=last_block.index + 1,
            previous_hash=last_block.hash,
            timestamp=time.time(),
            data=self.current_transactions
        )
        self.chain.append(block)
        self.current_transactions = []
        return block