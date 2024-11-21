# from flask import Flask, render_template, request, redirect, url_for
# from blockchain import Blockchain
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.backends import default_backend

# app = Flask(__name__)
# blockchain = Blockchain()

# # Load private key from the generated PEM file

# def load_private_key():
#     try:
#         with open("private_key.pem", "rb") as f:
#             private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
#             if private_key is None:
#                 raise ValueError("Failed to load private key.")
#             return private_key
#     except Exception as e:
#         print(f"Error loading private key: {e}")
#         return None



# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/submit_transaction', methods=['POST'])
# def submit_transaction():
#     sender = request.form['sender']
#     recipient = request.form['recipient']
#     amount = request.form['amount']
    
#     # Load private key
#     private_key = load_private_key()
#     if private_key is None:
#         return "Error: Private key not found or invalid.", 500  # Or redirect to an error page
    
#     transaction_data = f"{sender}{recipient}{amount}"
    
#     try:
#         # Sign the transaction using the private key
#         signature = private_key.sign(
#             transaction_data.encode(),
#             padding.PKCS1v15(),
#             hashes.SHA256()
#         )
#     except Exception as e:
#         return f"Error during signing: {e}", 500
    
#     # Add the new transaction with the signature
#     blockchain.new_transaction(sender, recipient, amount, signature)
    
#     # Display transaction details
#     print(f"New transaction added: {sender} -> {recipient} : {amount} units")
#     print(f"Transaction Signature: {signature.hex()}")

#     # Get last block's hash and find nonce for proof of work
#     last_block_hash = blockchain.chain[-1].hash
#     proof = blockchain.proof_of_work(last_block_hash)
    
#     # Mine a new block and add it to the chain
#     new_block = blockchain.new_block(proof)

#     # Display block details
#     print(f"\nBlock mined! Block index: {new_block.index}, Transactions: {new_block.data}, "
#           f"Proof: {proof}, Previous hash: {new_block.previous_hash}, Hash: {new_block.hash}")
    
#     # Redirect to the confirmation page
#     return redirect(url_for('confirmation'))

# @app.route('/confirmation')
# def confirmation():
#     return render_template('confirmation.html')

# if __name__ == '__main__':
#     app.run(debug=True)


from flask import Flask, render_template, request, redirect, url_for
from blockchain import Blockchain
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
blockchain = Blockchain()

# Load private key from the generated PEM file
def load_private_key():
    try:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            if private_key is None:
                raise ValueError("Failed to load private key.")
            return private_key
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit_transaction', methods=['POST'])
def submit_transaction():
    sender = request.form['sender']
    recipient = request.form['recipient']
    amount = request.form['amount']
    
    # Load private key
    private_key = load_private_key()
    if private_key is None:
        return "Error: Private key not found or invalid.", 500  # Or redirect to an error page
    
    transaction_data = f"{sender}{recipient}{amount}"
    
    try:
        # Sign the transaction using the private key
        signature = private_key.sign(
            transaction_data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception as e:
        return f"Error during signing: {e}", 500
    
    # Add the new transaction with the signature
    blockchain.new_transaction(sender, recipient, amount, signature)
    
    # Display transaction details
    print(f"New transaction added: {sender} -> {recipient} : {amount} units")
    print(f"Transaction Signature: {signature.hex()}")

    # Get last block's hash and find nonce for proof of work
    last_block_hash = blockchain.chain[-1].hash
    proof = blockchain.proof_of_work(last_block_hash)
    
    # Mine a new block and add it to the chain
    new_block = blockchain.new_block(proof)

    # Display block details
    print(f"\nBlock mined! Block index: {new_block.index}, Transactions: {new_block.data}, "
          f"Proof: {proof}, Previous hash: {new_block.previous_hash}, Hash: {new_block.hash}")
    
    # Redirect to the confirmation page
    return redirect(url_for('confirmation'))

@app.route('/confirmation')
def confirmation():
    return render_template('confirmation.html')

@app.route('/transaction_history')
def transaction_history():
    # Retrieve all transactions from the blockchain for the history page
    transactions = []
    for block in blockchain.chain:
        print(f"Block {block.index} data: {block.data}")  # Debug: Print block data
        
        for transaction in block.data:
            # Check if transaction is a dictionary or needs parsing
            if isinstance(transaction, dict):
                # Transaction is in expected dictionary format
                transactions.append({
                    "sender": transaction.get("sender"),
                    "recipient": transaction.get("recipient"),
                    "amount": transaction.get("amount"),
                    # "signature": transaction.get("signature").hex() if isinstance(transaction.get("signature"), bytes) else transaction.get("signature"),
                    "block_index": block.index,
                    "timestamp": block.timestamp
                })
            else:
                # If transaction is a string, log it as an unexpected format
                print(f"Unexpected transaction format in block {block.index}: {transaction}")
    
    return render_template('transaction_history.html', transactions=transactions)

if __name__ == '__main__':
    app.run(debug=True)
