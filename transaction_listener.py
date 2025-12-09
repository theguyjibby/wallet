import time
from web3 import Web3
from web333 import app, db, Transactions, Account
import os
from dotenv import load_dotenv

load_dotenv()

# Connect to Infura
INFURA_URL = os.getenv('INFURA_URL', 'https://sepolia.infura.io/v3/YOUR_INFURA_ID')
w3 = Web3(Web3.HTTPProvider(INFURA_URL))

def listen_loop():
    """
    Continuously polls for new blocks and checks for transactions 
    involving local accounts.
    """
    if not w3.is_connected():
        print("Failed to connect to Infura.")
        return

    print("Starting transaction listener...")
    print("Press Ctrl+C to stop.")
    
    # Start from the current block
    last_block_number = w3.eth.block_number
    
    while True:
        try:
            current_block_number = w3.eth.block_number
            
            # If we are behind, catch up
            if current_block_number > last_block_number:
                # Process all blocks from last_seen + 1 to current
                for block_num in range(last_block_number + 1, current_block_number + 1):
                    process_block(block_num)
                
                last_block_number = current_block_number
            
            # Wait a bit before checking again (avg block time is 12s)
            time.sleep(10)
            
        except KeyboardInterrupt:
            print("Stopping listener...")
            break
        except Exception as e:
            print(f"Error in main loop: {e}")
            time.sleep(5)

def process_block(block_number):
    print(f"Scanning block {block_number}...")
    try:
        # Get block with full transactions
        block = w3.eth.get_block(block_number, full_transactions=True)
        
        # Get all local account addresses to check against
        # We fetch this fresh for each block in case new accounts are created
        with app.app_context():
            # Create a dictionary for fast lookup: {address_lower: user_id}
            local_accounts = {acc.address.lower(): acc.user_id for acc in Account.query.all()}
        
        if not local_accounts:
            return

        for tx in block.transactions:
            # Check if 'to' address matches one of our accounts
            if tx['to'] and tx['to'].lower() in local_accounts:
                user_id = local_accounts[tx['to'].lower()]
                save_incoming_transaction(tx, user_id)
                
    except Exception as e:
        print(f"Error processing block {block_number}: {e}")

def save_incoming_transaction(tx, user_id):
    with app.app_context():
        try:
            tx_hash = tx['hash'].hex()
            
            # Check if we already saved this transaction for THIS user to avoid duplicates
            if Transactions.query.filter_by(tx_hash=tx_hash, user_id=user_id).first():
                return

            print(f" >>> FOUND DEPOSIT! Tx: {tx_hash} <<<")
            
            amount_eth = float(w3.from_wei(tx['value'], 'ether'))
            
            new_tx = Transactions(
                user_id=user_id,
                from_address=tx['from'],
                to_address=tx['to'],
                amount=amount_eth,
                crypto_currency="ETH", # Assuming ETH for now
                tx_hash=tx_hash,
                is_sent=False # This is an incoming transaction
            )
            
            db.session.add(new_tx)
            db.session.commit()
            print("Transaction saved to database.")
            
        except Exception as e:
            print(f"Error saving transaction: {e}")

if __name__ == "__main__":
    listen_loop()