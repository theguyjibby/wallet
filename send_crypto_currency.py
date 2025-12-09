from web3 import Web3
import requests
import os
from dotenv import load_dotenv

load_dotenv()

INFURA_URL = os.getenv('INFURA_URL', 'https://sepolia.infura.io/v3/YOUR_INFURA_ID')
w3 = Web3(Web3.HTTPProvider(INFURA_URL))
if w3.is_connected():
    print("Connected to Ethereum network")
else:
    print("Warning: Could not connect to Ethereum network on startup. Operations needing network will fail.")

def send_crypto(from_address, private_key, to_address, amount, crypto_currency='ETH', token_address=None, token_abi=None):
    nonce = w3.eth.get_transaction_count(from_address)

    if crypto_currency.upper() == 'ETH':
        gas_limit = 21000
        balance_wei = w3.eth.get_balance(from_address)
        total_cost_wei = w3.to_wei(amount, 'ether') + gas_limit * w3.eth.gas_price
        if balance_wei < total_cost_wei:
            raise Exception("Insufficient balance to cover amount and gas fees")
        
        tx = {
            'nonce': nonce,
            'to': to_address,
            'value': w3.to_wei(amount, 'ether'),
            'gas': gas_limit,
            'gasPrice': w3.eth.gas_price,
        }
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)  # Ensure this is correct
        return tx_hash.hex()
    else:
        if not token_address or not token_abi:
            raise Exception("Token address and ABI must be provided for token transfers")
        
        token_contract = w3.eth.contract(address=token_address, abi=token_abi)
        decimals = token_contract.functions.decimals().call()
        token_amount = int(amount * (10 ** decimals))
        
        tx = token_contract.functions.transfer(to_address, token_amount).build_transaction({
            'nonce': nonce,
            'gas': 100000,
            'gasPrice': w3.eth.gas_price,
        })
        gas_limit = w3.eth.estimate_gas(tx)
        tx['gas'] = gas_limit

        balance_wei = w3.eth.get_balance(from_address)
        if balance_wei < gas_limit * w3.eth.gas_price:
            raise Exception("Insufficient balance to cover gas fees")
        
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)  # Ensure this is correct
        return tx_hash.hex()

        
        



def check_balance(address):
    balance_wei = w3.eth.get_balance(address)
    balance_eth = w3.from_wei(balance_wei, 'ether')
    return balance_eth

def get_eth_price_usd():
    try:
        url ="https://api.coingecko.com/api/v3/simple/price"
        params= {
            "ids": "ethereum",
            "vs_currencies": "usd"

        }
        response = requests.get(url, params=params)
        data = response.json()
        price = data['ethereum']['usd']
        return price
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    print(get_eth_price_usd())
