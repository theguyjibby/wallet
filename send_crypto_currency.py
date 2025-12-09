from web3 import Web3
import requests
import os
from dotenv import load_dotenv
import time
from datetime import datetime, timedelta

load_dotenv()

# Price caching to prevent rate limiting
_cached_eth_price = None
_cache_timestamp = None
_CACHE_DURATION = 300  # 5 minutes in seconds

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
    """
    Fetch current ETH price in USD from CoinGecko API with caching.
    Returns cached price if fresh (< 5 minutes old).
    If cache is stale or empty, fetches new price with retry logic.
    Returns last known good price if all retries fail (never returns 0).
    """
    global _cached_eth_price, _cache_timestamp
    
    # Check if cache is valid
    if _cached_eth_price is not None and _cache_timestamp is not None:
        cache_age = time.time() - _cache_timestamp
        if cache_age < _CACHE_DURATION:
            # Cache is fresh, return it
            return _cached_eth_price
    
    # Cache is stale or doesn't exist, fetch new price
    max_retries = 3
    base_delay = 1
    
    for attempt in range(max_retries):
        try:
            url = "https://api.coingecko.com/api/v3/simple/price"
            params = {
                "ids": "ethereum",
                "vs_currencies": "usd"
            }
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if 'ethereum' in data and 'usd' in data['ethereum']:
                price = float(data['ethereum']['usd'])
                # Update cache
                _cached_eth_price = price
                _cache_timestamp = time.time()
                return price
            else:
                print(f"Unexpected API response format: {data}")
                
        except requests.exceptions.Timeout:
            print(f"ETH price API request timed out (attempt {attempt + 1}/{max_retries})")
        except requests.exceptions.RequestException as e:
            print(f"ETH price API request failed: {e} (attempt {attempt + 1}/{max_retries})")
        except (KeyError, ValueError, TypeError) as e:
            print(f"Error parsing ETH price: {e} (attempt {attempt + 1}/{max_retries})")
        except Exception as e:
            print(f"Unexpected error fetching ETH price: {e} (attempt {attempt + 1}/{max_retries})")
        
        # Wait before retrying (exponential backoff: 1s, 2s, 4s)
        if attempt < max_retries - 1:
            delay = base_delay * (2 ** attempt)
            print(f"Retrying in {delay} seconds...")
            time.sleep(delay)
    
    # All retries failed
    # Return cached price if we have one (even if stale), otherwise return a sensible default
    if _cached_eth_price is not None:
        print(f"All API attempts failed. Returning cached price: ${_cached_eth_price}")
        return _cached_eth_price
    else:
        # No cached price available, return approximate market price as fallback
        # This prevents $0 from breaking calculations
        fallback_price = 3300.0
        print(f"No cached price available. Returning fallback: ${fallback_price}")
        return fallback_price


if __name__ == "__main__":
    print(get_eth_price_usd())
