TOKENS = {
    "USDT": {
        "symbol": "USDT",
        "address": "0x01a6810727db185bbf7f30ec158c3ac8b8112627", # Sepolia USDT Address
        "decimals": 6,
        "type": "erc20"
    },
    "DAI" : {
        "symbol": "DAI",
        "address": "0x3e622317f8C93f7328350cF0B56d9eD4C620C5d6", # Sepolia DAI Address
        "decimals": 18,
        "type": "erc20"
    }
}

# The ERC20 ABI remains the same as it defines the standard interface
ERC20_ABI = [
    {"constant":True,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"},
    {"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
    {"constant":True,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"},
    {"constant":False,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}
]
