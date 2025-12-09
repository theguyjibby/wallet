from eth_account import Account as ethAccount



ethAccount.enable_unaudited_hdwallet_features()


def derive_account(mnemonics, index):
    path = f"m/44'/60'/0'/0/{index}"
    acct = ethAccount.from_mnemonic(mnemonics, account_path=path)
    return acct.address, acct.key.hex()

