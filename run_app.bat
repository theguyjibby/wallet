@echo off
echo Starting Web3 Wallet...

:: Start the Transaction Listener in a new window
start "Transaction Listener" cmd /k "python transaction_listener.py"

:: Start the Flask Application in the current window
echo Starting Web Server...
python web333.py
