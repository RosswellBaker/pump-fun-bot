import requests
from monitoring.filters import get_buy_instruction_amount, should_process_token

# Regular Solana RPC endpoint
SOLANA_RPC_ENDPOINT = "https://api.mainnet-beta.solana.com"

def fetch_transaction_logs(tx_hash: str) -> list[str]:
    """
    Fetches the logs for a given transaction hash from the Solana blockchain.

    Args:
        tx_hash: The transaction hash to fetch logs for.

    Returns:
        A list of logs from the transaction.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [tx_hash, {"encoding": "json", "commitment": "processed"}]  # Updated commitment level
    }
    response = requests.post(SOLANA_RPC_ENDPOINT, json=payload)
    print(f"RPC Response: {response.json()}")  # Debugging statement

    if response.status_code != 200:
        raise Exception(f"Failed to fetch transaction: {response.text}")

    result = response.json().get("result", {})
    if not result:
        raise Exception(f"No transaction found for hash: {tx_hash}")

    # Extract logs from the transaction result
    logs = result.get("meta", {}).get("logMessages", [])
    if not logs:
        raise Exception(f"No logs found for transaction: {tx_hash}")

    return logs

def test_filters(tx_hash: str) -> None:
    """
    Tests the filtering logic for a given transaction hash.

    Args:
        tx_hash: The transaction hash to test.

    Prints:
        The extracted buy instruction amount and whether the token passes the filter.
    """
    try:
        # Fetch the logs for the transaction
        logs = fetch_transaction_logs(tx_hash)

        # Extract the buy instruction amount
        buy_amount = get_buy_instruction_amount(logs)

        if buy_amount is None:
            print(f"Transaction {tx_hash}: No valid buy instruction found.")
            return

        # Check if the token passes the filter
        if should_process_token(logs):
            print(f"Transaction {tx_hash}: Passed filter. Buy amount: {buy_amount}")
        else:
            print(f"Transaction {tx_hash}: Skipped. Buy amount: {buy_amount} exceeds threshold.")
    except Exception as e:
        print(f"Error testing transaction {tx_hash}: {e}")

if __name__ == "__main__":
    # Input the transaction hash to test
    tx_hash = input("Enter the transaction hash (tx_hash) to test: ").strip()
    test_filters(tx_hash)