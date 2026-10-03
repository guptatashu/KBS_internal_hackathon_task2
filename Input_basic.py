def get_address():
    return input("Enter contract address: ").strip()


def validate_address(address):
    if not address.startswith("0x"):
        return False
    if len(address) != 42:
        return False

    hex_part = address[2:]
    hex_chars = "0123456789abcdefABCDEF"
    return all(c in hex_chars for c in hex_part)


def main():
    while True:
        address = get_address()
        if validate_address(address):
            print("Valid address:", address)
            break
        else:
            print("Invalid address. Please try again.")


if __name__ == "__main__":
    main()