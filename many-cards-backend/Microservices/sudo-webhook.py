import requests

# Sudo API Config
SUDO_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2ODNkMzhlODE4NDBhMzc1MTJkNGQwMjMiLCJlbWFpbEFkZHJlc3MiOiJpbmlsb25nZUBnbWFpbC5jb20iLCJqdGkiOiI2ODNkNjBkZTE4NDBhMzc1MTJkNGY2OWQiLCJtZW1iZXJzaGlwIjp7Il9pZCI6IjY4M2QzOGU4MTg0MGEzNzUxMmQ0ZDAyNSIsImJ1c2luZXNzIjp7Il9pZCI6IjY4M2QzOGU4MTg0MGEzNzUxMmQ0ZDAyMSIsIm5hbWUiOiJNYW55Q2FyZHMgSW5jLiIsImlzQXBwcm92ZWQiOmZhbHNlfSwidXNlciI6IjY4M2QzOGU4MTg0MGEzNzUxMmQ0ZDAyMyIsInJvbGUiOiJBUElLZXkifSwiaWF0IjoxNzQ4ODUyOTU4LCJleHAiOjE3ODA0MTA1NTh9.OIHjolMjZOFgqfgaHN6xleQkkr04HFg2mKSLVZcl_lg"
SUDO_BASE_URL = "https://api.sandbox.sudo.cards/cards"  # Added /v1/


def create_sudo_virtual_card(amount: float, customer_email: str):
    headers = {
        "Authorization": f"Bearer {SUDO_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "type": "virtual",  # Required field
        "currency": "NGN",  # Only NGN or USD supported
        "amount": amount,
        "customerEmail": customer_email,
        "customerId": "unique_customer_id_24chars",  # Exactly 24 chars
        "issuerCountry": "NGA",  # Nigeria
        "status": "active",  # Required field
        "enable2FA": False,  # Must be boolean
        "disposable": False,  # Must be boolean
    }

    response = requests.post(SUDO_BASE_URL, json=payload, headers=headers)
    return response.json()


# Example: Generate Card (only NGN or USD)
card = create_sudo_virtual_card(50.0, "inilonge@gmail.com")  # Fixed email typo
print(card)
