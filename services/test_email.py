import os
import requests
from dotenv import load_dotenv

# Load environment variables from a .env file (if you have one)
load_dotenv()

def send_simple_message():
    # Get API key from environment variable
    api_key = os.getenv('MAILGUN_API_KEY')
    if not api_key:
        raise ValueError("MAILGUN_API_KEY not set in environment variables")

    return requests.post(
        "https://api.mailgun.net/v3/sandboxd287f87ac85e4b3c8c3527e41cfa3edb.mailgun.org/messages",
        auth=("api", api_key),
        data={
            "from": "ThrillBill <ThrillBill@footballprophesy.com>",
            "to": "Bill Klinkatsis <billklinkatsis@gmail.com>",
            "subject": "Hello Bill Klinkatsis",
            "text": "Congratulations Bill Klinkatsis, you just sent an email with Mailgun! You are truly awesome!"
        }
    )

# Call the function and print response for debugging
if __name__ == "__main__":
    response = send_simple_message()
    print("Status Code:", response.status_code)
    print("Response Body:", response.text)