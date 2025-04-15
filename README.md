# TelegramBot-WakeOnLan

## 🚀 Project Overview
This is my Telegram bot that I use to remotely manage Windows PC on my network. It allows me to send Wake-on-LAN (WoL) packets to wake up Windows PC, as well as perform actions like restarting or shutting it down.

## 📋 Requirements
- Python 3.8+
- A Telegram bot token (set via environment variable `BOT_TOKEN`)
- Target machine's MAC address and network configuration for WoL

## 🔧 Setup Instructions
1. Clone the repository:
    ```bash
    git clone <repository-url>
    ```
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Set up environment variables:
    - `BOT_TOKEN`: Your Telegram bot token (required).
    - `ALLOWED_USER_ID`: The Telegram user ID allowed to interact with the bot (required).
    - `TARGET_MAC`: The MAC address of the target machine (required).
    - `TARGET_IP`: The IP address of the target machine (required).
    - `BROADCAST_IP`: The broadcast IP for sending Wake-on-LAN packets (required).
    - `WIN_CRED_FILE`: Absolute path to a Windows credentials file (required for restart/shutdown actions).
    - `TARGET_NAME`: (Optional) User-friendly name for the target PC. Defaults to "Main PC".

4. Run the bot:
    ```bash
    python wol-bot/wol-bot.py
    ```

## ⚠️ Security Notes
- Ensure sensitive information (e.g., `BOT_TOKEN`, credentials) is stored securely and not hardcoded.
- Avoid committing `.env` files or other sensitive configurations to the repository.

---

🌟 Happy coding!

