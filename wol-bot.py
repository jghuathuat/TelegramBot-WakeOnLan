#!/usr/bin/env python3

import asyncio
import logging
import os
import platform
import subprocess
import sys
from functools import wraps
from typing import Optional, Dict

# Telegram Bot imports
import telegram # Import root package for error handling
from telegram import (Bot, BotCommand, InlineKeyboardButton,
                      InlineKeyboardMarkup, Update)
from telegram.ext import (Application, ApplicationBuilder, CallbackQueryHandler,
                          CommandHandler, ContextTypes)
from telegram.constants import ParseMode # Optional: if you ever need message formatting

# === Configuration Loading (via Environment Variables) ===
# --- IMPORTANT FOR SYSTEMD ---
# These variables MUST be set in the systemd unit file (.service)
# or loaded via EnvironmentFile=.

BOT_TOKEN = os.environ.get("BOT_TOKEN")
ALLOWED_USER_ID_STR = os.environ.get("ALLOWED_USER_ID")
TARGET_MAC = os.environ.get("TARGET_MAC")
TARGET_IP = os.environ.get("TARGET_IP")
BROADCAST_IP = os.environ.get("BROADCAST_IP")

# --- CRITICAL: Path to Windows Credentials File ---
# MUST be an ABSOLUTE PATH. Ensure the service user has read permissions ONLY (chmod 600).
WIN_CRED_FILE = os.environ.get("WIN_CRED_FILE")

# Optional: User-friendly name for the target PC. Defaults to "Main PC".
TARGET_NAME = os.environ.get("TARGET_NAME", "Main PC")


# === Callback Data Constants ===
CALLBACK_WAKE = 'wake'
CALLBACK_STATUS = 'status'
CALLBACK_CONFIRM_RESTART = 'confirm_restart'
CALLBACK_CONFIRM_SHUTDOWN = 'confirm_shutdown'
CALLBACK_DO_RESTART = 'do_restart'
CALLBACK_DO_SHUTDOWN = 'do_shutdown'
CALLBACK_REFRESH_MENU = 'refresh_menu'


# === Environment Variable Validation & Initialization ===

# Validates required environment variables and converts types.
def validate_config_and_init():
    global ALLOWED_USER_ID # Allow modification of the global variable

    required = {
        "BOT_TOKEN": BOT_TOKEN,
        "ALLOWED_USER_ID": ALLOWED_USER_ID_STR,
        "TARGET_MAC": TARGET_MAC,
        "TARGET_IP": TARGET_IP,
        "BROADCAST_IP": BROADCAST_IP,
        "WIN_CRED_FILE": WIN_CRED_FILE,
    }

    missing = [name for name, value in required.items() if not value]
    if missing:
        print(f"❌ Error: Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    try:
        ALLOWED_USER_ID = int(ALLOWED_USER_ID_STR)
    except (ValueError, TypeError):
        print(f"❌ Error: ALLOWED_USER_ID is not a valid integer: '{ALLOWED_USER_ID_STR}'", file=sys.stderr)
        sys.exit(1)

    if ':' not in BOT_TOKEN:
        print(f"❌ Error: BOT_TOKEN format seems invalid.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isabs(WIN_CRED_FILE):
        print(f"❌ Error: WIN_CRED_FILE path ('{WIN_CRED_FILE}') must be an absolute path.", file=sys.stderr)
        sys.exit(1)

# Run validation immediately
validate_config_and_init()

# === Logging Setup (for Systemd/Journald) ===

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s] - %(message)s', # Added funcName
    level=logging.INFO,
    handlers=[logging.StreamHandler(sys.stdout)] # Log to stdout for journald
)
logger = logging.getLogger(__name__)


# === Security & Dependency Notes ===
#
# * Running as Systemd Service (Linux Host): *
#   - Configure using Environment Variables in the .service file or EnvironmentFile=.
#   - Use absolute paths, especially for WIN_CRED_FILE.
#   - Run the service as a dedicated non-root user (`User=`, `Group=`).
#   - Ensure the service user has read-only access to WIN_CRED_FILE and EnvironmentFile if used (`chmod 600`, `chown`).
#   - Install dependencies (`wakeonlan`, `samba-common-bin`, `iputils-ping`) on the Linux host.
#   - Check logs with `journalctl -u your-service-name.service -f`.
#   - Set `WorkingDirectory=` in the .service file.
#
# * Windows Credentials File (`WIN_CRED_FILE`): *
#   - Format:
#     username=YOUR_WINDOWS_USERNAME
#     password=YOUR_WINDOWS_PASSWORD
#   - Store securely with strict file permissions (readable only by service user).
#   - Plaintext password storage has inherent risks. Consider alternatives if feasible in your environment.
#
# * Required Linux Command-Line Tools: *
#   - `wakeonlan`: For Wake-on-LAN.
#   - `net` (from `samba-common-bin`): For Windows RPC shutdown/restart.
#   - `ping`: For status checks.


# === Keyboard Menus ===

# Creates the main control menu keyboard.
def create_main_menu() -> InlineKeyboardMarkup:
    keyboard = [
        [InlineKeyboardButton(f"💤 Wake {TARGET_NAME}", callback_data=CALLBACK_WAKE)],
        [InlineKeyboardButton("📶 Check Status", callback_data=CALLBACK_STATUS)],
        [InlineKeyboardButton(f"🔁 Restart {TARGET_NAME}", callback_data=CALLBACK_CONFIRM_RESTART)],
        [InlineKeyboardButton(f"⛔ Shutdown {TARGET_NAME}", callback_data=CALLBACK_CONFIRM_SHUTDOWN)],
        [InlineKeyboardButton("🔄 Refresh Menu", callback_data=CALLBACK_REFRESH_MENU)]
    ]
    return InlineKeyboardMarkup(keyboard)

# Creates a Yes/No confirmation menu for restart or shutdown.
def create_confirmation_menu(action: str) -> InlineKeyboardMarkup:
    callback_action = CALLBACK_DO_RESTART if action == 'restart' else CALLBACK_DO_SHUTDOWN
    keyboard = [
        [InlineKeyboardButton("✅ Yes", callback_data=callback_action),
         InlineKeyboardButton("❌ Cancel", callback_data=CALLBACK_REFRESH_MENU)]
    ]
    return InlineKeyboardMarkup(keyboard)

# === Authorization Decorator ===

# Decorator to verify the action is initiated by the ALLOWED_USER_ID.
def authorized_user_only(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if not user or user.id != ALLOWED_USER_ID:
            user_id_str = f"user ID {user.id}" if user else "unknown user"
            username_str = f" ('{user.username}')" if user and user.username else ""
            logger.warning(f"Unauthorized access attempt by {user_id_str}{username_str}")
            if update.callback_query:
                try:
                    # Answer silently for unauthorized button presses unless you want an alert
                    await update.callback_query.answer("❌ Unauthorized.", show_alert=False)
                except Exception as e:
                    logger.error(f"Error sending unauthorized callback answer: {e}")
            elif update.message:
                 await update.message.reply_text("❌ Unauthorized.")
            return None # Stop processing
        return await func(update, context, *args, **kwargs)
    return wrapper


# === Core Action Functions ===

# Helper to run blocking subprocess calls asynchronously.
# Raises exceptions on failure (FileNotFoundError, CalledProcessError, TimeoutExpired).
async def _run_subprocess(command: list[str], timeout: int, check: bool = True) -> subprocess.CompletedProcess:
    try:
        process = await asyncio.to_thread(
            subprocess.run,
            command,
            capture_output=True,
            text=True,
            check=check, # Raise CalledProcessError if check=True and return code != 0
            timeout=timeout
        )
        return process
    except FileNotFoundError as e:
        logger.error(f"Command not found: '{command[0]}'. Is it installed and in PATH? Error: {e}")
        raise # Re-raise to be caught by caller
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "(No stderr)"
        logger.error(f"Command '{command[0]}' failed (code {e.returncode}): {stderr_output}")
        raise # Re-raise
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command '{command[0]}' timed out after {timeout} seconds.")
        raise # Re-raise
    except Exception as e:
        logger.exception(f"Unexpected error running command '{command[0]}': {e}")
        raise # Re-raise


# Sends the Wake-on-LAN packet.
# Returns a status message string for the user.
async def wake_pc_action() -> str:
    logger.info(f"Attempting wake for MAC {TARGET_MAC} via {BROADCAST_IP}")
    command = ['wakeonlan', '-i', BROADCAST_IP, TARGET_MAC]
    try:
        process = await _run_subprocess(command, timeout=10)
        logger.info(f"Wakeonlan success. Output: {process.stdout.strip()}")
        return f"✅ Wake signal sent to {TARGET_NAME}."
    except FileNotFoundError:
        return "❌ Error: 'wakeonlan' command not found on server."
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, Exception) as e:
        # Specific errors logged in _run_subprocess or here if unexpected
        return f"❌ Error sending wake signal: {e}"


# Checks PC status using ping.
# Returns a status message string for the user.
async def check_status() -> str:
    logger.info(f"Pinging {TARGET_IP} ({TARGET_NAME})")
    system = platform.system().lower()
    try:
        # Use Linux/macOS ping parameters by default for systemd context
        params = ['-c', '1', '-W', '1']
        if system == 'windows': # Safety check if run elsewhere
            params = ['-n', '1', '-w', '1000']

        command = ['ping'] + params + [TARGET_IP]
        # Run ping but ignore output/errors, just check return code
        result = await asyncio.to_thread(
            subprocess.run, command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
        )
        status = "🟢 Online" if result.returncode == 0 else "🔴 Offline"
        logger.info(f"Ping result for {TARGET_IP}: {status} (Code: {result.returncode})")
        return status
    except subprocess.TimeoutExpired:
        logger.warning(f"Ping command to {TARGET_IP} timed out.")
        return "🟡 Timeout"
    except FileNotFoundError:
        logger.error("'ping' command not found. Check 'iputils-ping' package.")
        return "⚠️ Error ('ping' not found)"
    except Exception as e: # Catch potential unexpected errors from subprocess.run itself
        logger.exception(f"Unexpected error checking status for {TARGET_IP}: {e}")
        return "⚠️ Error"


# Reads 'username' and 'password' from WIN_CRED_FILE.
# Returns a dictionary {'username': 'user', 'password': 'pass'} or None on error.
def read_windows_credentials() -> Optional[Dict[str, str]]:
    creds: Dict[str, str] = {}
    if not os.path.exists(WIN_CRED_FILE):
        logger.error(f"Credentials file does not exist: {WIN_CRED_FILE}")
        return None

    try:
        with open(WIN_CRED_FILE, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split("=", 1)
                    creds[key.strip().lower()] = value.strip()
                else:
                    logger.warning(f"Skipping malformed line {line_num} in {WIN_CRED_FILE}: '{line}'")

        user = creds.get('username')
        password = creds.get('password')

        if user is None or password is None:
             logger.error(f"'username' or 'password' key missing/malformed in {WIN_CRED_FILE}")
             return None
        if not user:
             logger.error(f"'username' cannot be empty in {WIN_CRED_FILE}")
             return None
        return creds # Contains {'username': '...', 'password': '...'}

    except PermissionError:
         logger.error(f"Permission denied reading credentials file: {WIN_CRED_FILE}. Check service user permissions.")
         return None
    except Exception as e:
        logger.exception(f"Unexpected error reading credentials file {WIN_CRED_FILE}: {e}")
        return None


# Executes remote shutdown/restart via 'net rpc shutdown'.
# Returns a status message string for the user.
async def run_net_rpc(action_type: str) -> str:
    if action_type not in ['shutdown', 'restart']:
        logger.error(f"Invalid action_type '{action_type}' for run_net_rpc")
        return "❌ Internal Error: Invalid action."

    logger.info(f"Attempting RPC '{action_type}' on {TARGET_IP} ({TARGET_NAME})")

    creds = read_windows_credentials()
    if not creds:
        return "❌ Error: Could not load/validate credentials. Check logs."

    user = creds['username']
    password = creds['password']

    action_flag = '-r' if action_type == 'restart' else '-S'
    log_action = action_type.capitalize()
    # Note: Using double quotes around the comment for the shell requires careful handling
    # if the comment itself contains quotes. Simpler comment is safer.
    command = [
        'net', 'rpc', 'shutdown', action_flag,
        '-f', '-t', '5', '-C', 'BotAction', # Force, 5s delay, Simple Comment
        '-I', TARGET_IP, '-U', f"{user}%{password}"
    ]

    # Log command safely (mask password)
    try:
        masked_command_str = subprocess.list2cmdline(
            [part if not (part.startswith('-U') and f"{user}%" in part) else f"-U {user}%********" for part in command]
        )
        logger.info(f"Executing command: {masked_command_str}")
    except Exception as log_e:
        logger.error(f"Error preparing command for logging: {log_e}")
        logger.info(f"Executing command: net rpc shutdown {action_flag} ... -I {TARGET_IP} -U {user}%********")

    # Execute command - we check return code manually
    try:
        result = await _run_subprocess(command, timeout=30, check=False)

        if result.returncode == 0:
            stdout_output = result.stdout.strip() if result.stdout else "(No stdout)"
            logger.info(f"RPC {log_action} success for {TARGET_IP}. Stdout: {stdout_output}")
            return f"✅ {log_action} command sent successfully."
        else:
            # Log detailed error, return user-friendly message
            error_message = (result.stderr or result.stdout).strip()
            logger.error(f"RPC {log_action} failed for {TARGET_IP}. Code: {result.returncode}. Output: {error_message}")
            # Provide specific feedback based on common Samba/RPC errors
            if "NT_STATUS_LOGON_FAILURE" in error_message:
                return "❌ Failed: Authentication error (check creds)."
            elif "NT_STATUS_HOST_UNREACHABLE" in error_message or "Connection refused" in error_message:
                 return f"❌ Failed: Host unreachable or RPC blocked."
            elif "NT_STATUS_ACCESS_DENIED" in error_message:
                 return f"❌ Failed: Access Denied (check Windows permissions)."
            elif "NT_STATUS_INVALID_PARAMETER" in error_message or "invalid option" in error_message:
                 return f"❌ Failed: Invalid command parameter."
            else:
                 error_snippet = error_message[:80] + ('...' if len(error_message) > 80 else '')
                 return f"❌ Failed: RPC error ({error_snippet})"

    except FileNotFoundError:
        return "❌ Error: 'net' command not found (is samba-common-bin installed?)."
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        # Specific errors already logged by _run_subprocess or here if check=False
        return f"❌ Failed: RPC command execution error or timeout."
    except Exception as e:
        # Unexpected errors during the process
        return f"❌ Unexpected error during RPC execution: {e}"


# === Telegram Bot Handlers & Helpers ===

# Safely edits a message, ignoring 'Message is not modified' errors.
# Raises other exceptions (e.g., BadRequest, NetworkError) for general handling.
async def _edit_message(query: telegram.CallbackQuery, text: str, markup: Optional[InlineKeyboardMarkup] = None):
    try:
        # Ensure the query object and its message attribute exist
        if query and query.message:
             await query.edit_message_text(text=text, reply_markup=markup)
             logger.debug(f"Message edited: '{text[:30]}...'")
        else:
             logger.warning("Attempted to edit message, but query or query.message was None.")
    except telegram.error.BadRequest as e:
        if "Message is not modified" in str(e):
            logger.debug("Message edit resulted in no change. Ignoring Telegram error.")
        else:
            # Re-raise other BadRequest errors (e.g., chat not found, parse error)
            logger.error(f"Telegram BadRequest error during edit: {e}")
            raise
    except Exception as e:
         # Catch other potential errors during edit (e.g., NetworkError)
         logger.exception(f"Unexpected error during message edit: {e}")
         raise # Re-raise for outer handler


# Handles the /start command.
@authorized_user_only
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    logger.info(f"User {user.id} ('{user.username}') started interaction.")
    await update.message.reply_text(
        f"🤖 Welcome! Control {TARGET_NAME} using the buttons below:",
        reply_markup=create_main_menu()
    )


# Handles all button presses from inline keyboards.
@authorized_user_only
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not query: return # Should not happen with CallbackQueryHandler

    # Answer the callback query quickly to remove button loading state
    await query.answer()

    user = query.from_user # Already authorized by decorator
    data = query.data
    logger.info(f"User {user.id} ('{user.username}') pressed button: {data}")

    text = ""
    markup = create_main_menu() # Default to main menu

    try:
        if data == CALLBACK_WAKE:
            text = await wake_pc_action()
        elif data == CALLBACK_STATUS:
            status_msg = await check_status()
            text = f"🖥️ {TARGET_NAME} Status: {status_msg}"
        elif data == CALLBACK_CONFIRM_RESTART:
            text = f"⚠️ Confirm RESTART of {TARGET_NAME}?"
            markup = create_confirmation_menu("restart")
        elif data == CALLBACK_CONFIRM_SHUTDOWN:
            text = f"⚠️ Confirm SHUTDOWN of {TARGET_NAME}?"
            markup = create_confirmation_menu("shutdown")
        elif data == CALLBACK_DO_RESTART:
            await _edit_message(query, "⚙️ Sending restart command...", None) # Intermediate msg
            text = await run_net_rpc(action_type='restart')
            text = f"🔁 Restart result: {text}" # Final message text
            # markup is already main_menu
        elif data == CALLBACK_DO_SHUTDOWN:
            await _edit_message(query, "⚙️ Sending shutdown command...", None) # Intermediate msg
            text = await run_net_rpc(action_type='shutdown')
            text = f"⛔ Shutdown result: {text}" # Final message text
            # markup is already main_menu
        elif data == CALLBACK_REFRESH_MENU:
            text = "🤖 Choose an action:"
            # markup is already main_menu
        else:
            logger.warning(f"Received unknown callback data: {data}")
            text = "❓ Unknown action."

        # Edit the message with the final text and markup for most actions
        # (do_restart/do_shutdown already handled their final edit internally)
        if text: # Ensure we have something to edit
            await _edit_message(query, text, markup)

    except Exception as e:
        # General error handling for unexpected issues in actions or _edit_message
        logger.exception(f"Unhandled error processing button action '{data}': {e}")
        try:
            # Try to inform the user about the error
             await _edit_message(query, f"❌ Error processing '{data}'. See system logs.", create_main_menu())
        except Exception as inner_e:
             # Log if even editing the error message fails
             logger.error(f"Failed to edit message with error details: {inner_e}")


# === Bot Setup and Startup ===

# Sets the list of commands displayed in Telegram clients.
# This runs once after the Application is initialized.
async def post_init_set_commands(application: Application):
    bot: Bot = application.bot
    commands = [ BotCommand("start", f"Show control menu for {TARGET_NAME}") ]
    try:
        await bot.set_my_commands(commands)
        logger.info("Bot commands updated successfully with Telegram.")
    except Exception as e:
        logger.error(f"Failed to set bot commands during post_init: {e}")

# Main function: Initializes and starts the Telegram bot application.
def main():
    logger.info(f"Initializing bot application for target '{TARGET_NAME}'...")

    try:
        application = (
            ApplicationBuilder()
            .token(BOT_TOKEN)
            .post_init(post_init_set_commands) # Set commands after bot is ready
            .build()
        )

        # Register handlers
        application.add_handler(CommandHandler("start", start_command))
        application.add_handler(CallbackQueryHandler(button_handler))

        logger.info("Bot handlers registered. Starting polling...")
        print(f"🚀 Bot running for target '{TARGET_NAME}'. Polling for updates...") # Visible in journalctl

        # Run the bot until Ctrl-C or SIGTERM (from systemd)
        application.run_polling(allowed_updates=Update.ALL_TYPES)

    except Exception as e:
        logger.critical(f"Bot failed to start or encountered a fatal error: {e}", exc_info=True)
        print(f"❌ Bot critical failure: {e}", file=sys.stderr) # Ensure visibility
        sys.exit(1) # Non-zero exit signals failure to systemd

if __name__ == "__main__":
    main()