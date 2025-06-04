import os
import json
from dotenv import load_dotenv

load_dotenv()

DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')

CONFIG_FILE = 'config.json'


def load_config():
    """Load the bot configuration from config.json."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_config(config: dict) -> None:
    """Save the bot configuration to config.json."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)
