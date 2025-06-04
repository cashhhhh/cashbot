import imaplib
import email
import logging
from email.header import decode_header
from typing import List, Dict

from .config import load_config

config = load_config()


def load_used_codes() -> set:
    """Load used gift card codes from file."""
    used = set()
    try:
        with open('used_codes.txt', 'r') as f:
            for line in f:
                if ',' in line and not line.startswith('#'):
                    code = line.strip().split(',')[0]
                    used.add(code)
    except FileNotFoundError:
        pass
    return used


def get_emails_imap(guild_id: int, unread_only: bool = True) -> List[Dict[str, str]]:
    """Fetch emails using IMAP for a specific server."""
    try:
        server_config = config.get(str(guild_id))
        if not server_config:
            logging.error(f"No configuration found for server {guild_id}")
            return []

        imap = imaplib.IMAP4_SSL('imap.gmail.com')
        EMAIL = server_config['gmail']
        PASSWORD = server_config['app_password']
        imap.login(EMAIL, PASSWORD)

        imap.select('inbox')
        criteria = 'UNSEEN' if unread_only else 'ALL'
        status, messages = imap.search(None, criteria)
        if status != 'OK':
            raise Exception('Failed to fetch messages.')

        email_ids = messages[0].split()
        emails = []
        for email_id in email_ids:
            res, msg = imap.fetch(email_id, '(RFC822)')
            if res != 'OK':
                continue
            for response in msg:
                if isinstance(response, tuple):
                    msg = email.message_from_bytes(response[1])
                    subject, encoding = decode_header(msg['Subject'])[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(encoding if encoding else 'utf-8')
                    if msg.is_multipart():
                        snippet = ''
                        for part in msg.walk():
                            if part.get_content_type() == 'text/plain':
                                snippet = part.get_payload(decode=True).decode()
                                break
                    else:
                        snippet = msg.get_payload(decode=True).decode()
                    emails.append({'subject': subject, 'snippet': snippet})
        imap.close()
        imap.logout()
        return emails
    except Exception as e:
        logging.error(f"IMAP error for server {guild_id}: {e}")
        return []
