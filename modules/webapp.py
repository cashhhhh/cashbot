import os
import logging
from flask import Flask, redirect, request

app = Flask(__name__)
app.secret_key = os.urandom(24)


@app.route('/')
def index():
    return redirect(request.host_url.rstrip('/') + '/oauth2callback')


@app.route('/oauth2callback')
def oauth2callback():
    logging.info('Mock OAuth successful, credentials saved.')
    return redirect(request.host_url.rstrip('/') + '/success')


@app.route('/success')
def success():
    return 'Authentication successful. Now you can test the bot commands in Discord.'


def run_flask():
    try:
        logging.info('Starting Flask app...')
        app.run(host='0.0.0.0', port=5000, use_reloader=False)
    except Exception as e:
        logging.error(f'Flask app failed to start: {e}')
