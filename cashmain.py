

import re
import os
import pickle
import logging
import time
import imaplib
import email
import re
from datetime import datetime, timedelta
from email.header import decode_header
from flask import Flask, redirect, request
import discord 
from discord.ext import commands
import threading
import asyncio
import boto3  # AWS SDK for Python
import psutil
import json
import os
from discord.ui import Button, View

# Load or create a config file
if os.path.exists('config.json'):
    with open('config.json', 'r') as f:
        config = json.load(f)
else:
    config = {}


# Add these global variables at the top with other globals
SALES_ROLE_ID = 1103522760073945168  # Replace with your sales role ID
ALERT_CHANNEL_ID = 1223077287457587221  # Your existing alert channel
MIN_ONLINE_THRESHOLD = 5  # Minimum expected active sales members
activity_log = {}
# Configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
TOKEN_PATH = 'token.pickle'
OWNER_IDS = [
    '480028928329777163', '123456789012345678', '987654321098765432',
    '230803708034678786'
]  # List of owner IDs
DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
ALERT_CHANNEL_ID = 1223077287457587221
AWS_INSTANCE_ID = 'i-0c5eefd9c3afd7969'  # Updated instance ID
# Logging Setup
logging.basicConfig(level=logging.INFO)

# Flask App Setup
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Discord Bot Setup
intents = discord.Intents.all()  # Enable all intents to ensure DM functionality
bot = commands.Bot(command_prefix='!', intents=intents, self_bot=False)

# Global Variables
wrong_attempts = {}
SALES_APP_PREFIX = "sales-app-"
giftcard_codes = {
    "100": ["ABC123-DEF456", "GHI789-JKL012", "MNO345-PQR678"],
    "50": ["STU901-VWX234", "YZA567-BCD890", "EFG123-HIJ456"],
    "25": ["KLM789-NOP012", "QRS345-TUV678", "WXY901-ZAB234"],
    "10": ["CDE567-FGH890", "IJK123-LMN456", "OPQ789-RST012"]
}


async def evaluate_application(message):
    """Evaluate a sales application message based on criteria."""
    # Only evaluate for specific user
    if str(message.author.id) != "557628352828014614":
        return None

    # Remove mentions from content
    content = ' '.join(word for word in message.content.split()
                       if not word.startswith('<@'))
    content = content.lower()
    score = 0
    reasons = []

    # Age check
    if "age:" in content and any(str(age) in content for age in range(1, 16)):
        reasons.append("❌ Must be 16 or older")

    # Grammar and sentence structure
   # Update the conditional check to ensure s is not None
    has_short_sentences = any(
        len(s.strip().split()) < 3 for s in sentences if s and s.strip())
    if has_short_sentences:
        reasons.append("❌ Incomplete sentences detected")

    # Check for proper capitalization
    if not any(s.strip()[0].isupper() for s in sentences if s.strip()):
        reasons.append("❌ Lack of proper capitalization")

    # Check for pings/impatience indicators
    if "@" in content or "asap" in content or "urgent" in content:
        reasons.append("❌ Contains pings or shows impatience")

    # Calculate final score
    passed = len(reasons) == 0

    embed = discord.Embed(
        title="📝 Sales Application Evaluation",
        color=discord.Color.green() if passed else discord.Color.red(),
        timestamp=message.created_at)

    embed.add_field(name="Channel",
                    value=message.channel.mention,
                    inline=False)
    embed.add_field(name="Applicant",
                    value=message.author.mention,
                    inline=False)
    embed.add_field(name="Status",
                    value="✅ PASSED" if passed else "❌ FAILED",
                    inline=False)

    if reasons:
        embed.add_field(name="Reasons", value="\n".join(reasons), inline=False)

    return embed


def get_emails_imap(guild_id, unread_only=True):
    """Fetch emails using IMAP for a specific server."""
    try:
        # Get server-specific configuration
        server_config = config.get(str(guild_id))
        if not server_config:
            logging.error(f"No configuration found for server {guild_id}")
            return []

        # Connect to Gmail's IMAP server
        imap = imaplib.IMAP4_SSL("imap.gmail.com")

        # Login to the Gmail account using server-specific credentials
        EMAIL = server_config['gmail']
        PASSWORD = server_config['app_password']
        imap.login(EMAIL, PASSWORD)

        # Select the mailbox
        imap.select("inbox")

        # Search for emails
        criteria = 'UNSEEN' if unread_only else 'ALL'
        status, messages = imap.search(None, criteria)

        if status != "OK":
            raise Exception("Failed to fetch messages.")

        email_ids = messages[0].split()
        emails = []

        for email_id in email_ids:
            # Fetch the email
            res, msg = imap.fetch(email_id, "(RFC822)")
            if res != "OK":
                continue

            # Parse the email content
            for response in msg:
                if isinstance(response, tuple):
                    msg = email.message_from_bytes(response[1])

                    # Decode the email subject
                    subject, encoding = decode_header(msg["Subject"])[0]
                    if isinstance(subject, bytes):
                        # If it's a bytes type, decode to str
                        subject = subject.decode(
                            encoding if encoding else "utf-8")

                    # Extract the email snippet
                    if msg.is_multipart():
                        snippet = ""
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                snippet = part.get_payload(
                                    decode=True).decode()
                                break
                    else:
                        snippet = msg.get_payload(decode=True).decode()

                    emails.append({
                        "subject": subject,
                        "snippet": snippet,
                    })

        # Close the connection
        imap.close()
        imap.logout()

        return emails
    except Exception as e:
        logging.error(f"IMAP error for server {guild_id}: {e}")
        return []


@app.route('/')
def index():
    return redirect(request.host_url.rstrip('/') + '/oauth2callback')


@app.route('/oauth2callback')
def oauth2callback():
    logging.info("Mock OAuth successful, credentials saved.")
    return redirect(request.host_url.rstrip('/') + '/success')


@app.route('/success')
def success():
    return "Authentication successful. Now you can test the bot commands in Discord."


# Store command usage timestamps
checkticket_timestamps = []
SPIKE_THRESHOLD = 5  # Number of commands within time window to trigger alert
TIME_WINDOW = 60  # Time window in seconds
ALERT_USER_IDS = [480028928329777163,
                  230803708034678786]  # Users to notify on spike






@bot.command(name='checkticket')
async def checkticket(ctx, amount: float, unread_only: bool = True):
    """Check for emails with a specific gift card amount. Owner and authorized role command."""
    # Track command usage
    current_time = time.time()
    checkticket_timestamps.append(current_time)

    # Remove timestamps older than TIME_WINDOW
    checkticket_timestamps[:] = [
        t for t in checkticket_timestamps if current_time - t <= TIME_WINDOW
    ]

    # Check for traffic spike
    if len(checkticket_timestamps) >= SPIKE_THRESHOLD:
        spike_embed = discord.Embed(
            title="🚨 Traffic Alert",
            description=
            f"High traffic detected: {len(checkticket_timestamps)} checkticket commands in the last {TIME_WINDOW} seconds",
            color=discord.Color.red(),
            timestamp=datetime.now())
        for user_id in ALERT_USER_IDS:
            try:
                user = await bot.fetch_user(user_id)
                if not user:
                    logging.error(
                        f"Could not fetch user {user_id} for traffic alert")
                    continue

                await user.send(embed=spike_embed)
                logging.info(
                    f"Successfully sent traffic alert to user {user_id}")
            except discord.Forbidden:
                logging.error(
                    f"No permission to send traffic alert to user {user_id}")
            except Exception as e:
                logging.error(
                    f"Failed to send traffic alert to {user_id}: {e}")

    allowed_role_id = (1103522760073945168)
    is_owner = str(ctx.author.id) in OWNER_IDS
    has_role = any(role.id == allowed_role_id for role in ctx.author.roles)

    if not (is_owner or has_role):
        await ctx.send("You do not have permission to use this command.")
        return

    current_time = time.time()
    user_id = ctx.author.id

    if user_id not in wrong_attempts:
        wrong_attempts[user_id] = []

    wrong_attempts[user_id].append(current_time)
    wrong_attempts[user_id] = [
        t for t in wrong_attempts[user_id] if current_time - t < 300
    ]

    if len(wrong_attempts[user_id]) >= 4:
        fraud_msg = f"ALERT: Possible fraud detected from user {ctx.author}. Four incorrect attempts detected."
        alert_channel = bot.get_channel(ALERT_CHANNEL_ID)
        await alert_channel.send(fraud_msg)
        await notify_owner(fraud_msg)
        await ctx.send(
            "You have exceeded the allowed number of attempts. Fraud is being investigated."
        )
        return

    # Get server-specific configuration
    server_config = config.get(str(ctx.guild.id))
    if not server_config:
        await ctx.send("This server is not configured. Please use `!setup` first.")
        return

    # Use server-specific Gmail credentials
    emails = get_emails_imap(ctx.guild.id, unread_only=unread_only)  # Pass guild_id here
    if not emails:
        await ctx.send("No records found, please check your own email.")
        return

    matching_emails = [
        email for email in emails if str(amount) in email['snippet']
    ]
    if matching_emails:
        embed = discord.Embed(title="🎟️ Gift Card Check Results",
                              color=discord.Color.green())
        embed.add_field(
            name="Status",
            value=
            "✅ Gift Card Found. MAKE SURE YOU ADD ROLES",
            inline=False)
        embed.add_field(name="Amount", value=f"${amount:.2f} USD", inline=True)
        embed.add_field(name="Matches Found",
                        value=f"{len(matching_emails)} email(s)",
                        inline=True)
        message = await ctx.send(embed=embed)
        await message.add_reaction("<:emoji:903089677085597757>")
    else:
        embed = discord.Embed(title="🎟️ Gift Card Check Results",
                              color=discord.Color.red())
        embed.add_field(name="Status",
                        value="❌ No Gift Card Found",
                        inline=False)
        embed.add_field(name="Amount Searched",
                        value=f"${amount:.2f} USD",
                        inline=True)
        await ctx.send(embed=embed)

import discord
from discord.ext import commands
from datetime import datetime, timedelta
import asyncio

# CONFIG
COMMISSION_CONFIG = {
    "logs_channel_id": 1204975297594789898,  # Your commission logs channel
    "min_days_between_claims": 7,  # Days between claims
    "manager_approval_threshold": 50.00,  # Amount requiring owner approval
    "owner_ids": [480028928329777163, 230803708034678786],  # Your owner IDs
    "sales_roles": {  # Role-based commission structure
        "Trial Salesman": {"commission": 0.00},
        "Novice Salesman": {"commission": 0.10},
        "Junior Salesman": {"commission": 0.20},
        "Senior Salesman": {"commission": 0.25},
        "Pro Salesman": {"commission": 0.30},
        "Expert Salesman": {"commission": 0.33}
    }
}

# Add to existing bot
intents = discord.Intents.default()
intents.guilds = True
intents.messages = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

# COMMISSION APPROVAL VIEW
class CommissionApprovalView(discord.ui.View):
    def __init__(self, amount):
        super().__init__(timeout=None)
        self.approved = False
        self.amount = amount

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.green)
    async def approve(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id not in COMMISSION_CONFIG['owner_ids']:
            await interaction.response.send_message("❌ Owner only", ephemeral=True)
            return
        self.approved = True
        await interaction.response.send_message("✅ Approved")
        self.stop()

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.red)
    async def deny(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id not in COMMISSION_CONFIG['owner_ids']:
            await interaction.response.send_message("❌ Owner only", ephemeral=True)
            return
        await interaction.response.send_message("❌ Denied")
        self.stop()

# COMMISSION HANDLER
async def handle_commission_ticket(channel):
    try:
        # Step 1: Verify identity
        await channel.send(
            "🎟️ **Commission Claim Process**\n"
            "1. Please @mention yourself to verify your identity"
        )

        def check_mention(m):
            return m.channel == channel and not m.author.bot and len(m.mentions) > 0

        try:
            msg = await bot.wait_for('message', check=check_mention, timeout=300)
            seller = msg.mentions[0]
        except asyncio.TimeoutError:
            await close_ticket(channel, "Verification timed out")
            return

        # Step 2: Get claimed amount
        await channel.send(
            "2. How much are you claiming? (Enter the dollar amount only)"
        )

        def check_amount(m):
            try:
                float(m.content)
                return m.channel == channel and not m.author.bot
            except ValueError:
                return False

        try:
            msg = await bot.wait_for('message', check=check_amount, timeout=300)
            claimed_amount = float(msg.content)
        except asyncio.TimeoutError:
            await close_ticket(channel, "Amount entry timed out")
            return

        # Step 3: Verify seller role
        seller_role = None
        for role in seller.roles:
            if role.name in COMMISSION_CONFIG['sales_roles']:
                seller_role = role.name
                break

        if not seller_role:
            await close_ticket(channel, "No valid sales role found")
            return

        # Step 4: Calculate commission
        commission_rate = COMMISSION_CONFIG['sales_roles'][seller_role]['commission']
        commission_amount = claimed_amount * commission_rate

        # Step 5: Check cooldown
        last_claim = await get_last_claim(seller)
        if (datetime.now() - last_claim).days < COMMISSION_CONFIG['min_days_between_claims']:
            next_claim = last_claim + timedelta(days=COMMISSION_CONFIG['min_days_between_claims'])
            await close_ticket(channel, f"Next claim available: {next_claim.strftime('%Y-%m-%d')}")
            return

        # Step 6: Payout process
        payout_code = f"GC-{seller.id}-{int(datetime.now().timestamp())}"  # Replace with actual code
        approval_view = CommissionApprovalView(commission_amount)
        
        msg_content = [
            f"**Commission Request**",
            f"Seller: {seller.mention} ({seller_role})",
            f"Claimed Amount: ${claimed_amount:.2f}",
            f"Commission Rate: {commission_rate * 100}%",
            f"Payout Amount: ${commission_amount:.2f}",
            f"Code: ||{payout_code}||"
        ]

        if commission_amount >= COMMISSION_CONFIG['manager_approval_threshold']:
            msg_content.append("\n**Owner approval required**")
        else:
            msg_content.append("\nAuto-approving in 60 seconds...")
            approval_view.timeout = 60

        await channel.send("\n".join(msg_content), view=approval_view)
        await approval_view.wait()

        if approval_view.approved:
            await log_payout(seller.id, commission_amount, payout_code)
            await close_ticket(channel, "Payout completed")
        else:
            await channel.send("❌ Payout cancelled")
            await channel.edit(name=f"denied-{channel.name}")

    except Exception as e:
        await channel.send(f"⚠️ Error processing commission: {str(e)}")
        raise

# HELPER FUNCTIONS
async def get_last_claim(seller):
    """Get last claim date from logs"""
    log_channel = bot.get_channel(COMMISSION_CONFIG['logs_channel_id'])
    last_claim = datetime.min
    async for message in log_channel.history(limit=200):
        if str(seller.id) in message.content:
            last_claim = max(last_claim, message.created_at)
    return last_claim.replace(tzinfo=None)

async def log_payout(seller_id, amount, code):
    """Log payout to commission logs channel"""
    log_channel = bot.get_channel(COMMISSION_CONFIG['logs_channel_id'])
    embed = discord.Embed(
        title="Commission Paid",
        description=(
            f"**Seller:** <@{seller_id}>\n"
            f"**Amount:** ${amount:.2f}\n"
            f"**Code:** ||{code}||\n"
            f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ),
        color=discord.Color.green()
    )
    await log_channel.send(embed=embed)

async def close_ticket(channel, reason):
    """Close ticket with reason"""
    await channel.send(f"❌ Closing ticket: {reason}")
    await asyncio.sleep(10)
    await channel.delete()

# TICKET HANDLER
@bot.event
async def on_guild_channel_create(channel):
    if channel.name.startswith("commission-"):
        await channel.send(
            f"👋 Welcome {channel.mention}!\n"
            "Please wait while we initialize your commission claim..."
        )
        await handle_commission_ticket(channel)
        owner_mention = " ".join(f"<@{oid}>" for oid in COMMISSION_CONFIG['owner_ids'])
        await channel.send(f"{owner_mention} New commission claim started")

@bot.command()
async def profit(ctx):
    """Display profit for the bot owner, calculated from today's emails."""
    if str(ctx.author.id) not in OWNER_IDS:
        await ctx.send("You do not have permission to view the profit numbers."
                       )
        return

    import re
    from datetime import datetime, timedelta

    # Connect to IMAP
    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    EMAIL = os.getenv('GMAIL_EMAIL')
    PASSWORD = os.getenv('GMAIL_PASSWORD')
    imap.login(EMAIL, PASSWORD)
    imap.select("inbox")

    # Search for today's emails specifically (both read and unread)
    today = datetime.now()
    date_str = today.strftime("%d-%b-%Y")
    search_criteria = f'(OR (SEEN SENTON {date_str}) (UNSEEN SENTON {date_str}))'
    _, messages = imap.search(None, search_criteria)
    email_ids = messages[0].split()

    if not email_ids:
        await ctx.send("No emails found for today.")
        imap.close()
        imap.logout()
        return

    total = 0
    processed = 0

    # Create debug log
    with open('profit_debug.log', 'w', encoding='utf-8') as debug_file:
        debug_file.write(
            f"=== Profit Command Debug Log {datetime.now()} ===\n")
        debug_file.write(f"Found {len(email_ids)} total emails to process\n\n")

    for email_id in email_ids:
        _, msg = imap.fetch(email_id, '(RFC822)')
        email_body = msg[0][1]
        email_message = email.message_from_bytes(email_body)

        # Check if email is from today
        date_str = email_message['date']
        try:
            email_date = datetime.strptime(
                date_str.split(' (')[0].strip(),
                '%a, %d %b %Y %H:%M:%S %z').date()
            if email_date != today:
                continue
        except:
            continue

        # Get email content
        body = ""
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body = part.get_payload(decode=True).decode()
                        break
                    except:
                        continue
        else:
            try:
                body = email_message.get_payload(decode=True).decode()
            except:
                continue

        # Log email content for debugging
        with open('profit_debug.log', 'a', encoding='utf-8') as debug_file:
            debug_file.write(
                f"\nProcessing email from: {email_message.get('from', 'Unknown')}\n"
            )
            debug_file.write(
                f"Subject: {email_message.get('subject', 'No Subject')}\n")
            debug_file.write(f"Date: {email_message.get('date', 'No Date')}\n")
            debug_file.write("Content:\n")
            debug_file.write(body[:500] + "...\n" if len(body) > 500 else body)
            debug_file.write("\n" + "-" * 50 + "\n")

        # Log raw content before parsing
        with open('profit_debug.log', 'a', encoding='utf-8') as debug_file:
            debug_file.write("\nTrying to find amounts in text:\n")
            debug_file.write(f"Raw text: {body}\n")

        # Look for gift card values using multiple patterns
        patterns = [
            r'\$(\d+\.\d{2})\s*USD',
            r'Value:\s*\$(\d+\.\d{2})',
            r'Amount:\s*\$(\d+\.\d{2})',
            r'Card Value:\s*\$(\d+\.\d{2})',
            r'Gift Card.*?Value.*?\$(\d+\.\d{2})',
        ]

        amounts = []
        for pattern in patterns:
            found = re.findall(pattern, body, re.DOTALL | re.IGNORECASE)
            if found:
                with open('profit_debug.log', 'a',
                          encoding='utf-8') as debug_file:
                    debug_file.write(
                        f"Found amounts using pattern {pattern}: {found}\n")
            amounts.extend(found)

        for amount in amounts:
            try:
                total += float(amount)
                processed += 1
                print(f"Found amount: ${amount}")  # Debug print
            except ValueError:
                continue

    imap.close()
    imap.logout()

    # Calculate commission
    commission = total * 0.18
    net_profit = total - commission

    profit_msg = f"""```
Today's Summary:
Gross Total: ${total:.2f}
Commission (18%): ${commission:.2f}
Net Profit: ${net_profit:.2f}
```"""
    await ctx.send(profit_msg)

@bot.command(name='sellerlocations')
async def seller_locations(ctx):
    """Display a list of seller locations and postal codes from their game status."""
    try:
        # Get the sales role
        sales_role = ctx.guild.get_role(SALES_ROLE_ID)
        if not sales_role:
            await ctx.send("❌ Sales role not found.")
            return

        # Initialize a list to store seller locations
        sellers = []

        # Check each member in the sales role
        for member in sales_role.members:
            # Log the member's name and activity for debugging
            logging.info(f"Checking member: {member.display_name}")
            if member.activity:
                logging.info(f"Activity found: {member.activity.name} (Type: {member.activity.type})")

            # Check if the member has an activity (game status)
            if member.activity and member.activity.type in [discord.ActivityType.playing, discord.ActivityType.streaming]:
                activity_name = member.activity.name
                logging.info(f"Game status: {activity_name}")

                # Extract seller name, street name, and postal code using regex
                match = re.search(r'(\w+) is standing on (\w+ \w+) \((\w+)\)', activity_name, re.IGNORECASE)
                if match:
                    seller_name, street, postal = match.groups()
                    sellers.append({
                        'name': member.display_name,
                        'street': street,
                        'postal': postal
                    })
                    logging.info(f"Seller found: {member.display_name} - {street} ({postal})")
                else:
                    logging.info(f"No match found for: {activity_name}")

        # Check if any sellers were found
        if not sellers:
            await ctx.send("❌ No active sellers found.")
            return

        # Format the list of sellers
        seller_list = "\n".join(
            f"**{seller['name']}**: {seller['street']} ({seller['postal']})"
            for seller in sellers
        )

        # Send the list in an embed
        embed = discord.Embed(
            title="📍 Seller Locations",
            description=seller_list,
            color=discord.Color.blue()
        )
        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(f"❌ Error fetching seller locations: {str(e)}")

# Existing imports
import json
import os

# File to store customer credits
CREDITS_FILE = "credits.json"

# Load credits from file
if os.path.exists(CREDITS_FILE):
    with open(CREDITS_FILE, "r") as f:
        credits = json.load(f)
else:
    credits = {}

# Function to save credits to file
def save_credits():
    with open(CREDITS_FILE, "w") as f:
        json.dump(credits, f, indent=4)

# Command: !credit add <user_id> <amount>
@bot.command(name='creditadd')
@commands.has_permissions(administrator=True)
async def credit_add(ctx, user_id: str, amount: float):
    """Add credit to a customer's account."""
    try:
        # Ensure the user ID is valid
        user = await bot.fetch_user(int(user_id))
        if not user:
            await ctx.send("❌ User not found.")
            return

        # Add credit
        if user_id in credits:
            credits[user_id] += amount
        else:
            credits[user_id] = amount

        # Save credits
        save_credits()

        await ctx.send(f"✅ Added ${amount:.2f} credit to {user.mention}. Total credit: ${credits[user_id]:.2f}")

    except Exception as e:
        await ctx.send(f"❌ Error adding credit: {str(e)}")

# Command: !credit remove <user_id> <amount>
@bot.command(name='creditremove')
@commands.has_permissions(administrator=True)
async def credit_remove(ctx, user_id: str, amount: float):
    """Remove credit from a customer's account."""
    try:
        # Ensure the user ID is valid
        user = await bot.fetch_user(int(user_id))
        if not user:
            await ctx.send("❌ User not found.")
            return

        # Check if the user has enough credit
        if user_id not in credits or credits[user_id] < amount:
            await ctx.send("❌ Insufficient credit.")
            return

        # Remove credit
        credits[user_id] -= amount

        # Save credits
        save_credits()

        await ctx.send(f"✅ Removed ${amount:.2f} credit from {user.mention}. Remaining credit: ${credits[user_id]:.2f}")

    except Exception as e:
        await ctx.send(f"❌ Error removing credit: {str(e)}")

# Command: !credit check <user_id>
@bot.command(name='creditcheck')
async def credit_check(ctx, user_id: str):
    """Check a customer's credit."""
    try:
        # Ensure the user ID is valid
        user = await bot.fetch_user(int(user_id))
        if not user:
            await ctx.send("❌ User not found.")
            return

        # Get credit
        credit = credits.get(user_id, 0.0)

        await ctx.send(f"💰 {user.mention} has ${credit:.2f} credit.")

    except Exception as e:
        await ctx.send(f"❌ Error checking credit: {str(e)}")

# Modify the on_message event to notify on ticket creation
@bot.event
async def on_message(message):
    # Ignore messages from bots
    if message.author.bot:
        return

    # Check if the message is in a ticket channel
    if "ticket" in message.channel.name.lower():
        # Check if the user has credit
        user_id = str(message.author.id)
        if user_id in credits and credits[user_id] > 0:
            await message.channel.send(
                f"🎉 {message.author.mention}, you have **${credits[user_id]:.2f}** credit available!"
            )

    # Process commands
    await bot.process_commands(message)

@bot.command()
async def leaderboard(ctx):
    """Show the leaderboard."""
    leaderboard_data = {
        "salesperson_1": 10,
        "salesperson_2": 8
    }  # Example data
    leaderboard_msg = "Leaderboard:\n"
    for user, tickets in leaderboard_data.items():
        leaderboard_msg += f"{user}: {tickets} tickets\n"

    await ctx.send(leaderboard_msg)


@bot.command(name='stats')
async def stats(ctx):
    """Show detailed bot statistics including system resources"""
    global start_time
    
    try:
        # Check if stats are available
        if start_time is None:
            await ctx.send("📊 Bot statistics are still initializing...")
            return

        # Calculate uptime
        uptime_seconds = time.time() - start_time
        days, remainder = divmod(uptime_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)

        # Get system stats using psutil
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net_io = psutil.net_io_counters()
        temps = psutil.sensors_temperatures()
        cpu_freq = psutil.cpu_freq()

        # Create rich embed
        embed = discord.Embed(
            title="🤖 Bot Performance Dashboard",
            color=discord.Color.blue(),
            timestamp=datetime.now()
        )

        # Uptime and Basic Info
        embed.add_field(
            name="⏱ Uptime",
            value=f"{int(days)}d {int(hours)}h {int(minutes)}m {int(seconds)}s",
            inline=True
        )
        
        # Hardware Monitoring
        embed.add_field(
            name="🔥 CPU Usage",
            value=f"{cpu_percent}%",
            inline=True
        )
        
        embed.add_field(
            name="💾 Memory",
            value=f"Used: {memory.percent}%\nTotal: {memory.total//(1024**3)}GB",
            inline=True
        )

        # Disk Status
        embed.add_field(
            name="💽 Disk Storage",
            value=f"Used: {disk.percent}%\nFree: {disk.free//(1024**3)}GB",
            inline=True
        )

        # Network Statistics
        embed.add_field(
            name="🌐 Network Traffic",
            value=f"↑ {net_io.bytes_sent//(1024**2)}MB\n↓ {net_io.bytes_recv//(1024**2)}MB",
            inline=True
        )

        # Temperature Monitoring (if available)
        if temps:
            cpu_temp = next(iter(temps.values()))[0].current
            embed.add_field(
                name="🌡 CPU Temp",
                value=f"{cpu_temp}°C",
                inline=True
            )

        # CPU Frequency
        if cpu_freq:
            embed.add_field(
                name="⚡ CPU Clock",
                value=f"{cpu_freq.current/1000:.2f}GHz",
                inline=True
            )

        # Discord Statistics
        embed.add_field(
            name="📊 Discord Metrics",
            value=f"Guilds: {len(bot.guilds)}\nUsers: {sum(g.member_count for g in bot.guilds)}",
            inline=False
        )

        # Latency Information
        embed.set_footer(text=f"API Latency: {round(bot.latency * 1000)}ms")

        await ctx.send(embed=embed)

    except Exception as e:
        logging.error(f"Stats command error: {str(e)}")
        await ctx.send("❌ Failed to retrieve statistics. Check system permissions!")
        await notify_owner(f"Stats command failed: {str(e)}")

# Add to global variables
INACTIVE_THRESHOLD = 20  # Days
TICKET_LOGS_CHANNEL_ID = 1103526122211262565
SALES_TEAM_ROLE_ID = 1103522760073945168

# Add this function
async def check_inactive_sellers(warning_channel):
    """Check for sellers with no activity in last 20 days"""
    try:
        # Get ticket logs channel
        channel = bot.get_channel(TICKET_LOGS_CHANNEL_ID)
        if not channel:
            return await warning_channel.send("❌ Ticket logs channel not found")
        
        # Get messages from last 20 days
        cutoff = datetime.now() - timedelta(days=INACTIVE_THRESHOLD)
        active_sellers = set()
        
        async for message in channel.history(after=cutoff):
            if message.author.bot:
                continue
            active_sellers.add(message.author.id)
        
        # Get sales team role
        seller_role = discord.utils.get(channel.guild.roles, id=SALES_TEAM_ROLE_ID)
        if not seller_role:
            return await warning_channel.send("❌ Sales team role not found")
        
        # Find inactive sellers
        inactive_sellers = [
            member for member in seller_role.members 
            if member.id not in active_sellers 
            and str(member.id) not in OWNER_IDS
        ]
        
        # Send warnings
        if not inactive_sellers:
            return await warning_channel.send("✅ All sellers are active!")
            
        for seller in inactive_sellers:
            await warning_channel.send(
                f"⚠️ {seller.mention} You haven't made any sales in the last {INACTIVE_THRESHOLD} days. "
                "Please contact a manager if there are any issues."
            )
            
    except Exception as e:
        await warning_channel.send(f"❌ Error checking inactive sellers: {e}")

# Add this command
@bot.command(name='checkinactive')
@commands.is_owner()
async def check_inactive(ctx):
    """Check for inactive sellers and warn in this channel"""
    await ctx.send("🔄 Checking for inactive sellers...")
    await check_inactive_sellers(ctx.channel)

@bot.command(aliases=['logs', 'r'])
async def report(ctx, *, user: discord.Member = None):
    """Show log reports for today. Use !report @user to see specific user logs."""
    if str(ctx.author.id) not in OWNER_IDS:
        await ctx.send("You do not have permission to view reports.")
        return

    channel = bot.get_channel(1103526122211262565)
    if not channel:
        await ctx.send("Monitoring channel not found.")
        return

    today = datetime.now().date()
    messages = []
    async for message in channel.history(limit=1000,
                                         after=datetime.combine(
                                             today, datetime.min.time())):
        if "Customer:" in message.content or "!checkticket" in message.content.lower(
        ):
            messages.append({
                'user': message.author,
                'content': message.content,
                'timestamp': message.created_at
            })

    if user:
        # Report for mentioned user
        user_logs = [msg for msg in messages if msg['user'].id == user.id]
        if not user_logs:
            await ctx.send(f"No logs found for {user.name} today.")
            return

        embed = discord.Embed(title=f"📊 User Log Report",
                              description=f"Log report for {user.name}",
                              color=discord.Color.blue())
        embed.add_field(name="Total Logs Today",
                        value=str(len(user_logs)),
                        inline=False)
        if user_logs:
            embed.add_field(
                name="First Log",
                value=user_logs[0]['timestamp'].strftime('%I:%M %p'),
                inline=True)
            embed.add_field(
                name="Last Log",
                value=user_logs[-1]['timestamp'].strftime('%I:%M %p'),
                inline=True)
    else:
        # Report for all users today
        if not messages:
            await ctx.send("No logs found for today.")
            return

        user_counts = {}
        for msg in messages:
            user_counts[msg['user'].name] = user_counts.get(
                msg['user'].name, 0) + 1

        embed = discord.Embed(
            title="📊 Daily Log Report",
            description=f"Log report for {today.strftime('%Y-%m-%d')}",
            color=discord.Color.blue())

        sorted_users = sorted(user_counts.items(),
                              key=lambda x: x[1],
                              reverse=True)
        for username, count in sorted_users:
            embed.add_field(name=username, value=f"{count} logs", inline=True)

        embed.add_field(name="Total Logs",
                        value=str(len(messages)),
                        inline=False)

    await ctx.send(embed=embed)


@bot.command()
async def clearfraud(ctx, user: discord.User):
    """Clear fraud detection attempts for a user."""
    if str(ctx.author.id) not in OWNER_IDS:
        await ctx.send(
            "You do not have permission to clear fraud detection attempts.")
        return

    if user.id in wrong_attempts:
        del wrong_attempts[user.id]
        await ctx.send(
            f"Fraud detection attempts for {user.name} have been cleared.")
    else:
        await ctx.send(f"No fraud attempts found for {user.name}.")


# Add start time tracking
start_time = None


@bot.event
async def on_ready():
    global start_time
    start_time = time.time()
    logging.info(f'{bot.user} has connected to Discord!')


# Store daily messages and crash logs
daily_messages = {}
crash_logs = []
MAX_CRASH_LOGS = 3

# Add global variables for ticket tracking
ticket_stats = {}


@bot.event
async def on_message(message):
    if message.author.bot:
        return

    # Handle DM logging
    if isinstance(message.channel, discord.DMChannel):
        try:
            # Log to file
            with open('dm_logs.txt', 'a', encoding='utf-8') as f:
                timestamp = message.created_at.strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"\n=== DM from {message.author} ({message.author.id}) at {timestamp} ===\n")
                f.write(f"Content: {message.content}\n")
                # Log attachments if any
                if message.attachments:
                    f.write("Attachments:\n")
                    for attachment in message.attachments:
                        f.write(f"- {attachment.url}\n")
                f.write("=" * 50 + "\n")

            # Forward DM to owner
            owner = await bot.fetch_user(480028928329777163)  # Cash's ID
            if owner:
                embed = discord.Embed(
                    title="📥 New DM Received",
                    description=f"From: {message.author.mention} ({message.author.id})",
                    color=discord.Color.blue(),
                    timestamp=message.created_at
                )
                embed.add_field(name="Content", value=message.content, inline=False)
                if message.attachments:
                    embed.add_field(
                        name="Attachments", 
                        value="\n".join(f"[Attachment]({a.url})" for a in message.attachments),
                        inline=False
                    )
                await owner.send(embed=embed)
        except Exception as e:
            logging.error(f"Failed to log DM: {str(e)}")

    # Track checkticket commands
    today = datetime.now().date()
    if "!checkticket" in message.content.lower():
        if today not in ticket_stats:
            ticket_stats[today] = {"count": 0, "amounts": []}

        # Extract amount from command
        try:
            amount = float(message.content.split()[1])
            ticket_stats[today]["count"] += 1
            ticket_stats[today]["amounts"].append(amount)
        except (IndexError, ValueError):
            pass

    # Log messages for specified channel
    if message.channel.id == 1103526122211262565:
        today = datetime.now().date()
        if today not in daily_messages:
            daily_messages[today] = {}

        author_id = str(message.author.id)
        if author_id not in daily_messages[today]:
            daily_messages[today][author_id] = {'count': 0, 'total': 0.0}

        daily_messages[today][author_id]['count'] += 1

        # Check for ticket mentions
        content = message.content
        ticket_match = re.search(r'Ticket:\s*(\S+)', content)
        if ticket_match:
            ticket_id = ticket_match.group(1)
            # Check audit log for ticket closure
            found_closure = False
            five_minutes_ago = datetime.now() - timedelta(minutes=5)
            try:
                async for entry in message.guild.audit_logs(
                        limit=50,
                        action=discord.AuditLogAction.channel_delete,
                        after=five_minutes_ago):
                    if entry.target and isinstance(
                            entry.target, discord.abc.GuildChannel
                    ) and entry.target.name == f'ticket-{ticket_id}':
                        found_closure = True
                        break
            except discord.Forbidden:
                logging.error("Bot lacks audit log permissions")
                pass

            if not found_closure:
                try:
                    alert_channel = bot.get_channel(1223077287457587221)
                    alert_embed = discord.Embed(
                        title="🚨 Ticket Alert",
                        description=
                        f"Ticket mentioned but not found closed:\nTicket ID: {ticket_id}\nUser: {message.author.mention}",
                        color=discord.Color.red(),
                        timestamp=datetime.now())
                    alert_embed.add_field(
                        name="Message Link",
                        value=f"[Click here]({message.jump_url})")
                    if alert_channel:
                        await alert_channel.send(embed=alert_embed)
                except Exception as e:
                    logging.error(f"Failed to send ticket alert: {e}")

        content = content.lower()
        import re

        # Check if message follows expected format (Customer: something $amount)
        is_valid_format = bool(
            re.match(r'customer:.*?\$\d+(?:\.\d{2})?', content))
        price_matches = re.findall(r'\$(\d+(?:\.\d{2})?)', content)

        if price_matches and is_valid_format:
            try:
                price = float(price_matches[0])
                daily_messages[today][author_id]['total'] += price

                # Check audit log for ticket channel deletions in last 5 minutes
                found_ticket = False
                five_minutes_ago = datetime.now() - timedelta(minutes=5)
                try:
                    async for entry in message.guild.audit_logs(
                            limit=50,
                            action=discord.AuditLogAction.channel_delete,
                            after=five_minutes_ago):
                        if entry.target and isinstance(
                                entry.target, discord.abc.GuildChannel
                        ) and entry.target.name.startswith('ticket-'):
                            found_ticket = True
                            break
                except discord.Forbidden:
                    logging.error("Bot lacks audit log permissions")
                    pass

                if not found_ticket:
                    # Send alert only to owner via DM
                    try:
                        alert_channel = bot.get_channel(1223077287457587221)
                        alert_embed = discord.Embed(
                            title="🚨 Review Required",
                            description=
                            f"Sale logged without matching ticket:\nUser: {message.author.mention}\nAmount: ${price}",
                            color=discord.Color.red(),
                            timestamp=datetime.now())
                        alert_embed.add_field(
                            name="Sale Message Link",
                            value=f"[Click here]({message.jump_url})")
                        if alert_channel:
                            await alert_channel.send(embed=alert_embed)
                    except Exception as e:
                        logging.error(f"Failed to send review alert: {e}")

            except ValueError:
                pass

    await bot.process_commands(message)


@bot.command()
async def topusers(ctx):
    """Show top 3 most active users in the last 24 hours."""
    channel = bot.get_channel(1103526122211262565)
    if not channel:
        await ctx.send("Channel not found.")
        return

    user_stats = {}
    twenty_four_hours_ago = datetime.now() - timedelta(days=1)

    async for message in channel.history(after=twenty_four_hours_ago):
        if message.author.bot:
            continue

        author_id = str(message.author.id)
        if author_id not in user_stats:
            user_stats[author_id] = {'count': 0, 'total': 0.0}

        user_stats[author_id]['count'] += 1

        # Extract price from message
        content = message.content.lower()
        price_matches = re.findall(r'\$(\d+(?:\.\d{2})?)', content)
        if price_matches:
            try:
                price = float(price_matches[0])
                user_stats[author_id]['total'] += price
            except ValueError:
                continue

    if not user_stats:
        await ctx.send("No messages found in the last 24 hours.")
        return

    # Sort users by message count
    sorted_users = sorted(user_stats.items(),
                          key=lambda x: x[1]['count'],
                          reverse=True)[:3]

    embed = discord.Embed(title="🏆 Top 3 Most Active Users Today",
                          color=discord.Color.gold(),
                          timestamp=datetime.now())

    medals = ["🥇", "🥈", "🥉"]
    for i, (user_id, stats) in enumerate(sorted_users):
        try:
            user = await bot.fetch_user(int(user_id))
            embed.add_field(
                name=f"{medals[i]} {user.name}",
                value=
                f"Messages: {stats['count']}\nTotal: ${stats['total']:.2f}",
                inline=False)
        except:
            continue

    await ctx.send(embed=embed)


@bot.command()
async def checkapplication(ctx, channel_id: int):
    """Check applications in a specific sales application channel."""
    if str(ctx.author.id) not in OWNER_IDS:
        await ctx.send("You do not have permission to use this command.")
        return

    channel = bot.get_channel(channel_id)
    if not channel or not channel.name.startswith(SALES_APP_PREFIX):
        await ctx.send("❌ Invalid sales application channel.")
        return

    async with ctx.typing():
        messages = []
        async for message in channel.history(limit=100):
            if not message.author.bot:
                evaluation = await evaluate_application(message)
                messages.append(evaluation)

        if not messages:
            await ctx.send("No applications found in this channel.")
            return

        for embed in messages[:10]:  # Send up to 10 most recent evaluations
            await ctx.send(embed=embed)

        if len(messages) > 10:
            await ctx.send(
                f"Showing 10 most recent of {len(messages)} applications.")


def run_flask():
    try:
        logging.info("Starting Flask app...")
        app.run(host='0.0.0.0', port=5000, use_reloader=False)
    except Exception as e:
        logging.error(f"Flask app failed to start: {e}")


async def notify_owner(message):
    """Send a DM to the bot owner."""
    try:
        owner = await bot.fetch_user(480028928329777163)
        if owner:
            await owner.send(message)
    except Exception as e:
        logging.error(f"Failed to notify owner: {e}")


def run_discord():
    while True:
        try:
            logging.info("Starting Discord bot...")
            bot.run(DISCORD_TOKEN, reconnect=True)
        except Exception as e:
            error_msg = f"Discord bot disconnected: {e}"
            logging.error(error_msg)

            # Log crash with timestamp and details
            crash_logs.append({
                'timestamp': datetime.now(),
                'error': str(e),
                'traceback': logging.traceback.format_exc()
            })

            # Keep only the last MAX_CRASH_LOGS crashes
            while len(crash_logs) > MAX_CRASH_LOGS:
                crash_logs.pop(0)

            try:
                # Notify owner about the disconnect
                async def send_error():
                    temp_bot = commands.Bot(command_prefix='!',
                                            intents=discord.Intents.default())
                    await temp_bot.start(DISCORD_TOKEN)
                    await notify_owner(error_msg)
                    await temp_bot.close()

                asyncio.run(send_error())
            except:
                pass
            # Implement exponential backoff for reconnection
            retry_time = min(30 * (len(crash_logs) + 1), 300)  # Max 5 minutes
            logging.info(f"Attempting reconnection in {retry_time} seconds...")
            time.sleep(retry_time)
            continue


@bot.command()
async def crash(ctx):
    """Display the last 3 crash logs (Owner only)."""
    if str(ctx.author.id) not in OWNER_IDS:
        await ctx.send("❌ This command is restricted to bot owners only.")
        return

    if not crash_logs:
        await ctx.send("No crash logs found.")
        return

    embed = discord.Embed(
        title="🔥 Recent Bot Crashes",
        color=discord.Color.red(),
        description="Here are the most recent crash details:")

    for i, crash in enumerate(reversed(crash_logs), 1):
        crash_time = crash['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        error_details = f"```\n{crash['error']}\n```"

        embed.add_field(name=f"Crash #{i} - {crash_time}",
                        value=error_details,
                        inline=False)

    embed.set_footer(
        text=
        "This command is restricted to owners to protect sensitive error information"
    )
    await ctx.send(embed=embed)


@bot.command()
async def sendmsg(ctx, *, message: str):
    """Send a DM to specific users."""
    user_ids = [230803708034678786, 480028928329777163]
    success_count = 0
    failure_details = []

    for user_id in user_ids:
        try:
            user = await bot.fetch_user(user_id)
            if not user:
                failure_details.append(f"Could not fetch user {user_id}")
                continue

            embed = discord.Embed(title="Message",
                                  description=message,
                                  color=discord.Color.blue(),
                                  timestamp=datetime.now())
            embed.set_footer(text=f"Sent by {ctx.author.name}")
            await user.send(embed=embed)
            success_count += 1
            logging.info(f"Successfully sent message to user {user_id}")
        except discord.Forbidden:
            failure_details.append(f"No permission to DM user {user_id}")
            logging.error(f"Forbidden to send message to {user_id}")
        except Exception as e:
            failure_details.append(f"Error for user {user_id}: {str(e)}")
            logging.error(f"Failed to send message to {user_id}: {str(e)}")

    response = f"✅ Message sent successfully to {success_count} user(s)"
    if failure_details:
        response += "\n❌ Failures:\n" + "\n".join(failure_details)
    await ctx.send(response)


@bot.command()
async def payout(ctx, user: discord.Member):
    """Show lifetime commission report for a user."""
    channel = bot.get_channel(1103526122211262565)  # Sales log channel
    if not channel:
        await ctx.send("Sales log channel not found.")
        return

    total_sales = 0
    sales_count = 0
    commission_rate = 18.0

    async for message in channel.history(limit=None):
        if message.author == user and "customer:" in message.content.lower():
            content = message.content.lower()
            price_matches = re.findall(r'\$(\d+(?:\.\d{2})?)', content)
            if price_matches:
                try:
                    price = float(price_matches[0])
                    total_sales += price
                    sales_count += 1
                except ValueError:
                    continue

    commission = total_sales * (commission_rate / 100)

    embed = discord.Embed(title="💰 Commission Report",
                          description=f"for {user.name}",
                          color=discord.Color.green(),
                          timestamp=datetime.now())

    embed.add_field(name="Date Range",
                    value="From Lifetime to Present",
                    inline=False)

    embed.add_field(name="Total Sales",
                    value=f"${total_sales:.2f}",
                    inline=True)

    embed.add_field(name=f"Commission ({commission_rate}%)",
                    value=f"${commission:.2f}",
                    inline=True)

    embed.add_field(name="Sales Count", value=str(sales_count), inline=True)

    await ctx.send(embed=embed)


@bot.command()
async def calculate(ctx,
                    user: discord.Member = None,
                    commission_rate: float = 18.0,
                    start_date: str = None,
                    end_date: str = None):
    """Calculate sales and commission for a user. Format: !calculate @user [rate] [MM/DD/YYYY] [MM/DD/YYYY]"""
    if not user:
        await ctx.send(
            "❌ Please mention a user: !calculate @user [rate] [MM/DD/YYYY] [MM/DD/YYYY]"
        )
        return

    logging.info(
        f"Calculate command called by {ctx.author} for user: {user.name}, rate: {commission_rate}, dates: {start_date} to {end_date}"
    )

    # If no dates provided, calculate for all time
    if not start_date:
        total_sales = 0
        sales_count = 0
    if not end_date:
        end_date = start_date

    try:
        start = datetime.strptime(start_date, '%m/%d/%Y')
        end = datetime.strptime(end_date, '%m/%d/%Y')
        end = end.replace(hour=23, minute=59,
                          second=59)  # Include full end date
    except ValueError:
        await ctx.send("❌ Invalid date format. Please use MM/DD/YYYY")
        return

    channel = bot.get_channel(1103526122211262565)  # Sales log channel
    if not channel:
        await ctx.send("Sales log channel not found.")
        return

    total_sales = 0
    sales_count = 0
    messages = []

    async for message in channel.history(limit=1000,
                                         after=start,
                                         before=end + timedelta(days=1)):
        if message.author == user and "customer:" in message.content.lower():
            content = message.content.lower()
            # Enhanced pattern matching for sales
            price_matches = re.findall(r'\$(\d+(?:\.\d{2})?)', content) or \
                          re.findall(r'(?:amount|total|price|sale)[^\d]*(\d+(?:\.\d{2})?)', content) or \
                          re.findall(r'(\d+(?:\.\d{2})?)\s*(?:usd|dollars)', content)
            if price_matches:
                try:
                    price = float(price_matches[0])
                    total_sales += price
                    sales_count += 1
                    messages.append(
                        f"${price:.2f} - {message.created_at.strftime('%m/%d %I:%M %p')}"
                    )
                except ValueError:
                    continue

    if not messages:
        await ctx.send(f"No sales found between {start_date} and {end_date}")
        return

    commission = total_sales * (commission_rate / 100
                                )  # Convert percentage to decimal

    embed = discord.Embed(title="📊 Sales Report",
                          description=f"Report for {user.mention}",
                          color=user.color if user.color
                          != discord.Color.default() else discord.Color.blue(),
                          timestamp=datetime.now())

    embed.set_thumbnail(url=user.display_avatar.url)
    embed.add_field(name="📅 Period",
                    value=f"From {start_date} to {end_date}",
                    inline=False)

    embed.add_field(name="Total Sales",
                    value=f"${total_sales:.2f}",
                    inline=True)

    embed.add_field(name=f"Commission ({commission_rate}%)",
                    value=f"${commission:.2f}",
                    inline=True)

    embed.add_field(name="Number of Sales",
                    value=str(sales_count),
                    inline=True)

    # Add recent sales (up to 10)
    recent_sales = "\n".join(messages[-10:])
    if messages:
        embed.add_field(name="Recent Sales",
                        value=f"```{recent_sales}```",
                        inline=False)

    await ctx.send(embed=embed)


@bot.command()
async def ticketstats(ctx):
    """Show statistics for !checkticket commands used today."""
    today = datetime.now().date()

    if today not in ticket_stats or ticket_stats[today]["count"] == 0:
        await ctx.send("No !checkticket commands have been used today.")
        return

    stats = ticket_stats[today]
    total_amount = sum(stats["amounts"])
    avg_amount = total_amount / len(
        stats["amounts"]) if stats["amounts"] else 0

    embed = discord.Embed(title="📊 Today's Ticket Check Statistics",
                          color=discord.Color.blue(),
                          timestamp=datetime.now())

    embed.add_field(name="Total Commands",
                    value=str(stats["count"]),
                    inline=True)

    embed.add_field(name="Total Amount Checked",
                    value=f"${total_amount:.2f}",
                    inline=True)

    embed.add_field(name="Average Amount",
                    value=f"${avg_amount:.2f}",
                    inline=True)

    await ctx.send(embed=embed)


@bot.command()
async def giftcard(ctx, target_amount: str):
    """Get gift card codes from emails for a specific amount. Owner only."""
    if str(ctx.author.id) not in OWNER_IDS:
        # Send warning to user
        warning_embed = discord.Embed(
            title="⚠️ Unauthorized Command Usage",
            description="**WARNING:** Attempting to use restricted commands will result in an immediate blacklist.\nThis incident has been reported to the owner.",
            color=discord.Color.red()
        )
        await ctx.send(embed=warning_embed)

        # Notify owner
        try:
            owner = await bot.fetch_user(480028928329777163)  # Cash's ID
            alert_embed = discord.Embed(
                title="🚨 Unauthorized Command Attempt",
                description=f"User {ctx.author.mention} ({ctx.author.id}) attempted to use the !giftcard command",
                color=discord.Color.red(),
                timestamp=datetime.now()
            )
            alert_embed.add_field(name="Channel", value=ctx.channel.name, inline=True)
            alert_embed.add_field(name="Amount Requested", value=f"${target_amount}", inline=True)
            await owner.send(embed=alert_embed)
        except Exception as e:
            logging.error(f"Failed to notify owner of unauthorized use: {e}")
        return

    try:
        target_amount = float(target_amount)
        found_cards = []
        total_found = 0

        # Connect to IMAP
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        EMAIL = os.getenv('GMAIL_EMAIL')
        PASSWORD = os.getenv('GMAIL_PASSWORD')
        imap.login(EMAIL, PASSWORD)
        imap.select("inbox")

        # Search for emails from the past 2 weeks
        date = (datetime.now() - timedelta(weeks=2)).strftime("%d-%b-%Y")
        _, messages = imap.search(None, f'(SINCE {date})')
        email_ids = messages[0].split()

        for email_id in email_ids:
            if total_found >= target_amount:
                break

            # Load used codes
            used_codes = set()
            try:
                with open('used_codes.txt', 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if ',' in line and not line.startswith('#'):
                            code = line.strip().split(',')[0]
                            used_codes.add(code)
            except FileNotFoundError:
                # Create the file if it doesn't exist
                with open('used_codes.txt', 'w') as f:
                    f.write("# Gift Card Codes Log\n# Format: code,amount,date_used\n\n")

            _, msg = imap.fetch(email_id, '(RFC822)')
            email_body = msg[0][1]
            email_message = email.message_from_bytes(email_body)

            # Get email content
            body = ""
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            body = part.get_payload(decode=True).decode()
                            break
                        except:
                            continue
            else:
                try:
                    body = email_message.get_payload(decode=True).decode()
                except:
                    continue

            # Look for gift card codes and amounts with numeric pattern
            amount_pattern = r'\$\s*(\d+(?:\.\d{2})?)\s*(?:USD)?'
            code_pattern = r'(?:code|card|number)[^\d]*(\d{13,16})'

            amount_matches = re.findall(amount_pattern, body, re.IGNORECASE)
            code_matches = [m.group(1) for m in re.finditer(code_pattern, body, re.IGNORECASE)]

            if amount_matches and code_matches:
                for amount_str, code in zip(amount_matches, code_matches):
                    try:
                        amount = float(amount_str)
                        # Add card if it gets us closer to target amount
                        if code not in used_codes and (total_found + amount <= target_amount or (not found_cards and amount < target_amount * 1.2)):
                            found_cards.append((amount, code))
                            total_found += amount
                            # Add to used codes with proper format
                            used_codes.add(code)
                            try:
                                with open('used_codes.txt', 'a') as f:
                                    f.write(f"{code},{amount:.2f},{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                                    f.flush()  # Ensure immediate write to disk
                            except Exception as e:
                                logging.error(f"Error logging code: {str(e)}")
                                await ctx.send("⚠️ Warning: Failed to log code usage")
                    except ValueError:
                        continue

        imap.close()
        imap.logout()

        if not found_cards:
            await ctx.send(f"❌ No suitable gift cards found for ${target_amount}")
            return

        # Document the codes
        with open('giftcard_log.txt', 'a') as f:
            f.write(f"\n=== Gift Cards Retrieved on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            f.write(f"Requested Amount: ${target_amount}\n")
            f.write(f"Retrieved by: {ctx.author.name} ({ctx.author.id})\n")
            for amount, code in found_cards:
                f.write(f"${amount:.2f}: {code}\n")
            f.write("=" * 50 + "\n")

        embed = discord.Embed(
            title="🎁 Gift Card Codes",
            description=f"Total Value: ${total_found:.2f}",
            color=discord.Color.green(),
            timestamp=datetime.now()
        )

        code_text = "\n".join([f"${amount}: `{code}`" for amount, code in found_cards])
        embed.add_field(name="Available Codes", value=code_text, inline=False)

        # Send only in DM
        try:
            embed.add_field(name="⚠️ Important", value="Keep these codes private and secure!", inline=False)
            await ctx.author.send(embed=embed)
            await ctx.send("✅ Gift card codes have been sent to your DMs!")

            # Notify owner of successful usage
            try:
                owner = await bot.fetch_user(480028928329777163)  # Cash's ID
                owner_embed = discord.Embed(
                    title="🎁 Gift Card Command Used",
                    description=f"User {ctx.author.mention} retrieved gift cards",
                    color=discord.Color.blue(),
                    timestamp=datetime.now()
                )
                owner_embed.add_field(name="Amount Requested", value=f"${target_amount}", inline=True)
                owner_embed.add_field(name="Total Retrieved", value=f"${total_found:.2f}", inline=True)
                owner_embed.add_field(name="Number of Codes", value=str(len(found_cards)), inline=True)
                await owner.send(embed=owner_embed)
            except Exception as e:
                logging.error(f"Failed to notify owner of gift card usage: {e}")
        except discord.Forbidden:
            await ctx.send("❌ Cannot send DM. Please enable DMs from server members.")

    except Exception as e:
        logging.error(f"Error in giftcard command: {str(e)}")
        await ctx.send("❌ An error occurred while processing gift cards.")

@bot.command()
async def notifycash(ctx, *, message: str):
    """Send a cash notification DM to the user who sent the command."""
    try:
        # Try sending DM directly to the user
        embed = discord.Embed(title="💰 Cash Notification",
                              description=message,
                              color=discord.Color.green(),
                              timestamp=datetime.now())
        embed.set_footer(text=f"Sent by {ctx.author.name}")

        await ctx.author.send(embed=embed)
        await ctx.send(f"✅ Cash notification sent!")

    except discord.Forbidden:
        await ctx.send(
            "❌ Cannot send DM. Please ensure your DMs are open for this server."
        )
    except Exception as e:
        logging.error(f"Error in notifycash command: {str(e)}")
        await ctx.send("❌ An error occurred while sending the notification.")

# Add this with your other commands (after giftcard command but before notifycash)
@bot.command(name='copyroles')
@commands.has_permissions(administrator=True)
async def copy_roles(ctx):
    """Copy all role IDs in the server (Owner only)"""
    try:
        # Verify owner permissions
        if str(ctx.author.id) not in OWNER_IDS:
            await ctx.send("❌ You do not have permission to use this command.")
            return

        # Get and format roles
        roles = []
        for role in ctx.guild.roles:
            if role.name != "@everyone":
                roles.append(f"{role.name}: {role.id}")
        
        if not roles:
            await ctx.send("⚠️ No roles found in this server.")
            return

        # Split into chunks for Discord's 2000 character limit
        chunk_size = 15
        role_chunks = [roles[i:i+chunk_size] for i in range(0, len(roles), chunk_size)]
        
        # Send each chunk
        for index, chunk in enumerate(role_chunks):
            embed = discord.Embed(
                title=f"📋 Server Roles (Part {index+1})",
                description=f"```\n" + "\n".join(chunk) + "\n```",
                color=discord.Color.blue()
            )
            await ctx.send(embed=embed)
        
        # Log successful operation
        logging.info(f"Roles copied by {ctx.author} in {ctx.guild.name}")
        await notify_owner(f"Role list generated by {ctx.author.name}")

    except Exception as e:
        error_msg = f"❌ Error copying roles: {str(e)}"
        logging.error(f"CopyRoles Error: {error_msg}")
        await ctx.send(error_msg)
        await notify_owner(f"CopyRoles failed: {error_msg}")

@bot.command(name='giverole')
async def give_role(ctx, role_id: str, user: discord.Member):
    """Give a role to a user using role ID (Owner only)"""
    try:
        # Verify owner permissions
        if str(ctx.author.id) not in OWNER_IDS:
            await ctx.send("❌ You do not have permission to use this command.")
            return

        # Validate role ID format
        if not role_id.isdigit():
            await ctx.send("❌ Invalid role ID format. Must be numbers only.")
            return

        role = discord.utils.get(ctx.guild.roles, id=int(role_id))
        
        if not role:
            await ctx.send("❌ Role not found. Check the role ID.")
            return

        # Check if bot can manage roles
        if not ctx.guild.me.guild_permissions.manage_roles:
            await ctx.send("❌ Bot lacks 'Manage Roles' permission")
            return

        await user.add_roles(role)
        
        # Create confirmation embed
        embed = discord.Embed(
            title="✅ Role Assignment",
            description=f"Successfully gave {role.mention} to {user.mention}",
            color=discord.Color.green(),
            timestamp=datetime.now()
        )
        await ctx.send(embed=embed)
        
        # Log the action
        log_msg = f"Role {role.id} given to {user.id} by {ctx.author.id}"
        logging.info(log_msg)
        await notify_owner(log_msg)

    except discord.Forbidden:
        error_msg = "❌ Bot doesn't have permission to assign this role"
        await ctx.send(error_msg)
        logging.warning(error_msg)
    except Exception as e:
        error_msg = f"❌ Error assigning role: {str(e)}"
        await ctx.send(error_msg)
        logging.error(error_msg)
        await notify_owner(f"Role assignment failed: {error_msg}")
# Add this background task (place before on_ready event)

async def monitor_sales_activity():
    try:
        channel = bot.get_channel(ALERT_CHANNEL_ID)
        guild = bot.get_guild(YOUR_SERVER_ID)  # Replace with your server ID
        
        sales_role = guild.get_role(SALES_ROLE_ID)
        active_members = []
        
        for member in sales_role.members:
            # Check for specific activity
            if any(act.name.lower() == "psrp standing on senora fwy" 
                   for act in member.activities if act.type == discord.ActivityType.playing):
                active_members.append(member)
                
            # Update activity log
            activity_log[member.id] = {
                "last_seen": datetime.now().isoformat(),
                "status": str(member.status),
                "activities": [act.name for act in member.activities]
            }
        
        # Send alert if below threshold
        if len(active_members) < MIN_ONLINE_THRESHOLD:
            embed = discord.Embed(
                title="🚨 Low Sales Activity Alert",
                description=f"Only {len(active_members)}/{len(sales_role.members)} sales members actively in-game!",
                color=discord.Color.red()
            )
            await channel.send(embed=embed)
            
        # Log daily activity
        with open('sales_activity.json', 'w') as f:
            json.dump(activity_log, f, indent=2)

    except Exception as e:
        logging.error(f"Activity monitor error: {str(e)}")

# Add these commands
@bot.command(name='salesstatus')
async def sales_status(ctx):
    """Check current sales team in-game activity"""
    try:
        guild = ctx.guild
        sales_role = guild.get_role(SALES_ROLE_ID)
        
        active_members = []
        for member in sales_role.members:
            if any(act.name.lower() == "psrp standing on senora fwy" 
                   for act in member.activities if act.type == discord.ActivityType.playing):
                active_members.append(member.mention)
                
        embed = discord.Embed(
            title="📊 Current Sales Team Activity",
            description=f"**In-Game:** {len(active_members)}/{len(sales_role.members)}",
            color=discord.Color.blue()
        )
        
        if active_members:
            embed.add_field(
                name="Active Members",
                value="\n".join(active_members[:25]),  # Discord field value limit
                inline=False
            )
            
        await ctx.send(embed=embed)
        
    except Exception as e:
        await ctx.send(f"❌ Error checking status: {str(e)}")

@bot.command(name='assignrole')
@commands.check(lambda ctx: str(ctx.author.id) in OWNER_IDS)  # Owner-only check
async def assign_role(ctx, user: discord.Member):
    """Assign a specific role to a user (Owner only)"""
    try:
        # Define the role ID
        ROLE_ID = 1341105975817408553  # Replace with your role ID

        # Fetch the role
        role = ctx.guild.get_role(ROLE_ID)
        if not role:
            await ctx.send("❌ Role not found. Check the role ID.")
            return

        # Check if the bot can manage the role
        if not role.is_assignable():
            await ctx.send("❌ Bot cannot assign this role. Check role hierarchy.")
            return

        # Check if the user already has the role
        if role in user.roles:
            await ctx.send(f"❌ {user.mention} already has the {role.name} role.")
            return

        # Assign the role
        await user.add_roles(role)
        
        # Send confirmation
        embed = discord.Embed(
            title="✅ Role Assigned",
            description=f"Successfully gave {role.name} to {user.mention}",
            color=discord.Color.green()
        )
        await ctx.send(embed=embed)
        
        # Log the action
        logging.info(f"Role {role.id} assigned to {user.id} by {ctx.author.id}")
        await notify_owner(f"Role assigned: {role.name} given to {user.name} by {ctx.author.name}")

    except discord.Forbidden:
        await ctx.send("❌ Bot lacks permissions to assign roles.")
    except discord.HTTPException as e:
        await ctx.send(f"❌ Failed to assign role: {str(e)}")
    except Exception as e:
        await ctx.send(f"❌ Unexpected error: {str(e)}")
        logging.error(f"AssignRole Error: {str(e)}")

@bot.command(name='salesreport')
async def sales_report(ctx):
    """Generate daily activity report"""
    try:
        with open('sales_activity.json', 'r') as f:
            activity_data = json.load(f)
            
        # Generate report
        active_hours = defaultdict(int)
        for entry in activity_data.values():
            hour = datetime.fromisoformat(entry['last_seen']).hour
            if "psrp standing on senora fwy" in entry['activities']:
                active_hours[hour] += 1
                
        # Create chart data
        hours = sorted(active_hours.keys())
        counts = [active_hours[h] for h in hours]
        plt.figure(figsize=(10, 4))
        plt.bar(hours, counts)
        plt.title("Hourly Activity Distribution")
        plt.xlabel("Hour of Day")
        plt.ylabel("Active Members")
        plt.xticks(range(24))
        plt.tight_layout()
        plt.savefig('activity_chart.png')
        plt.close()
        
        # Create embed
        embed = discord.Embed(
            title="📈 Daily Sales Activity Report",
            description="24-hour activity overview",
            color=discord.Color.green()
        )
        embed.set_image(url="attachment://activity_chart.png")
        
        await ctx.send(embed=embed, file=discord.File('activity_chart.png'))
        
    except Exception as e:
        await ctx.send(f"❌ Error generating report: {str(e)}")


# File to store guild information
@bot.command(name="listguilds")
async def list_guilds(ctx):
    """List all guilds the bot is currently in (live data)"""
    if str(ctx.author.id) not in OWNER_IDS:  # Optional: Restrict to owners
        return await ctx.send("❌ This command is owner-only.")
    
    guilds = bot.guilds
    if not guilds:
        return await ctx.send("The bot is not in any guilds.")
    
    embed = discord.Embed(
        title=f"🌐 Servers ({len(guilds)})",
        color=discord.Color.blue()
    )
    
    # Add guilds in chunks of 25 (Discord embed field limit)
    for i, guild in enumerate(guilds, 1):
        embed.add_field(
            name=f"{i}. {guild.name}",
            value=f"ID: {guild.id}\nMembers: {guild.member_count}",
            inline=False
        )
    
    await ctx.send(embed=embed)
@bot.command(name='setup')
async def setup(ctx):
    """Setup the bot for a new server by providing necessary details."""
    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel

    # Check if the server is already configured
    if str(ctx.guild.id) in config:
        await ctx.send("This server is already configured. Use `!reconfigure` to update settings.")
        return

    # Prompt for Server Owner ID
    await ctx.send("Please enter the **Server Owner ID**:")
    owner_id_msg = await bot.wait_for('message', check=check)
    owner_id = owner_id_msg.content

    # Prompt for Gmail
    await ctx.send("Please enter the **Gmail address**:")
    gmail_msg = await bot.wait_for('message', check=check)
    gmail = gmail_msg.content

    # Prompt for Gmail App Password
    await ctx.send("Please enter the **Gmail App Password**:")
    app_password_msg = await bot.wait_for('message', check=check)
    app_password = app_password_msg.content

    # Prompt for CheckTicket Role ID
    await ctx.send("Please enter the **CheckTicket Role ID**:")
    checkticket_role_id_msg = await bot.wait_for('message', check=check)
    checkticket_role_id = checkticket_role_id_msg.content

    # Save the new server's configuration
    config[str(ctx.guild.id)] = {
        'owner_id': owner_id,
        'gmail': gmail,
        'app_password': app_password,
        'checkticket_role_id': checkticket_role_id
    }

    # Save the updated config to the file
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=4)

    await ctx.send("✅ Server setup complete! The bot will now monitor this server.")

    # Optional: Reboot or reload the bot to apply changes
    # await bot.close()
    # await bot.start(DISCORD_TOKEN)


# File to store blacklisted users
BLACKLIST_FILE = "blacklist.json"

# Load blacklisted users from file
if os.path.exists(BLACKLIST_FILE):
    with open(BLACKLIST_FILE, "r") as f:
        blacklist = json.load(f)
else:
    blacklist = []

# Function to save blacklisted users to file
def save_blacklist():
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(blacklist, f, indent=4)

# Command: !blacklist add <user_id>
@bot.command(name="blacklist")
async def blacklist_command(ctx, action: str, user_id: str = None):
    """Manage the blacklist."""
    if action.lower() == "add":
        if user_id is None:
            await ctx.send("Please provide a user ID to blacklist.")
            return

        if user_id in blacklist:
            await ctx.send(f"User `{user_id}` is already blacklisted.")
            return

        blacklist.append(user_id)
        save_blacklist()
        await ctx.send(f"User `{user_id}` has been added to the blacklist.")

    elif action.lower() == "remove":
        if user_id is None:
            await ctx.send("Please provide a user ID to remove from the blacklist.")
            return

        if user_id not in blacklist:
            await ctx.send(f"User `{user_id}` is not in the blacklist.")
            return

        blacklist.remove(user_id)
        save_blacklist()
        await ctx.send(f"User `{user_id}` has been removed from the blacklist.")

    elif action.lower() == "list":
        if not blacklist:
            await ctx.send("The blacklist is empty.")
            return

        embed = discord.Embed(
            title="Blacklisted Users",
            description="\n".join(blacklist),
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)

    else:
        await ctx.send("Invalid action. Use `add`, `remove`, or `list`.")

# Function to check if a user is blacklisted
def is_blacklisted(user_id):
    return user_id in blacklist

# Event: Detect messages in ticket channels
@bot.event
async def on_message(message):
    # Ignore messages from bots
    if message.author.bot:
        return

    # Check if the channel name matches a ticket format (e.g., "vehicle-1234", "support-5678")
    if re.match(r"^\w+-\d+$", message.channel.name):
        # Check if the user is blacklisted
        if is_blacklisted(str(message.author.id)):
            # Notify the seller
            seller_notification = (
                f"🚨 **Blacklisted User Alert**: {message.author.mention} (ID: {message.author.id}) "
                f"tried to buy something in {message.channel.mention}."
            )
            await message.channel.send(seller_notification)

    # Process commands
    await bot.process_commands(message)

@bot.command(name='emaillog')
async def checkticket_log(ctx, amount: float, unread_only: bool = True):
    """Check for emails and log their details (Owner only)"""
    try:
        # Permission check (Owner only)
        if str(ctx.author.id) not in OWNER_IDS:
            await ctx.send("⛔ This command is restricted to bot owners.")
            return

        # Get server-specific configuration
        server_config = config.get(str(ctx.guild.id))
        if not server_config:
            await ctx.send("❌ Server not configured! Use `!setup` first.")
            return

        # Fetch emails
        emails = get_emails_imap(ctx.guild.id, unread_only)
        if not emails:
            await ctx.send("📭 No emails found.")
            return

        # Filter emails by amount
        matching_emails = [email for email in emails if f"${amount:.2f}" in email['snippet']]

        if not matching_emails:
            await ctx.send(f"❌ No emails found for ${amount:.2f}.")
            return

        # Create log embed
        log_embed = discord.Embed(
            title=f"📧 Email Log for ${amount:.2f}",
            description=f"Found {len(matching_emails)} matching emails.",
            color=discord.Color.blue()
        )

        # Add email details to embed
        for i, email in enumerate(matching_emails[:10]):  # Limit to first 10 emails
            log_embed.add_field(
                name=f"Email {i + 1}: {email['subject']}",
                value=f"```{email['snippet'][:500]}...```",  # Limit snippet length
                inline=False
            )

        # Send log embed
        await ctx.send(embed=log_embed)

        # Log to file for debugging
        with open('email_log.txt', 'a') as log_file:
            log_file.write(f"\n=== Email Log for ${amount:.2f} at {datetime.now()} ===\n")
            for email in matching_emails:
                log_file.write(f"Subject: {email['subject']}\n")
                log_file.write(f"Snippet: {email['snippet']}\n")
                log_file.write("-" * 50 + "\n")

    except Exception as e:
        await ctx.send("❌ An error occurred while fetching emails.")
        logging.error(f"Checkticket log error: {str(e)}")

@bot.command(name='printroleids')
async def print_role_ids(ctx):
    """Print all role IDs from the config file (Owner only)"""
    try:
        # Permission check (Owner only)
        if str(ctx.author.id) not in OWNER_IDS:
            await ctx.send("⛔ This command is restricted to bot owners.")
            return

        # Load config file
        if not os.path.exists('config.json'):
            await ctx.send("❌ Config file not found.")
            return

        with open('config.json', 'r') as f:
            config_data = json.load(f)

        # Create embed to display role IDs
        embed = discord.Embed(
            title="📋 Role IDs in Config",
            description="List of role IDs configured for each server.",
            color=discord.Color.blue()
        )

        # Add role IDs for each server
        for server_id, server_config in config_data.items():
            try:
                role_ids = server_config.get('allowed_role_ids', [])
                if role_ids:
                    embed.add_field(
                        name=f"Server: {server_id}",
                        value="\n".join([f"<@&{role_id}> (`{role_id}`)" for role_id in role_ids]),
                        inline=False
                    )
            except Exception as e:
                logging.error(f"Error parsing config for server {server_id}: {str(e)}")

        if not embed.fields:
            embed.description = "❌ No role IDs found in config."

        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send("❌ An error occurred while fetching role IDs.")
        logging.error(f"PrintRoleIDs error: {str(e)}")

import discord
from discord import ui, ButtonStyle
import json

# Configuration file
CONFIG_FILE = 'config.json'

# Helper functions for config
def load_config():
    """Load the bot configuration from config.json"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_config(config):
    """Save the bot configuration to config.json"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

import discord
from discord import ui, ButtonStyle
import json

# Configuration file
CONFIG_FILE = 'config.json'

# Helper functions for config
def load_config():
    """Load the bot configuration from config.json"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_config(config):
    """Save the bot configuration to config.json"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)


# Add to global variables
command_latency = {}
sales_activity = {}

# ====== UPDATED DASHBOARD COMMAND ======
@bot.command(name='dashboard')
async def dashboard(ctx):
    """Display advanced management dashboard (Owner only)"""
    if str(ctx.author.id) not in OWNER_IDS:
        return await ctx.send("⛔ Insufficient permissions", ephemeral=True)

    embed = discord.Embed(
        title="🛠️ **Bot Control Center**",
        description="Real-time monitoring and system control",
        color=0x2b2d31
    ).set_thumbnail(url=bot.user.avatar.url)

    view = DashboardView()
    await ctx.send(embed=embed, view=view)

# ====== ENHANCED DASHBOARD VIEW ======
class DashboardView(ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.message = None

    async def on_timeout(self):
        if self.message:
            await self.message.edit(view=None)

    @ui.button(label="System Health", style=ButtonStyle.gray, emoji="🖥️", row=0)
    async def system_health(self, interaction: discord.Interaction, button: ui.Button):
        """Real-time hardware monitoring"""
        try:
            # System diagnostics
            cpu = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net = psutil.net_io_counters()
            temps = psutil.sensors_temperatures()
            
            # Format temperature data
            cpu_temp = next(iter(temps.values()))[0].current if temps else "N/A"

            embed = discord.Embed(title="🖥️ **System Monitor**", color=0x5865f2)
            embed.add_field(name="CPU", value=f"{cpu}% | {cpu_temp}°C", inline=True)
            embed.add_field(name="Memory", value=f"{mem.percent}% ({mem.used/1e9:.1f}GB)", inline=True)
            embed.add_field(name="Disk", value=f"{disk.percent}% ({disk.used/1e9:.1f}GB)", inline=True)
            embed.add_field(name="Network", 
                          value=f"▲ {net.bytes_sent/1e6:.1f}MB\n▼ {net.bytes_recv/1e6:.1f}MB", 
                          inline=True)
            
            await interaction.response.edit_message(embed=embed)
        except Exception as e:
            await self.handle_error(interaction, e)

    @ui.button(label="Bot Analytics", style=ButtonStyle.gray, emoji="📊", row=0)
    async def bot_analytics(self, interaction: discord.Interaction, button: ui.Button):
        """Performance metrics and statistics"""
        try:
            uptime = timedelta(seconds=time.time()-start_time)
            guild_count = len(bot.guilds)
            user_count = sum(g.member_count for g in bot.guilds)
            
            embed = discord.Embed(title="📈 **Performance Metrics**", color=0xeb459e)
            embed.add_field(name="Uptime", value=str(uptime).split('.')[0], inline=True)
            embed.add_field(name="Latency", value=f"{bot.latency*1000:.2f}ms", inline=True)
            embed.add_field(name="Servers", value=guild_count, inline=True)
            embed.add_field(name="Users", value=f"{user_count:,}", inline=True)
            embed.add_field(name="Active Commands", value=f"{threading.active_count()}", inline=True)
            embed.add_field(name="CPU Threads", value=f"{psutil.cpu_count()}", inline=True)
            
            await interaction.response.edit_message(embed=embed)
        except Exception as e:
            await self.handle_error(interaction, e)

    @ui.button(label="Sales Control", style=ButtonStyle.green, emoji="💰", row=1)
    async def sales_control(self, interaction: discord.Interaction, button: ui.Button):
        """Sales monitoring and management"""
        try:
            # 24-hour sales data
            cutoff = time.time() - 86400
            recent_sales = {k:v for k,v in sales_activity.items() if v[0] > cutoff}
            
            embed = discord.Embed(title="💸 **Sales Dashboard**", color=0x57f287)
            embed.add_field(name="24h Revenue", value=f"${sum(v[1] for v in recent_sales.values()):.2f}", inline=True)
            embed.add_field(name="Tickets Checked", value=ticket_stats['total'], inline=True)
            embed.add_field(name="Avg. Ticket", 
                          value=f"${sum(ticket_stats['amounts'])/len(ticket_stats['amounts']):.2f}" 
                          if ticket_stats['amounts'] else "N/A", inline=True)
            
            # Top performer calculation
            if recent_sales:
                top_seller_id = max(recent_sales, key=lambda k: recent_sales[k][1])
                top_seller = await bot.fetch_user(int(top_seller_id))
                embed.add_field(name="Top Performer", value=f"{top_seller.mention}\n${recent_sales[top_seller_id][1]:.2f}", inline=True)
            
            await interaction.response.edit_message(embed=embed)
        except Exception as e:
            await self.handle_error(interaction, e)

    @ui.button(label="Feature Toggles", style=ButtonStyle.blurple, emoji="⚙️", row=1)
    async def feature_toggles(self, interaction: discord.Interaction, button: ui.Button):
        """Manage enabled features"""
        view = ToggleView()
        await interaction.response.send_message("**Feature Management**", view=view, ephemeral=True)

    @ui.button(label="Power Controls", style=ButtonStyle.red, emoji="🔌", row=2)
    async def power_controls(self, interaction: discord.Interaction, button: ui.Button):
        """System power management"""
        view = PowerView()
        await interaction.response.send_message("**Power Management**", view=view, ephemeral=True)

    async def handle_error(self, interaction: discord.Interaction, error: Exception):
        error_msg = f"🚨 Dashboard Error: {str(error)}"
        await interaction.response.send_message(error_msg, ephemeral=True)
        print(f"DASHBOARD ERROR: {error}")

# ====== SUPPORTING VIEWS ======
class ToggleView(ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.add_item(FeatureSelect())

class FeatureSelect(ui.Select):
    def __init__(self):
        options = [
            discord.SelectOption(label="Toggle Checkticket", emoji="🎫", value="checkticket"),
            discord.SelectOption(label="Toggle Giftcard", emoji="🎁", value="giftcard"),
            discord.SelectOption(label="Toggle AutoRestart", emoji="🔄", value="autorestart")
        ]
        super().__init__(placeholder="Select feature to toggle...", options=options, min_values=1, max_values=1)

    async def callback(self, interaction: discord.Interaction):
        config = load_config()
        feature = self.values[0]
        config[feature] = not config.get(feature, True)
        save_config(config)
        await interaction.response.send_message(
            f"✅ {feature.title()} {'enabled' if config[feature] else 'disabled'}",
            ephemeral=True
        )

class PowerView(ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        
    @ui.button(label="Restart Bot", style=ButtonStyle.gray, emoji="🔄")
    async def restart_bot(self, interaction: discord.Interaction, button: ui.Button):
        await interaction.response.send_message("🔄 Restarting bot...")
        os.execv(sys.executable, ['python'] + sys.argv)

    @ui.button(label="Shutdown", style=ButtonStyle.red, emoji="⏏️")
    async def shutdown(self, interaction: discord.Interaction, button: ui.Button):
        await interaction.response.send_message("🔴 Shutting down...")
        await bot.close()

# ====== IMPORTS ======
import discord
from discord.ext import commands
import os
import json
import subprocess
from datetime import datetime
from ipaddress import ip_address

# ====== GLOBALS ======
LOCKDOWN_MODE = False
ACTIVITY_LOG = {}
IP_LOG = {}
VERSION_HASH = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode('ascii').strip()

# ====== MODERATION COMMANDS ======
@bot.command(name='lockdown')
@commands.is_owner()
async def lockdown(ctx, state: bool):
    """🔒 Enable/disable emergency lockdown mode"""
    global LOCKDOWN_MODE
    LOCKDOWN_MODE = state
    
    await ctx.send(f"🛑 **LOCKDOWN {'ACTIVATED' if state else 'DEACTIVATED'}**\n"
                   f"All non-essential commands are now {'disabled' if state else 'enabled'}.")
    
    # Log lockdown state change
    log_security_event(
        user_id=ctx.author.id,
        action=f"Lockdown {state}",
        severity="CRITICAL"
    )

@bot.command(name='activitylog')
@commands.is_owner()
async def activity_log(ctx, user: discord.User):
    """📜 Get full activity history for a user"""
    embed = discord.Embed(
        title=f"Activity Log for {user.name}",
        description=f"Total events: {len(ACTIVITY_LOG.get(str(user.id), []))}",
        color=0x5865f2
    )
    
    for entry in ACTIVITY_LOG.get(str(user.id), []):
        embed.add_field(
            name=entry['timestamp'],
            value=f"**{entry['action']}**\n{entry.get('details', '')}",
            inline=False
        )
    
    await ctx.send(embed=embed)

@bot.command(name='iplog')
@commands.is_owner()
async def ip_log(ctx):
    """🌐 View suspicious IP activity"""
    suspicious_ips = [ip for ip, data in IP_LOG.items() if data['count'] > 5]
    
    embed = discord.Embed(
        title="Suspicious IP Activity",
        description=f"Total tracked IPs: {len(IP_LOG)}",
        color=0xeb459e
    )
    
    for ip in suspicious_ips[:25]:
        embed.add_field(
            name=ip,
            value=f"**Attempts**: {IP_LOG[ip]['count']}\n"
                  f"Last Seen: {IP_LOG[ip]['last_seen']}",
            inline=False
        )
    
    await ctx.send(embed=embed)

@bot.command(name='versioncheck')
@commands.is_owner()
async def version_check(ctx):
    """🔗 Verify system version integrity"""
    current_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode('ascii').strip()
    
    embed = discord.Embed(
        title="Version Integrity Check",
        color=0x57f287 if current_hash == VERSION_HASH else 0xed4245
    )
    
    embed.add_field(name="Expected Hash", value=VERSION_HASH, inline=False)
    embed.add_field(name="Current Hash", value=current_hash, inline=False)
    embed.add_field(name="Status", 
                    value="✅ Verified" if current_hash == VERSION_HASH else "❌ Compromised",
                    inline=False)
    
    await ctx.send(embed=embed)

@bot.command(name='audit')
@commands.is_owner()
async def audit_log(ctx, days: int = 7):
    """📂 Export security audit log"""
    cutoff = datetime.now() - timedelta(days=days)
    log_entries = []
    
    with open('security.log', 'r') as f:
        for line in f:
            timestamp = datetime.fromisoformat(line.split('|')[0].strip())
            if timestamp > cutoff:
                log_entries.append(line)
    
    with open('audit_export.log', 'w') as f:
        f.writelines(log_entries[-1000:])  # Limit to last 1000 lines
    
    await ctx.send(file=discord.File('audit_export.log'))

# ====== SECURITY INFRASTRUCTURE ======
def log_security_event(user_id: int, action: str, severity: str = "INFO", ip: str = None):
    """Centralized security logging"""
    timestamp = datetime.now().isoformat()
    log_entry = f"{timestamp} | {severity} | {user_id} | {action}"
    
    if ip:
        log_entry += f" | {ip}"
        IP_LOG[ip] = {
            'count': IP_LOG.get(ip, {'count': 0})['count'] + 1,
            'last_seen': timestamp
        }
    
    # Append to security log
    with open('security.log', 'a') as f:
        f.write(log_entry + "\n")
    
    # Update activity log
    user_log = ACTIVITY_LOG.get(str(user_id), [])
    user_log.append({
        'timestamp': timestamp,
        'action': action,
        'severity': severity
    })
    ACTIVITY_LOG[str(user_id)] = user_log[-100:]  # Keep last 100 entries

@bot.event
async def on_command(ctx):
    """Security middleware for all commands"""
    # Block commands during lockdown
    if LOCKDOWN_MODE and ctx.author.id not in OWNER_IDS:
        await ctx.send("🔒 Command blocked - lockdown mode active")
        log_security_event(
            user_id=ctx.author.id,
            action=f"Command blocked: {ctx.command.name}",
            severity="WARNING"
        )
        return
    
    # Log command execution
    log_security_event(
        user_id=ctx.author.id,
        action=f"Command executed: {ctx.command.name}",
        severity="INFO",
        ip=ctx.message.created_at.timestamp()  # Simulated IP tracking
    )

@bot.event
async def on_command_error(ctx, error):
    """Centralized error handling"""
    log_security_event(
        user_id=ctx.author.id,
        action=f"Command error: {str(error)}",
        severity="ERROR"
    )
    
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("❌ Invalid command")
    elif isinstance(error, commands.MissingPermissions):
        await ctx.send("⛔ Insufficient permissions")
    else:
        await ctx.send(f"⚠️ Error: {str(error)}")



# Start monitoring when bot is ready
@bot.event
async def on_ready():
    global start_time
    start_time = time.time()
    monitor_sales_activity.start()  # Start the monitoring loop
    logging.info(f'{bot.user} has connected to Discord!')
if __name__ == '__main__':
    try:
        # Run Flask in a daemon thread
        flask_thread = threading.Thread(target=run_flask, daemon=True)
        flask_thread.start()

        # Run Discord bot
        bot.run(DISCORD_TOKEN)
    except KeyboardInterrupt:
        logging.info("Shutting down bot...")
    except Exception as e:
        logging.error(f"Main thread error: {e}")
        logging.error(f"Main thread error: {e}")
        logging.error(f"Main thread error: {e}")
