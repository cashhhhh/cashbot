






import re
import os
import pickle
import logging
import time
import imaplib
import email
from datetime import datetime, timedelta
from email.header import decode_header
from flask import Flask, redirect, request
import discord
from discord.ext import commands
from discord.ui import Button, View
import threading
import asyncio
import boto3  # AWS SDK for Python
import psutil
import json
from dotenv import load_dotenv

load_dotenv() 



# Load or create a config file
if os.path.exists('config.json'):
    with open('config.json', 'r') as f:
        config = json.load(f)
else:
    config = {}
# At top of file if not already present:
giftcard_cache = {
    "value": 0.0,
    "used": 0.0,
    "unused": 0.0,
    "codes": 0,
    "last_updated": 0
}

def load_used_codes():
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
# Track all command usages
command_usage_logs = []  # [(timestamp, guild_id, command_name)]
dashboard_sessions = {}  # {user_id: {"page": int}}



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

# ✅ Minimal Reposting Loop Injected into Existing Bot

SOURCE_CHANNEL_ID = 1361882298282283161
REPOST_CHANNELS = [
    1223077287457587221,
    1361847485961601134
]

last_reposted_ids = set()

from discord.ext import tasks

async def perform_repost():
    try:
        source = bot.get_channel(SOURCE_CHANNEL_ID)
        targets = [bot.get_channel(cid) for cid in REPOST_CHANNELS]

        if not source or any(ch is None for ch in targets):
            print("❌ Missing channel(s).")
            return

        messages = [msg async for msg in source.history(limit=5)]
        for msg in reversed(messages):  # oldest first
            if msg.id in last_reposted_ids:
                continue

            full_text = msg.content or ""

            # Include full embed content if present
            for em in msg.embeds:
                if em.title:
                    full_text += f"\n**{em.title}**"
                if em.description:
                    full_text += f"\n{em.description}"
                for field in em.fields:
                    full_text += f"\n**{field.name}**\n{field.value}"

            full_text = full_text.strip() or "[No content]"

            embed = discord.Embed(
                title="🔁 Repost from PSRP",
                description=full_text[:4000],  # Embed limit safeguard
                color=0x3498db
            )

            for ch in targets:
                await ch.send(embed=embed)

            last_reposted_ids.add(msg.id)
            print(f"✅ Reposted message {msg.id}")

    except Exception as e:
        print(f"❌ Error: {e}")


@tasks.loop(seconds=10)
async def auto_repost():
    print("⏱️ Auto repost loop ticked")
    await perform_repost()

@bot.command()
@commands.is_owner()
async def manualrepost(ctx):
    await perform_repost()
    await ctx.send("✅ Manual repost check complete.")


@bot.event
async def on_ready():
    global start_time
    start_time = time.time()

    print(f"✅ Logged in as {bot.user}")
    auto_repost.start()  # ← ✅ starts the repost loop
    monitor_sales_activity.start()  # ← if you're using this too

    # Optional: Update channel ping or logging
    update_channel = bot.get_channel(1361849234550165618)
    if update_channel:
        await update_channel.send("🔄 **Bot restarted. Repost loop is active.**")



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

    allowed_role_ids = [1103522760073945168, 1325902622120738866, 1361045953296990490, 1332736087029710958, 1361231253596278794, 1319913613389074487, 1267783758757757045, 1330907621984833536]
    is_owner = str(ctx.author.id) in OWNER_IDS
    has_role = any(role.id in allowed_role_ids for role in ctx.author.roles)


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



from datetime import datetime, timedelta
import re
import string

CAR_VALUES = {
    "amloadinga": 10, "cccrazy": 10, "vanzs14": 0, "jtss": 10, "petedaycab/trailkinght": 8,
    "dombeast": 30, "ruffgt40v2": 30, "rryosemite1500nlc": 30, "rryosemite1500nlc2": 30, "offdominatorcaracpd": 30,
    "fgt86": 12, "donblaze": 12, "superfox2": 12, "ugc23h2r": 7, "loadingcamz1x": 10, "vanz23mloadingwb": 8,
    "godzdrzrprolftd": 5, "loadinghy21": 8, "godzloadingwbv2": 7, "vanzch06": 7, "fcustmaro": 5, "loadingfen": 4,
    "loadinggodz300uc": 4, "cumminscaddy": 3, "loadingvia": 3, "zaccdrag150weld": 5, "jacksubie": 5, "ccsttgloading": 5,
    "razerdragmlovading": 5, "dragrtrstang": 5, "godztloading": 4, "godz69mav2": 5, "godzlctrdcencal": 4, "godza90drift": 5,
    "bcr1drag": 4, "zacclowlind": 4, "gsstmp4": 5, "gstcs21b": 5, "bcsick7": 6, "loadingairwb": 4, "freebogemenzo": 3,
    "plutomloading5": 4, "factisr35": 4, "jdmodelloading": 2, "godzevxdrift": 3, "ccvip": 5, "sou_loading_wb_8": 4,
    "toraloadingden": 4, "loadinghe": 2, "godzkr23loadingmega": 4, "driftahbug": 3, "dillloading": 2, "jaws": 2,
    "bcbuggyxl": 2, "godzd75loading4drsema": 5, "carteltrailerv2": 3, "loading450": 4, "bbmower": 3, "loadingyz": 4,
    "burritopw": 3, "vetog": 2, "vetok": 2, "jloadingb": 2, "fakeyak": 1, "godzt12m": 3, "vbbpxxc": 4,
    "godzd75loading4drsemakart": 5, "godzkarttrailer": 3, "mti": 2, "280z": 3, "godztcploading": 3, "godzxc1hovercraft": 2,
    "335brm": 2, "loadduck": 2, "hippie": 5, "f117a": 50, "trudy": 50, "f22a": 50, "darkstar": 50,
    "loading15s": 50, "f35c": 50, "hh60g": 50
}

FRAUD_WATCH_CHANNEL = 1361847485961601134
FRAUD_ALERT_CHANNEL = 1362243005435740410
OWNER_ID = 480028928329777163

checkticket_logs = []

@bot.event
async def on_message(message):
    now = datetime.utcnow()


    # ✅ Track checkticket commands
    if message.content.startswith("!checkticket") or "$" in message.content:
        dollar_match = re.search(r"\$(\d+)", message.content)
        if dollar_match:
            value = int(dollar_match.group(1))
            checkticket_logs.append((now, value))
            checkticket_logs[:] = [(t, v) for t, v in checkticket_logs if now - t <= timedelta(minutes=10)]

    # ✅ FRAUD DETECTION
    if message.channel.id == FRAUD_WATCH_CHANNEL:
        print("📥 Watching message in fraud channel...")

        matched = []
        total_value = 0
        full_text = message.content or ""

        if message.embeds:
            for em in message.embeds:
                if em.title:
                    full_text += f"\n{em.title}"
                if em.description:
                    full_text += f"\n{em.description}"
                for field in em.fields:
                    full_text += f"\n{field.name}\n{field.value}"

        lines = full_text.lower().splitlines()
        cleaned_lines = [line.translate(str.maketrans("", "", string.punctuation)) for line in lines]

        for line in cleaned_lines:
            words = line.lower().split()
            for word in words:
                cleaned_word = word.strip()
                if cleaned_word in CAR_VALUES:
                    matched.append(cleaned_word)
                    total_value += CAR_VALUES[cleaned_word]

        if matched:
            print(f"🚨 Detected possible fraud: {matched} (${total_value})")
            valid = any(value >= total_value for ts, value in checkticket_logs if now - ts <= timedelta(minutes=10))
            if not valid:
                embed = discord.Embed(
                    title="🚨 Fraud Alert",
                    description=f"**Unmatched vehicle transfer**\nModels: {', '.join(matched)}\n**Total Value:** ${total_value}",
                    color=discord.Color.red()
                )
                embed.add_field(name="User", value=f"{message.author} ({message.author.id})")
                embed.add_field(name="Message", value=full_text[:1000], inline=False)

                try:
                    owner = await bot.fetch_user(OWNER_ID)
                    if owner:
                        await owner.send(embed=embed)
                except Exception as e:
                    print(f"❌ Failed to DM owner: {e}")

                try:
                    alert_channel = bot.get_channel(FRAUD_ALERT_CHANNEL)
                    if alert_channel:
                        await alert_channel.send(embed=embed)
                except Exception as e:
                    print(f"❌ Failed to post alert: {e}")

    # ✅ BLACKLIST DETECTION (Ticket channel name match)
    if re.match(r"^\w+-\d+$", message.channel.name):
        if is_blacklisted(str(message.author.id)):
            seller_notification = (
                f"🚨 **Blacklisted User Alert**: {message.author.mention} (ID: {message.author.id}) "
                f"tried to buy something in {message.channel.mention}."
            )
            await message.channel.send(seller_notification)

    # ✅ Always process commands
    await bot.process_commands(message)


@bot.event
async def on_message_delete(message):
    if message.author.bot:
        return

    if message.mentions:
        content = message.content or "*[no text]*"
        channel = message.channel
        embed = discord.Embed(
            title="👻 Ghost Ping Detected",
            description=f"{message.author.mention} tried to ping and dip.",
            color=discord.Color.orange(),
            timestamp=datetime.utcnow()
        )
        embed.add_field(name="Message Content", value=content, inline=False)
        embed.add_field(name="Channel", value=channel.mention, inline=True)

        alert_channel = bot.get_channel(1223077287457587221)



import re
import asyncio

# 🔧 Set your server & log channel IDs
DEV_SERVER_ID = 1361841087668289697  # <-- REPLACE with your dev server ID
LOG_CHANNEL_ID = 1361847485961601134  # <-- REPLACE with your log/staff channel ID

# 🧼 Words to watch for (lowercase only)
FLAGGED_WORDS = [
    "nigger", "faggot", "retard", "tranny", "rape", "porn", "cp",
    "grabify", "iplogger", "bootyou", "discord.gg/"
]

# ✅ Logs when someone joins the dev server
@bot.event
async def on_member_join(member):
    if member.guild.id == DEV_SERVER_ID:
        log_channel = bot.get_channel(LOG_CHANNEL_ID)
        await log_channel.send(f"✅ `{member}` joined the dev server. ID: `{member.id}`")

# ❌ Logs when someone leaves the dev server
@bot.event
async def on_member_remove(member):
    if member.guild.id == DEV_SERVER_ID:
        log_channel = bot.get_channel(LOG_CHANNEL_ID)
        await log_channel.send(f"❌ `{member}` left or was removed from the dev server. ID: `{member.id}`")



# 🧾 Manual audit command to list all current dev server members
@bot.command(name="auditdev")
@commands.is_owner()
async def audit_dev_server(ctx):
    guild = bot.get_guild(DEV_SERVER_ID)
    if not guild:
        return await ctx.send("❌ Bot is not in the dev server.")

    members = [f"{m} - {m.id}" for m in guild.members if not m.bot]
    log_channel = bot.get_channel(LOG_CHANNEL_ID)
    await log_channel.send(
        f"🧾 **Current Dev Server Members ({len(members)})**:\n" + "\n".join(members)
    )

import re



@bot.listen('on_command')
async def track_command_usage(ctx):
    now = datetime.utcnow()
    command_usage_logs.append((now, ctx.guild.id if ctx.guild else None, ctx.command.name))

    # Purge old logs beyond 5 days
    five_days_ago = now - timedelta(days=5)
    command_usage_logs[:] = [
        (timestamp, guild_id, command_name)
        for timestamp, guild_id, command_name in command_usage_logs
        if timestamp >= five_days_ago
    ]

@bot.command(name="remindme")
async def remind_me(ctx, time_str: str, *, reminder: str = "You asked to be reminded."):
    """Set a reminder. Example: !remindme 15m Do something."""
    
    # Convert time string (e.g. 10m, 5s, 1h) to seconds
    match = re.match(r"^(\d+)([smh])$", time_str.lower())
    if not match:
        return await ctx.send("❌ Invalid time format. Use like `10s`, `15m`, or `1h`.")

    amount, unit = match.groups()
    seconds = int(amount) * {"s": 1, "m": 60, "h": 3600}[unit]

    await ctx.send(f"✅ I’ll remind you in {amount}{unit}.")

    try:
        await asyncio.sleep(seconds)
        await ctx.author.send(f"⏰ Reminder: {reminder}")
    except Exception as e:
        print(f"[Reminder Error] {e}")

                                  
@bot.command(name="builddevserver")
@commands.is_owner()
async def build_dev_server(ctx):
    await ctx.send("🛠️ Creating **Cash Bot Dev Server**...")

    new_guild = await bot.create_guild(name="Cash Bot Dev Server")
    await asyncio.sleep(5)

    for _ in range(10):
        guild = discord.utils.get(bot.guilds, id=new_guild.id)
        if guild:
            break
        await asyncio.sleep(2)

    if not guild:
        return await ctx.send("❌ Failed to load the new server.")

    # Create roles
    perms = discord.Permissions
    roles = {
        "Bot Owner": perms(administrator=True),
        "Bot Dev": perms(manage_guild=True, manage_messages=True, read_message_history=True),
        "Trusted Admin": perms(manage_messages=True, view_audit_log=True),
        "Muted": perms(send_messages=False, read_messages=True)
    }

    role_refs = {}
    for role_name, role_perms in roles.items():
        role = await guild.create_role(name=role_name, permissions=role_perms)
        role_refs[role_name] = role

    # Build categories/channels
    categories = {
        "📢 BOT HQ": ["announcements", "changelog", "alerts"],
        "🔧 LOGS": ["training-logs", "credit-transfers", "checkticket-logs", "errors"],
        "🧠 DEVELOPMENT": ["feature-voting", "ideas", "dev-chat"],
        "👤 STAFF": ["admin-chat", "mod-support"],
        "📝 ONBOARDING": ["applications"]
    }

    for cat_name, channel_list in categories.items():
        overwrites = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False),
            role_refs["Bot Owner"]: discord.PermissionOverwrite(read_messages=True, send_messages=True),
            role_refs["Bot Dev"]: discord.PermissionOverwrite(read_messages=True, send_messages=True),
            role_refs["Trusted Admin"]: discord.PermissionOverwrite(read_messages=True, send_messages=True)
        }
        category = await guild.create_category(name=cat_name, overwrites=overwrites)
        for chan in channel_list:
            await guild.create_text_channel(name=chan, category=category)

    # Invite + DM
    ann_channel = discord.utils.get(guild.text_channels, name="announcements")
    invite = await ann_channel.create_invite(max_age=0, unique=True)

    try:
        await ctx.author.send(f"✅ Your Dev Server is ready: {invite.url}\n"
                              f"⚠️ After joining, run `!getownerrole` in the new server to receive your Bot Owner role.")
    except:
        await ctx.send("✅ Server created, but I couldn’t DM you the invite.")

    await ctx.send("🎉 Server created! Join it and run `!getownerrole` inside to claim your owner role.")@bot.command(name="apply")
async def apply(ctx):
    """Handles application flow in DMs and sends result to owner."""
    if ctx.channel.name != "applications":
        return await ctx.send("❌ You must run this in the #applications channel.")

    try:
        await ctx.author.send("📋 How many people are in your server?")
        people_msg = await bot.wait_for(
            "message",
            timeout=60,
            check=lambda m: m.author == ctx.author and isinstance(m.channel, discord.DMChannel)
        )

        await ctx.author.send("🚗 How many cars are you managing?")
        cars_msg = await bot.wait_for(
            "message",
            timeout=60,
            check=lambda m: m.author == ctx.author and isinstance(m.channel, discord.DMChannel)
        )

        owner = (await bot.application_info()).owner

        embed = discord.Embed(
            title="New Bot Access Application",
            description=f"**User:** {ctx.author.mention}\n"
                        f"**Server Size:** {people_msg.content}\n"
                        f"**Cars Managed:** {cars_msg.content}",
            color=discord.Color.orange(),
            timestamp=datetime.utcnow()
        )

        class ApprovalView(discord.ui.View):
            @discord.ui.button(label="Yes", style=discord.ButtonStyle.green)
            async def yes(self, interaction: discord.Interaction, button: discord.ui.Button):
                if interaction.user.id != owner.id:
                    return await interaction.response.send_message("❌ You’re not authorized.", ephemeral=True)
                await interaction.response.send_message("✅ Approved!", ephemeral=True)

            @discord.ui.button(label="No", style=discord.ButtonStyle.red)
            async def no(self, interaction: discord.Interaction, button: discord.ui.Button):
                if interaction.user.id != owner.id:
                    return await interaction.response.send_message("❌ You’re not authorized.", ephemeral=True)
                await interaction.response.send_message("❌ Denied.", ephemeral=True)

        await owner.send(embed=embed, view=ApprovalView())
        await ctx.author.send("✅ Application submitted. You'll be contacted shortly.")
    except Exception:
        await ctx.send("❌ Failed to DM you. Please open your DMs.")

import discord
from discord.ext import commands
import asyncio
from datetime import datetime

POST_CHANNEL_ID = 1103526122211262565  # Correct marketplace channel
CASH_BOT_ID = 1326838893420613652  # <<< REPLACE THIS with your real Cash Bot's user ID

@bot.command(name="postdeal")
async def post_deal(ctx):
    if not isinstance(ctx.channel, discord.TextChannel):
        await ctx.send("This command must be used inside a ticket channel.")
        return

    await ctx.send("Checking recent messages for approved Gift Card...")

    # Check last 20 messages for Cash Bot approval
    messages = [msg async for msg in ctx.channel.history(limit=20)]
    amount_found = None

    for msg in messages:
        if msg.author.id == CASH_BOT_ID:
            if msg.embeds:
                embed = msg.embeds[0]
                for field in embed.fields:
                    if "Gift Card Found" in field.value:
                        # Extract amount from embed fields
                        for sub_field in embed.fields:
                            if "Amount" in sub_field.name:
                                amount_found = sub_field.value.strip()
                                break
            if amount_found:
                break

    if not amount_found:
        await ctx.send(f"Pending Management Approval. <@480028928329777163>")
        return

    # If approved, collect additional info
    def check_author(m):
        return m.author == ctx.author and m.channel == ctx.channel

    try:
        await ctx.send("Enter the Customer Name:")
        customer = (await bot.wait_for("message", check=check_author, timeout=120)).content

        await ctx.send("Enter the Vehicle(s):")
        vehicles = (await bot.wait_for("message", check=check_author, timeout=120)).content

        await ctx.send("Enter your Current Rank:")
        rank = (await bot.wait_for("message", check=check_author, timeout=120)).content

    except asyncio.TimeoutError:
        await ctx.send("You took too long to respond. Please try again.")
        return

    # Extract Ticket Number from channel name
    ticket_number = ctx.channel.name.split("-")[-1]
    today_date = datetime.utcnow().strftime("%m/%d/%y")

    # Build the preview embed
    preview = discord.Embed(title="Deal Preview", color=0x00ff00)
    preview.add_field(name="Date", value=today_date, inline=False)
    preview.add_field(name="Customer", value=customer, inline=False)
    preview.add_field(name="Vehicles", value=vehicles, inline=False)
    preview.add_field(name="Total Price", value=amount_found, inline=False)
    preview.add_field(name="Ticket", value=ticket_number, inline=False)
    preview.add_field(name="Current Rank", value=rank, inline=False)

    view = ConfirmView(ctx.author)

    await ctx.send(embed=preview, view=view)

class ConfirmView(discord.ui.View):
    def __init__(self, author):
        super().__init__(timeout=60)
        self.author = author

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.success)
    async def approve(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user != self.author:
            await interaction.response.send_message("Only the salesman who started the post can approve it.", ephemeral=True)
            return

        post_channel = bot.get_channel(POST_CHANNEL_ID)
        if not post_channel:
            await interaction.response.send_message("Failed to find post channel.", ephemeral=True)
            return

        await post_channel.send(content=f"Approved Deal posted by {self.author.mention}:", embed=self.message.embeds[0])
        await interaction.response.send_message("Deal posted successfully.", ephemeral=True)
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.danger)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user != self.author:
            await interaction.response.send_message("Only the salesman who started the post can cancel it.", ephemeral=True)
            return
        await interaction.response.send_message("Cancelled deal posting.", ephemeral=True)
        self.stop()

# Do not forget to merge this properly under your existing bot instance and event loop.
import discord
from discord.ext import commands
import re

# --- CONFIGURATION ---
POST_CHANNEL_ID = 1103526122211262565  # Your deals channel
BOT_USER_ID = 1326838893420613652        # <<< REPLACE with your actual Cash Bot's ID

# Role to commission mapping
ROLE_COMMISSIONS = {
    "Trial Salesman": 0,
    "Novice Salesman": 10,
    "Jr. Salesman": 20,
    "Senior Salesman": 25,
    "Pro Salesman": 30,
    "Expert Salesman": 33,
}

@bot.hybrid_command(name="logcommission", description="Calculate a salesman's total deals and commission based on real roles.")
async def logcommission(ctx, member: discord.Member = None):
    if member is None:
        member = ctx.author

    post_channel = bot.get_channel(POST_CHANNEL_ID)
    if post_channel is None:
        await ctx.send("Error: Could not find the post channel.")
        return

    await ctx.send(f"Calculating commissions for {member.mention}, please wait...")

    # Fetch last 1200 messages
    messages = [msg async for msg in post_channel.history(limit=1200)]

    total_deals = 0
    total_sales = 0

    for msg in messages:
        if msg.author.id != BOT_USER_ID:
            continue  # Only Cash Bot messages
        if not msg.embeds:
            continue  # Must have an embed

        embed = msg.embeds[0]

        if embed.title != "Approved Deal":
            continue  # Only process real deal posts

        # Match based on message content mention
        if member.mention not in (msg.content or ""):
            continue

        # Extract price from embed field
        price = None
        for field in embed.fields:
            if "Total Price" in field.name:
                match = re.search(r'\$?([0-9]+)', field.value)
                if match:
                    price = int(match.group(1))
                break

        if price is not None:
            total_deals += 1
            total_sales += price

    # Determine commission rate based on user's roles
    commission_rate = 0
    user_roles = [role.name for role in member.roles]

    for role_name, rate in ROLE_COMMISSIONS.items():
        if role_name in user_roles:
            commission_rate = rate
            break

    commission_earned = int(total_sales * (commission_rate / 100))

    # Build final embed report
    embed = discord.Embed(title=f"Commission Report: {member.display_name}", color=0x00ff00)
    embed.add_field(name="Total Deals Closed", value=total_deals, inline=False)
    embed.add_field(name="Total Sales Volume", value=f"${total_sales}", inline=False)
    embed.add_field(name="Current Role", value=next((r for r in user_roles if r in ROLE_COMMISSIONS), "Unknown"), inline=False)
    embed.add_field(name="Commission Rate", value=f"{commission_rate}%", inline=False)
    embed.add_field(name="Total Commission Earned", value=f"${commission_earned}", inline=False)

    await ctx.send(embed=embed)

# --- REMEMBER ---
# Replace BOT_USER_ID with your real Cash Bot ID.
# Ensure the bot has permissions: Read Message History, Read Messages, Send Messages.

import discord
from discord.ext import commands
from datetime import datetime, timedelta

TARGET_USER_ID = 480028928329777163  # Your ID (Cash)
POST_CHANNEL_ID = 1362557854208491630  # Where to repost found messages

@bot.hybrid_command(name="searchcash", description="Pulls all messages mentioning Cash or 'cash' in last 4 days.")
async def searchcash(ctx):
    await ctx.send("Searching messages, please wait...")

    repost_channel = bot.get_channel(POST_CHANNEL_ID)
    if repost_channel is None:
        await ctx.send("Error: Could not find the repost channel.")
        return

    four_days_ago = datetime.utcnow() - timedelta(days=4)
    found_messages = []

    for channel in ctx.guild.text_channels:
        try:
            async for msg in channel.history(after=four_days_ago, limit=None):
                if msg.author.bot:
                    continue  # Ignore bot messages

                # Check if Cash is mentioned or "cash" appears in message content
                if (any(user.id == TARGET_USER_ID for user in msg.mentions)) or ("cash" in msg.content.lower()):
                    found_messages.append(msg)

                if len(found_messages) >= 75:
                    break
            if len(found_messages) >= 75:
                break
        except Exception as e:
            print(f"Failed to read {channel.name}: {e}")
            continue

    if not found_messages:
        await ctx.send("No messages mentioning you or 'cash' found in the last 4 days.")
        return

    await ctx.send(f"Found {len(found_messages)} messages. Posting them now...")

    for msg in found_messages:
        jump_link = msg.jump_url
        content_preview = msg.content if len(msg.content) < 500 else msg.content[:500] + "..."

        embed = discord.Embed(title=f"Mention by {msg.author.display_name}", description=content_preview, color=0x3498db)
        embed.add_field(name="Channel", value=msg.channel.mention, inline=True)
        embed.add_field(name="[View Message]", value=f"[Jump to Message]({jump_link})", inline=True)
        embed.set_footer(text=f"Sent at {msg.created_at.strftime('%Y-%m-%d %H:%M:%S')} UTC")

        await repost_channel.send(embed=embed)

    await ctx.send("Finished posting all found messages!")

# --- NOTES ---
# Make sure your bot has:
# - Read Message History
# - Read Messages
# - Send Messages
# - Embed Links permissions in the repost channel.


@bot.hybrid_command(name="approvepending", description="Manually approve a pending deal posting.")
async def approve_pending(ctx: commands.Context):
    # Only allow specific user to use this
    if ctx.author.id != 480028928329777163:  # YOUR USER ID
        await ctx.send("You do not have permission to approve pending deals.", ephemeral=True)
        return

    await ctx.send("Manually approving pending deal. Please provide the following:")

    def check_author(m):
        return m.author == ctx.author and m.channel == ctx.channel

    try:
        await ctx.send("Enter the Customer Name:")
        customer = (await bot.wait_for("message", check=check_author, timeout=120)).content

        await ctx.send("Enter the Vehicle(s):")
        vehicles = (await bot.wait_for("message", check=check_author, timeout=120)).content

        await ctx.send("Enter your Current Rank:")
        rank = (await bot.wait_for("message", check=check_author, timeout=120)).content

    except asyncio.TimeoutError:
        await ctx.send("You took too long to respond. Please try again.")
        return

    # Extract Ticket Number from channel name
    ticket_number = ctx.channel.name.split("-")[-1]
    today_date = datetime.utcnow().strftime("%m/%d/%y")

    # Since this is a manual approve, no auto amount from Gift Card
    await ctx.send("Enter the Total Price (e.g., $30):")
    total_price = (await bot.wait_for("message", check=check_author, timeout=120)).content

    # Build the final deal embed
    deal = discord.Embed(title="Approved Deal", color=0x00ff00)
    deal.add_field(name="Date", value=today_date, inline=False)
    deal.add_field(name="Customer", value=customer, inline=False)
    deal.add_field(name="Vehicles", value=vehicles, inline=False)
    deal.add_field(name="Total Price", value=total_price, inline=False)
    deal.add_field(name="Ticket", value=ticket_number, inline=False)
    deal.add_field(name="Current Rank", value=rank, inline=False)

    post_channel = bot.get_channel(1103526122211262565)  # Your final deals channel

    if post_channel:
        await post_channel.send(content=f"Manual Deal Approved by {ctx.author.mention}:", embed=deal)
        await ctx.send("✅ Deal posted successfully to marketplace!")
    else:
        await ctx.send("❌ Failed to find the marketplace channel. Please check channel ID.")


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


import re
import asyncio

# Track user training sessions
user_training_sessions = {}

import re
import asyncio

user_training_sessions = {}

import re
import asyncio

user_training_sessions = {}

@bot.command(name="globalunban")
@commands.is_owner()
async def global_unban(ctx, user_id: int):
    """Unban a user from ALL servers the bot is in and politely DM them."""
    results = []

    try:
        user = await bot.fetch_user(user_id)
    except Exception as e:
        await ctx.send(f"❌ Failed to fetch user: {e}")
        return

    for guild in bot.guilds:
        try:
            # Fetch bans properly
            banned_users = []
            async for ban_entry in guild.bans():
                banned_users.append(ban_entry.user)

            # Check if user is banned
            if any(bu.id == user.id for bu in banned_users):
                await guild.unban(user)
                results.append(f"✅ {guild.name}: Unbanned successfully")
            else:
                results.append(f"❌ {guild.name}: User was not banned")

        except Exception as e:
            results.append(f"⚠️ {guild.name}: Failed to unban ({e})")

    # DM user after unban
    try:
        if user:
            dm_message = (
                "👋 Hello!\n\n"
                "We wanted to kindly let you know that you have been **successfully unbanned** across our server network.\n\n"
                "We appreciate you and hope you have a great experience moving forward. "
                "Please be sure to review the server rules. Welcome back!"
            )
            await user.send(dm_message)
            results.append("📬 Professional DM sent successfully.")
        else:
            results.append("⚠️ Could not fetch user to DM.")
    except Exception as e:
        results.append(f"⚠️ Failed to send DM: {e}")

    # Send final report
    response = "\n".join(results)
    await ctx.send(f"**🌎 Global Unban Report:**\n{response}")

import discord
from discord.ext import commands
from discord import app_commands
import asyncio
from datetime import datetime, timedelta

# CONFIG
OWNER_ID = 480028928329777163  # Your Discord user ID
SALES_CHANNEL_ID = 1103526122211262565  # Your sales post channel
TICKET_CATEGORY_ID = 123456789012345678  # Your ticket category (update with real one)
POST_CHANNEL_ID = 1103526122211262565  # Deals channel for counting
ROLE_REQUEST_CHANNEL_ID = 1362826410133295326  # Example role request channel
MENTION_TARGET_ID = 480028928329777163  # You (Cash)

class DashboardView(discord.ui.View):
    def __init__(self, embeds):
        super().__init__(timeout=300)
        self.embeds = embeds
        self.index = 0

    @discord.ui.button(label="⬅️ Back", style=discord.ButtonStyle.secondary)
    async def back(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != OWNER_ID:
            await interaction.response.send_message("You can't control this.", ephemeral=True)
            return
        self.index = (self.index - 1) % len(self.embeds)
        await interaction.response.edit_message(embed=self.embeds[self.index], view=self)

    @discord.ui.button(label="➡️ Next", style=discord.ButtonStyle.secondary)
    async def next(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != OWNER_ID:
            await interaction.response.send_message("You can't control this.", ephemeral=True)
            return
        self.index = (self.index + 1) % len(self.embeds)
        await interaction.response.edit_message(embed=self.embeds[self.index], view=self)

    @discord.ui.button(label="Panic Lock Server", style=discord.ButtonStyle.danger)
    async def panic(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != OWNER_ID:
            await interaction.response.send_message("You can't control this.", ephemeral=True)
            return
        await interaction.response.send_message("\u26a0\ufe0f Panic Lock Triggered! (Placeholder action)", ephemeral=True)

@bot.command(name="operationsdashboard")
async def operationsdashboard(ctx):
    if ctx.author.id != OWNER_ID:
        await ctx.send("You do not have permission to run this.")
        return

    await ctx.send("\u23f3 Gathering full operational data... Please wait...")

    sales_channel = bot.get_channel(SALES_CHANNEL_ID)
    post_channel = bot.get_channel(POST_CHANNEL_ID)

    now = datetime.utcnow()
    yesterday = now - timedelta(days=1)
    week = now - timedelta(days=7)

    # --- SALES DATA ---
    last_24h_sales = 0
    last_7d_sales = 0
    deal_count_24h = 0
    deal_count_7d = 0

    if post_channel:
        async for msg in post_channel.history(after=week, limit=1200):
            if msg.author.bot and msg.embeds:
                embed = msg.embeds[0]
                for field in embed.fields:
                    if "Total Price" in field.name:
                        try:
                            amount = int(field.value.replace("$", "").strip())
                            if msg.created_at > yesterday:
                                last_24h_sales += amount
                                deal_count_24h += 1
                            last_7d_sales += amount
                            deal_count_7d += 1
                        except:
                            continue

    # --- TICKET DATA ---
    active_tickets = 0
    stuck_tickets = 0
    try:
        ticket_category = discord.utils.get(ctx.guild.categories, id=TICKET_CATEGORY_ID)
        if ticket_category:
            for channel in ticket_category.channels:
                if isinstance(channel, discord.TextChannel):
                    active_tickets += 1
    except:
        pass

    # --- MENTION DATA ---
    mention_count = 0
    for channel in ctx.guild.text_channels:
        try:
            async for msg in channel.history(after=yesterday, limit=300):
                if any(user.id == MENTION_TARGET_ID for user in msg.mentions):
                    mention_count += 1
        except:
            continue

    # --- STAFF ONLINE ---
    staff_online = sum(1 for m in ctx.guild.members if any(r.permissions.kick_members for r in m.roles) and m.status != discord.Status.offline)

    # --- BOT PING ---
    ping_ms = round(bot.latency * 1000)

    # --- EMBEDS ---
    page1 = discord.Embed(title="\ud83d\udcc8 Sales & Ticket Overview", color=0x00ff99)
    page1.add_field(name="Sales Last 24h", value=f"${last_24h_sales}", inline=True)
    page1.add_field(name="Sales Last 7d", value=f"${last_7d_sales}", inline=True)
    page1.add_field(name="Deals 24h", value=f"{deal_count_24h}", inline=True)
    page1.add_field(name="Deals 7d", value=f"{deal_count_7d}", inline=True)
    page1.add_field(name="Active Tickets", value=f"{active_tickets}", inline=True)
    page1.set_footer(text=f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    page2 = discord.Embed(title="\ud83d\udc68\u200d\ud83d\udcbc Staff, Roles & Fraud", color=0x3498db)
    page2.add_field(name="Staff Online", value=f"{staff_online}", inline=True)
    page2.add_field(name="Pending Role Requests", value=f"(Coming soon)", inline=True)
    page2.add_field(name="Recent Fraud Flags", value=f"(Coming soon)", inline=True)

    page3 = discord.Embed(title="\ud83d\udcca Community Growth Tracker", color=0x9b59b6)
    page3.add_field(name="Mentions of Cash (24h)", value=f"{mention_count}", inline=True)
    page3.add_field(name="New Members 24h", value=f"(Coming soon)", inline=True)
    page3.add_field(name="Top Invite Booster", value=f"(Coming soon)", inline=True)

    page4 = discord.Embed(title="\ud83d\udcca Bot Health and Emergency", color=0xe67e22)
    page4.add_field(name="Bot Uptime (Ping)", value=f"{ping_ms}ms", inline=True)
    page4.add_field(name="Emergency Lock", value=f"Use Panic Button \ud83d\uded1", inline=True)

    embeds = [page1, page2, page3, page4]

    await ctx.send(embed=page1, view=DashboardView(embeds))

# --- END OF FILE ---

# Notes:
# - Replace TICKET_CATEGORY_ID with your real ticket category ID
# - Replace channels if needed for deal logging
# - This is v1.0, will upgrade "coming soon" stats next!


@bot.command(name="leaveserver")
@commands.is_owner()
async def leave_server_by_id(ctx, server_id: int):
    """Owner-only command: bot leaves a server by its ID."""
    guild = discord.utils.get(bot.guilds, id=server_id)

    if not guild:
        return await ctx.send("❌ The bot is not currently in that server or the ID is invalid.")

    await ctx.send(f"⚠️ Are you sure you want me to leave **{guild.name}** (`{server_id}`)?\n"
                   f"Type `confirm {server_id}` within 15 seconds to confirm.")

    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel and m.content.lower() == f"confirm {server_id}"

    try:
        await bot.wait_for("message", timeout=15.0, check=check)
        await ctx.send(f"👋 Leaving server: **{guild.name}**")
        await guild.leave()
    except asyncio.TimeoutError:
        await ctx.send("⏰ Cancelled. No confirmation received.")
    except discord.HTTPException as e:
        await ctx.send(f"❌ Failed to leave the server: {e}")

@bot.command(name="commandusage")
@commands.is_owner()
async def command_usage(ctx):
    """Show command usage stats across all servers for the last 5 days."""
    now = datetime.utcnow()
    five_days_ago = now - timedelta(days=5)

    usage_counter = {}
    for timestamp, guild_id, command_name in command_usage_logs:
        if timestamp >= five_days_ago:
            usage_counter[command_name] = usage_counter.get(command_name, 0) + 1

    if not usage_counter:
        await ctx.send("No command usage recorded in the last 5 days.")
        return

    sorted_usage = sorted(usage_counter.items(), key=lambda x: x[1], reverse=True)

    embed = discord.Embed(
        title="📊 Command Usage (Last 5 Days)",
        color=discord.Color.blue(),
        timestamp=datetime.utcnow()
    )

    for cmd_name, count in sorted_usage:
        embed.add_field(name=f"!{cmd_name}", value=f"Used {count} times", inline=False)

    await ctx.send(embed=embed)


@bot.command(name="train")
async def start_training(ctx):
    """Walks a Trial Salesman through onboarding with test validation and auto-role."""
    user_id = ctx.author.id

    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel

    async def wait_for_input(prompt, validator, fail_msg, step_key):
        user_training_sessions[user_id] = step_key
        await ctx.send(prompt)
        try:
            while True:
                msg = await bot.wait_for("message", timeout=60.0, check=check)
                content = msg.content.strip().lower()

                if content == "!trainskip":
                    await ctx.send("⏭️ Skipped this step. Moving on.")
                    return "skipped"

                if validator(content):
                    return "passed"
                else:
                    await ctx.send(fail_msg)
        except asyncio.TimeoutError:
            await ctx.send("⏰ Time’s up! Training canceled.")
            return "timeout"
        finally:
            user_training_sessions.pop(user_id, None)

    await ctx.send(f"📚 **Welcome to Training, {ctx.author.mention}!**\n"
                   "Let’s go over the basics. You can type `!trainskip` at any time to move ahead.")

    # Step 1: Explain and test !checkticket
    await asyncio.sleep(1)
    await ctx.send("🔹 **Step 1: `!checkticket` Command**\n"
                   "This is how you report a gift card. Example: `!checkticket 200`")

    result = await wait_for_input(
        prompt="🧪 Type how you would run the `!checkticket` command for a 200 card:",
        validator=lambda x: x.startswith("!checkticket") and re.search(r"\d+", x),
        fail_msg="❌ Try again — it should look like `!checkticket 200`",
        step_key="checkticket"
    )
    if result == "timeout":
        return

    # Step 2: Trigger word test
    await asyncio.sleep(1)
    await ctx.send("🔹 **Step 2: Trigger Words**\n"
                   "Use keywords like `customer:` to log deals.\n"
                   "_Example: `customer: John - 200`_")

    result = await wait_for_input(
        prompt="🧪 Send a message starting with `customer:` and include a name and value.",
        validator=lambda x: x.startswith("customer:") and re.search(r"\d+", x),
        fail_msg="❌ Try again. Make sure your message starts with `customer:` and has a number.",
        step_key="triggerword"
    )
    if result == "timeout":
        return

    # Auto-role grant
    trial_role = discord.utils.get(ctx.guild.roles, name="Trial Salesman")
    if trial_role:
        await ctx.author.add_roles(trial_role)
        await ctx.send(f"🧢 You’ve been given the **Trial Salesman** role.")
    else:
        await ctx.send("⚠️ Could not find the `Trial Salesman` role. Please tell a trainer.")

    # Done!
    await asyncio.sleep(1)
    await ctx.send(f"🎉 **Training complete!**\n"
                   "You’re now ready to move to VC, pick your cars, and get set up.\n"
                   "Let your trainer know you're finished.")

@bot.command(name="trainskip")
async def skip_training(ctx):
    """Skip current training step if in session."""
    if ctx.author.id not in user_training_sessions:
        await ctx.send("❌ You're not in an active training session.")
        return
    await ctx.send("⏭️ Step will be skipped on your next message.")





@bot.command(name="profile")
async def rep_profile(ctx, user: discord.Member = None):
    user = user or ctx.author
    channel = bot.get_channel(1103526122211262565)  # sales log channel
    if not channel:
        return await ctx.send("❌ Sales log channel not found.")

    total_sales = 0
    sales_count = 0
    last_payout = None

    async for message in channel.history(limit=1000):
        if message.author == user and "customer:" in message.content.lower():
            match = re.search(r'\$(\d+(?:\.\d{2})?)', message.content)
            if match:
                amount = float(match.group(1))
                total_sales += amount
                sales_count += 1
                if not last_payout or message.created_at > last_payout:
                    last_payout = message.created_at

    avg_sale = total_sales / sales_count if sales_count else 0
    credit_balance = credits.get(str(user.id), 0.0)

    embed = discord.Embed(
        title=f"💼 Rep Profile: {user.display_name}",
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    embed.set_thumbnail(url=user.display_avatar.url)
    embed.add_field(name="Total Sales", value=f"${total_sales:.2f}", inline=True)
    embed.add_field(name="Sales Count", value=str(sales_count), inline=True)
    embed.add_field(name="Average Sale", value=f"${avg_sale:.2f}", inline=True)
    embed.add_field(name="Credit Balance", value=f"${credit_balance:.2f}", inline=True)
    if last_payout:
        embed.add_field(name="Last Sale", value=last_payout.strftime('%Y-%m-%d %I:%M %p'), inline=False)
    else:
        embed.add_field(name="Last Sale", value="No sales found.", inline=False)

    await ctx.send(embed=embed)


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
from discord.ui import Button, View

@bot.command(name="serverdashboard")
@commands.has_permissions(administrator=True)
async def server_dashboard(ctx):
    """Show server stats in a clean dashboard."""
    guild_id = ctx.guild.id

    stats = server_stats.get(guild_id)
    if not stats:
        await ctx.send("❌ No stats available yet for this server.")
        return

    embed = discord.Embed(
        title=f"📊 Server Dashboard for {ctx.guild.name}",
        color=discord.Color.green(),
        timestamp=datetime.utcnow()
    )

    embed.add_field(name="Total Sales", value=f"🛒 {stats['sales']}", inline=True)
    embed.add_field(name="Total Fraud Alerts", value=f"🚨 {stats['frauds']}", inline=True)
    embed.add_field(name="Tickets Opened", value=f"🎟️ {stats['tickets']}", inline=True)
    embed.add_field(name="Users Joined", value=f"👥 {stats['joins']}", inline=True)
    embed.add_field(name="Commands Used (Last 5 Days)", value=f"⌨️ {stats['commands_used']}", inline=True)

    await ctx.send(embed=embed)



# --- CONFIG ---
OWNER_IDS = [480028928329777163]  # <- YOUR Discord User ID goes here
AUDIT_LOG_FILE = "auditlog.jsonl"

# --- Helper to save to audit log ---
def save_audit_log(event_type, user_id, details):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": event_type,
        "user_id": str(user_id),
        "details": details
    }
    with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

# --- The actual Owner Panel command ---
@commands.command(name="ownerpanel")
async def owner_panel(ctx):
    if ctx.author.id not in OWNER_IDS:
        await ctx.send("❌ You do not have permission to access the Owner Command Center.", delete_after=5)
        return

    view = View(timeout=300)  # 5 minutes timeout

    embed = discord.Embed(
        title="🏛️ Owner Command Center",
        description="Choose your action below:",
        color=discord.Color.gold(),
        timestamp=datetime.utcnow()
    )

    # --- Button: Global Ban ---
    async def global_ban_callback(interaction):
        await interaction.response.send_message("Please provide the User ID to globally ban:", ephemeral=True)
        msg = await bot.wait_for("message", check=lambda m: m.author.id == ctx.author.id, timeout=60)
        target_id = int(msg.content.strip("<@!>"))

        confirm_embed = discord.Embed(title="⚠️ Confirm Global Ban", description=f"Ban <@{target_id}> globally?", color=discord.Color.red())
        confirm_view = View()

        async def confirm_ban_callback(confirm_interaction):
            for guild in bot.guilds:
                try:
                    user = await bot.fetch_user(target_id)
                    await guild.ban(user, reason="Global ban via Owner Panel")
                except Exception:
                    pass
            try:
                user = await bot.fetch_user(target_id)
                await user.send("🚫 You have been globally banned by server administration.")
            except:
                pass
            save_audit_log("global_ban", target_id, f"Globally banned by {ctx.author}")
            await confirm_interaction.response.send_message(f"✅ User <@{target_id}> globally banned.", ephemeral=True)

        async def cancel_callback(confirm_interaction):
            await confirm_interaction.response.send_message("❌ Cancelled.", ephemeral=True)

        confirm_view.add_item(Button(label="✅ Confirm", style=discord.ButtonStyle.danger, custom_id="confirm_ban"))
        confirm_view.add_item(Button(label="❌ Cancel", style=discord.ButtonStyle.secondary, custom_id="cancel_ban"))

        confirm_view.children[0].callback = confirm_ban_callback
        confirm_view.children[1].callback = cancel_callback

        await ctx.author.send(embed=confirm_embed, view=confirm_view)

    # --- Button: View User History ---
    async def view_history_callback(interaction):
        await interaction.response.send_message("Provide User ID to view history:", ephemeral=True)
        msg = await bot.wait_for("message", check=lambda m: m.author.id == ctx.author.id, timeout=60)
        target_id = msg.content.strip("<@!>")

        embed_history = discord.Embed(title=f"📜 User History: {target_id}", color=discord.Color.blue())

        try:
            with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            user_entries = [json.loads(l) for l in lines if json.loads(l)["user_id"] == target_id]

            if not user_entries:
                embed_history.description = "No records found."
            else:
                for entry in user_entries[-10:]:  # Show last 10 actions
                    embed_history.add_field(name=entry["timestamp"], value=f"{entry['type']} - {entry['details']}", inline=False)
        except:
            embed_history.description = "No audit log found."

        await ctx.author.send(embed=embed_history)

    # --- Button: Emergency Lockdown ---
    async def lockdown_callback(interaction):
        await interaction.response.send_message("⚠️ Confirm Emergency Lockdown?", ephemeral=True)
        confirm_view = View()

        async def confirm_lockdown_callback(confirm_interaction):
            # Example lockdown: disable posting, mute sellers
            for guild in bot.guilds:
                for channel in guild.text_channels:
                    try:
                        await channel.set_permissions(guild.default_role, send_messages=False)
                    except:
                        pass
            save_audit_log("lockdown", ctx.guild.id, "Emergency Lockdown triggered")
            await confirm_interaction.response.send_message("🚨 Emergency Lockdown Activated.", ephemeral=True)

        async def cancel_lockdown_callback(confirm_interaction):
            await confirm_interaction.response.send_message("❌ Lockdown Cancelled.", ephemeral=True)

        confirm_view.add_item(Button(label="✅ Confirm Lockdown", style=discord.ButtonStyle.danger))
        confirm_view.add_item(Button(label="❌ Cancel", style=discord.ButtonStyle.secondary))

        confirm_view.children[0].callback = confirm_lockdown_callback
        confirm_view.children[1].callback = cancel_lockdown_callback

        await ctx.author.send(view=confirm_view)

    # --- Button: Investigation ---
    async def investigation_callback(interaction):
        await interaction.response.send_message("Provide User ID to investigate:", ephemeral=True)
        msg = await bot.wait_for("message", check=lambda m: m.author.id == ctx.author.id, timeout=60)
        target_id = int(msg.content.strip("<@!>"))

        try:
            user = await bot.fetch_user(target_id)
            await user.send("🔎 You are under investigation by server security staff. Please operate professionally.")
        except:
            pass

        save_audit_log("investigation", target_id, f"Investigation opened by {ctx.author}")
        await ctx.author.send(f"✅ Investigation opened on <@{target_id}>.")

    # --- Buttons ---
    ban_button = Button(label="🚫 Ban User Globally", style=discord.ButtonStyle.danger)
    history_button = Button(label="📜 View User History", style=discord.ButtonStyle.primary)
    lockdown_button = Button(label="🚨 Emergency Lockdown", style=discord.ButtonStyle.danger)
    investigate_button = Button(label="🔍 Investigate User", style=discord.ButtonStyle.secondary)

    ban_button.callback = global_ban_callback
    history_button.callback = view_history_callback
    lockdown_button.callback = lockdown_callback
    investigate_button.callback = investigation_callback

    view.add_item(ban_button)
    view.add_item(history_button)
    view.add_item(lockdown_button)
    view.add_item(investigate_button)

    await ctx.author.send(embed=embed, view=view)

# --- ADD THE COMMAND ---
bot.add_command(owner_panel)




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
@bot.command(name="blacklistban")
@commands.is_owner()
async def blacklist_ban(ctx, user_id: int):
    """Ban a user from all servers the bot is in, except PSRP Dev."""
    PSRP_DEV_SERVER_ID = 913635757401448448  # Replace with your dev server ID

    try:
        user = await bot.fetch_user(user_id)
        if not user:
            await ctx.send("❌ Could not fetch that user.")
            return

        success = 0
        failed = []

        for guild in bot.guilds:
            if guild.id == PSRP_DEV_SERVER_ID:
                continue  # ❌ Skip PSRP Dev server

            try:
                await guild.ban(user, reason=f"Blacklisted by {ctx.author}", delete_message_days=0)
                success += 1
            except discord.Forbidden:
                failed.append(guild.name)
            except Exception as e:
                failed.append(f"{guild.name} ({str(e)})")

        embed = discord.Embed(
            title="🚫 Global Ban Executed",
            color=discord.Color.red(),
            description=f"User {user} (`{user.id}`) has been banned from {success} server(s)."
        )

        if failed:
            embed.add_field(
                name="❌ Failed Servers",
                value="\n".join(failed),
                inline=False
            )

        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")
@bot.command(name='giftcardtotal')
@commands.cooldown(1, 300, commands.BucketType.user)
@commands.is_owner()
async def giftcard_total(ctx):
    """Scans inbox for gift card totals and usage info (owner only)."""
    try:
        now = time.time()
        CACHE_TTL = 300  # 5 minutes

        # Use cache if fresh
        if now - giftcard_cache["last_updated"] < CACHE_TTL:
            embed = discord.Embed(
                title="💳 Gift Card Summary (Cached)",
                description="Results from previous scan (within 5 minutes)",
                color=discord.Color.teal(),
                timestamp=datetime.now()
            )
            embed.add_field(name="Total Detected", value=f"${giftcard_cache['value']:.2f}", inline=True)
            embed.add_field(name="Used Value", value=f"${giftcard_cache['used']:.2f}", inline=True)
            embed.add_field(name="Available", value=f"${giftcard_cache['unused']:.2f}", inline=True)
            embed.add_field(name="Codes Found", value=str(giftcard_cache['codes']), inline=True)
            return await ctx.send(embed=embed)

        loading_msg = await ctx.send("🔄 Scanning inbox for gift cards... Please wait.")

        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        EMAIL = os.getenv('GMAIL_EMAIL')
        PASSWORD = os.getenv('GMAIL_PASSWORD')
        imap.login(EMAIL, PASSWORD)
        imap.select("inbox")

        _, messages = imap.search(None, 'ALL')
        email_ids = messages[0].split()[-1000:]  # Last 1000 emails only

        used_codes = load_used_codes()

        total_value = 0.0
        used_value = 0.0
        unused_value = 0.0
        code_count = 0

        for email_id in reversed(email_ids):
            _, msg = imap.fetch(email_id, '(RFC822)')
            raw = msg[0][1]
            email_message = email.message_from_bytes(raw)

            # Extract body
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

            # Patterns
            amount_pattern = r'\$\s*(\d+(?:\.\d{2})?)\s*(?:USD)?'
            code_pattern = r'(?:code|number|card)[^\d]*(\d{13,19})'

            amounts = re.findall(amount_pattern, body, re.IGNORECASE)
            codes = [m.group(1) for m in re.finditer(code_pattern, body, re.IGNORECASE)]

            if amounts and codes:
                for amount_str, code in zip(amounts, codes):
                    try:
                        amount = float(amount_str)
                        code_count += 1
                        total_value += amount
                        if code in used_codes:
                            used_value += amount
                        else:
                            unused_value += amount
                    except:
                        continue

        imap.close()
        imap.logout()

        # Cache results
        giftcard_cache.update({
            "value": total_value,
            "used": used_value,
            "unused": unused_value,
            "codes": code_count,
            "last_updated": now
        })

        embed = discord.Embed(
            title="💳 Gift Card Summary",
            description="Latest scan of inbox (last 1,000 emails)",
            color=discord.Color.green(),
            timestamp=datetime.now()
        )
        embed.add_field(name="Total Detected", value=f"${total_value:.2f}", inline=True)
        embed.add_field(name="Used Value", value=f"${used_value:.2f}", inline=True)
        embed.add_field(name="Available", value=f"${unused_value:.2f}", inline=True)
        embed.add_field(name="Codes Found", value=str(code_count), inline=True)

        await loading_msg.edit(content=None, embed=embed)

    except Exception as e:
        logging.error(f"GiftCardTotal Error: {str(e)}")
        await ctx.send("❌ Error while scanning gift card total.")



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
        return  # 🔇 Silently ignore unknown commands
    elif isinstance(error, commands.MissingPermissions):
        await ctx.send("⛔ Insufficient permissions")
    else:
        await ctx.send(f"⚠️ Error: {str(error)}")


    update_channel = bot.get_channel(1361849234550165618)
    if update_channel:
        await update_channel.send("🔄 **Bot restarted. Possible update pushed.**")

    # Optional: Track code line count
    try:
        current_file = os.path.abspath(__file__)
        with open(current_file, 'r') as f:
            current_lines = len(f.readlines())

        previous_file = "last_code_linecount.txt"
        previous_lines = 0

        try:
            with open(previous_file, "r") as p:
                previous_lines = int(p.read())
        except FileNotFoundError:
            pass

        if current_lines > previous_lines:
            await update_channel.send(f"🆕 **Update Detected:** `{current_lines - previous_lines}` new lines added to the bot.")
        elif current_lines < previous_lines:
            await update_channel.send(f"⚠️ **Codebase Shrunk:** `{previous_lines - current_lines}` lines removed.")

        with open(previous_file, "w") as w:
            w.write(str(current_lines))

    except Exception as e:
        print(f"[Update Tracker] Failed: {e}")

# Launch Flask + bot
if __name__ == '__main__':
    try:
        from flask_app import run_flask  # make sure your run_flask() is defined in flask_app or same file

        flask_thread = threading.Thread(target=run_flask, daemon=True)
        flask_thread.start()

        token = os.getenv("DISCORD_TOKEN")
        if not token:
            raise RuntimeError("DISCORD_TOKEN environment variable not set.")
        bot.run(token)

    except Exception as e:
        print(f"❌ Error starting bot: {e}")

        
        # Run Discord bot
        bot.run(DISCORD_TOKEN)
    except KeyboardInterrupt:
        logging.info("Shutting down bot...")
    except Exception as e:
        logging.error(f"Main thread error: {e}")
        logging.error(f"Main thread error: {e}")
        logging.error(f"Main thread error: {e}")
