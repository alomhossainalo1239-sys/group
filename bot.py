"""
Group Maintenance / Moderation Bot -- single-file build.

Run with:  python bot.py
Requires:  BOT_TOKEN and SECRET_KEY environment variables (see bottom of
           this file / README notes in the project chat for how to set
           these up). A .env file next to this script is loaded automatically.

Everything (config, database, security, permission checks, and all
handlers) lives in this one file by request. For anything beyond quick
personal use, splitting this back into modules is recommended -- but
functionally this file is complete and production-capable as-is.
"""
import hashlib
import hmac
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, fields

from dotenv import load_dotenv
from telegram import (
    ChatMember,
    ChatPermissions,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.constants import ChatMemberStatus, ChatType, MessageEntityType, ParseMode
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# =============================================================================
# CONFIG
# =============================================================================
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
DATABASE_PATH = os.getenv("DATABASE_PATH", "bot.db")
SECRET_KEY = os.getenv("SECRET_KEY", "")

WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
WEBHOOK_LISTEN = os.getenv("WEBHOOK_LISTEN", "0.0.0.0")
WEBHOOK_PORT = int(os.getenv("WEBHOOK_PORT", "8443"))
WEBHOOK_SECRET_TOKEN = os.getenv("WEBHOOK_SECRET_TOKEN", "") or SECRET_KEY

_SETUP_HINT = (
    "Generate one with:\n"
    "  python -c \"import secrets; print(secrets.token_hex(32))\"\n"
    "then put it in your .env file (never commit .env to git)."
)

if not BOT_TOKEN:
    raise RuntimeError(
        "BOT_TOKEN is not set. Create a .env file with BOT_TOKEN=... from @BotFather."
    )
if not SECRET_KEY:
    raise RuntimeError(f"SECRET_KEY is not set. {_SETUP_HINT}")
if len(SECRET_KEY) < 32:
    raise RuntimeError(f"SECRET_KEY is too short/weak ({len(SECRET_KEY)} chars). {_SETUP_HINT}")
if WEBHOOK_URL and not WEBHOOK_SECRET_TOKEN:
    raise RuntimeError(
        "WEBHOOK_URL is set but no WEBHOOK_SECRET_TOKEN/SECRET_KEY is available to "
        "verify incoming requests. Refusing to start an unverified webhook."
    )

# NOTE: Telegram's Bot API has no real button "color" field (that's a
# Discord concept). This emoji prefix is the closest honest equivalent to a
# style picker for InlineKeyboardButton, which has no styling options at all.
BUTTON_STYLES = {"primary": "🔵", "success": "🟢", "danger": "🔴"}
DEFAULT_BUTTON_STYLE = "primary"
STYLE_ORDER = ["primary", "success", "danger"]

logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("mod_bot")


# =============================================================================
# SECURITY -- HMAC-signed, expiring tokens for the DM settings deep link
# =============================================================================
DEFAULT_TTL_SECONDS = 15 * 60  # 15 minutes
_SIG_LENGTH = 16


def _sign(payload: str) -> str:
    return hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:_SIG_LENGTH]


def sign_chat_token(chat_id: int, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    expiry = int(time.time()) + ttl_seconds
    payload = f"{chat_id}_{expiry}"
    token = f"{payload}_{_sign(payload)}"
    if len(token) > 64:
        raise ValueError(f"Signed token exceeds Telegram's 64-char payload limit: {len(token)}")
    return token


def verify_chat_token(token: str) -> int | None:
    parts = token.split("_")
    if len(parts) != 3:
        return None
    chat_id_str, expiry_str, sig = parts
    try:
        chat_id = int(chat_id_str)
        expiry = int(expiry_str)
    except ValueError:
        return None
    if not hmac.compare_digest(sig, _sign(f"{chat_id_str}_{expiry_str}")):
        logger.warning("Rejected settings deep-link token with invalid signature.")
        return None
    if time.time() > expiry:
        logger.info("Rejected expired settings deep-link token for chat_id=%s", chat_id)
        return None
    return chat_id


# =============================================================================
# DATABASE -- per-group settings, one row per chat_id
# =============================================================================
_db_lock = threading.Lock()

DEFAULT_WELCOME_MESSAGE = (
    "👋 Welcome {mention} to *{chat_title}*!\n\n"
    "Please read the group rules and enjoy your stay."
)


@dataclass
class GroupSettings:
    chat_id: int
    welcome_message: str = DEFAULT_WELCOME_MESSAGE
    welcome_enabled: int = 1

    button1_name: str = "Rules"
    button1_url: str = "https://telegram.org"
    button1_style: str = DEFAULT_BUTTON_STYLE

    button2_name: str = "Support"
    button2_url: str = "https://telegram.org"
    button2_style: str = DEFAULT_BUTTON_STYLE

    button3_name: str = "Website"
    button3_url: str = "https://telegram.org"
    button3_style: str = DEFAULT_BUTTON_STYLE

    antilink_enabled: int = 1
    automute_on_link_button: int = 1

    def as_dict(self):
        return {f.name: getattr(self, f.name) for f in fields(self)}


class Database:
    def __init__(self, path: str = DATABASE_PATH):
        self.path = path
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        with _db_lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS group_settings (
                    chat_id INTEGER PRIMARY KEY,
                    welcome_message TEXT NOT NULL,
                    welcome_enabled INTEGER NOT NULL DEFAULT 1,
                    button1_name TEXT NOT NULL,
                    button1_url TEXT NOT NULL,
                    button1_style TEXT NOT NULL,
                    button2_name TEXT NOT NULL,
                    button2_url TEXT NOT NULL,
                    button2_style TEXT NOT NULL,
                    button3_name TEXT NOT NULL,
                    button3_url TEXT NOT NULL,
                    button3_style TEXT NOT NULL,
                    antilink_enabled INTEGER NOT NULL DEFAULT 1,
                    automute_on_link_button INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_joins (
                    chat_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    update_id INTEGER NOT NULL,
                    PRIMARY KEY (chat_id, user_id, update_id)
                )
                """
            )

    def get_settings(self, chat_id: int) -> GroupSettings:
        with _db_lock:
            row = self._conn.execute(
                "SELECT * FROM group_settings WHERE chat_id = ?", (chat_id,)
            ).fetchone()
            if row is not None:
                return GroupSettings(**dict(row))

            defaults = GroupSettings(chat_id=chat_id)
            cols = ", ".join(defaults.as_dict().keys())
            placeholders = ", ".join("?" for _ in defaults.as_dict())
            with self._conn:
                self._conn.execute(
                    f"INSERT INTO group_settings ({cols}) VALUES ({placeholders})",
                    tuple(defaults.as_dict().values()),
                )
            logger.info("Created default settings for chat_id=%s", chat_id)
            return defaults

    def update_field(self, chat_id: int, field: str, value) -> None:
        allowed_fields = {f.name for f in fields(GroupSettings)} - {"chat_id"}
        if field not in allowed_fields:
            raise ValueError(f"Refusing to update unknown/unsafe field: {field}")
        self.get_settings(chat_id)  # ensure row exists
        with _db_lock, self._conn:
            self._conn.execute(
                f"UPDATE group_settings SET {field} = ? WHERE chat_id = ?", (value, chat_id)
            )

    def set_button(self, chat_id: int, index: int, *, name=None, url=None, style=None):
        if index not in (1, 2, 3):
            raise ValueError("Button index must be 1, 2, or 3")
        if name is not None:
            self.update_field(chat_id, f"button{index}_name", name)
        if url is not None:
            self.update_field(chat_id, f"button{index}_url", url)
        if style is not None:
            self.update_field(chat_id, f"button{index}_style", style)

    def toggle_antilink(self, chat_id: int) -> bool:
        new_val = 0 if self.get_settings(chat_id).antilink_enabled else 1
        self.update_field(chat_id, "antilink_enabled", new_val)
        return bool(new_val)

    def toggle_automute(self, chat_id: int) -> bool:
        new_val = 0 if self.get_settings(chat_id).automute_on_link_button else 1
        self.update_field(chat_id, "automute_on_link_button", new_val)
        return bool(new_val)

    def toggle_welcome(self, chat_id: int) -> bool:
        new_val = 0 if self.get_settings(chat_id).welcome_enabled else 1
        self.update_field(chat_id, "welcome_enabled", new_val)
        return bool(new_val)

    def mark_join_processed(self, chat_id: int, user_id: int, update_id: int) -> bool:
        """True if this is a NEW join event (send welcome); False if a
        duplicate delivery of an already-handled join (skip it)."""
        with _db_lock, self._conn:
            try:
                self._conn.execute(
                    "INSERT INTO processed_joins (chat_id, user_id, update_id) VALUES (?, ?, ?)",
                    (chat_id, user_id, update_id),
                )
                return True
            except sqlite3.IntegrityError:
                return False


db = Database()


# =============================================================================
# PERMISSIONS -- issuer-is-admin checks & bot-has-permission checks
# =============================================================================
ADMIN_STATUSES = (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER)

FRIENDLY_PERMISSION_NAMES = {
    "can_restrict_members": "Ban/Restrict Users",
    "can_delete_messages": "Delete Messages",
    "can_change_info": "Change Group Info (needed for lock/unlock)",
    "can_invite_users": "Invite Users",
}


async def is_user_admin(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
        return member.status in ADMIN_STATUSES
    except TelegramError as e:
        logger.warning("is_user_admin lookup failed for chat=%s user=%s: %s", chat_id, user_id, e)
        return False


async def get_bot_member(chat_id: int, context: ContextTypes.DEFAULT_TYPE) -> ChatMember | None:
    try:
        return await context.bot.get_chat_member(chat_id, context.bot.id)
    except TelegramError as e:
        logger.error("Could not fetch bot's own membership in chat=%s: %s", chat_id, e)
        return None


async def get_bot_permission_gaps(chat_id: int, context: ContextTypes.DEFAULT_TYPE,
                                   needed: list[str]) -> list[str]:
    bot_member = await get_bot_member(chat_id, context)
    if bot_member is None:
        return needed
    if bot_member.status != ChatMemberStatus.ADMINISTRATOR:
        return needed
    return [p for p in needed if not getattr(bot_member, p, False)]


def describe_missing(missing: list[str]) -> str:
    return ", ".join(FRIENDLY_PERMISSION_NAMES.get(p, p) for p in missing)


async def resolve_target_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Reply-based target resolution (Telegram can't reliably resolve an
    arbitrary @username to a user_id unless they're already cached)."""
    message = update.effective_message
    if message.reply_to_message and message.reply_to_message.from_user:
        return message.reply_to_message.from_user
    if message.entities:
        for entity in message.entities:
            if entity.type == "text_mention" and entity.user:
                return entity.user
    return None


# =============================================================================
# MODERATION PERMISSIONS PRESETS
# =============================================================================
LOCKED_PERMISSIONS = ChatPermissions(
    can_send_messages=False, can_send_audios=False, can_send_documents=False,
    can_send_photos=False, can_send_videos=False, can_send_video_notes=False,
    can_send_voice_notes=False, can_send_polls=False, can_send_other_messages=False,
    can_add_web_page_previews=False,
)
UNLOCKED_PERMISSIONS = ChatPermissions(
    can_send_messages=True, can_send_audios=True, can_send_documents=True,
    can_send_photos=True, can_send_videos=True, can_send_video_notes=True,
    can_send_voice_notes=True, can_send_polls=True, can_send_other_messages=True,
    can_add_web_page_previews=True,
)
MUTED_PERMISSIONS = ChatPermissions(
    can_send_messages=False, can_send_audios=False, can_send_documents=False,
    can_send_photos=False, can_send_videos=False, can_send_video_notes=False,
    can_send_voice_notes=False, can_send_polls=False, can_send_other_messages=False,
    can_add_web_page_previews=False,
)


async def _group_only(update: Update) -> bool:
    if update.effective_chat.type == ChatType.PRIVATE:
        await update.effective_message.reply_text(
            "This command only works inside a group, not in a private chat with me."
        )
        return False
    return True


async def _require_issuer_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not await is_user_admin(update.effective_chat.id, update.effective_user.id, context):
        await update.effective_message.reply_text("🚫 Only group admins can use this command.")
        return False
    return True


async def _require_bot_permission(update: Update, context: ContextTypes.DEFAULT_TYPE,
                                   needed: list[str]) -> bool:
    missing = await get_bot_permission_gaps(update.effective_chat.id, context, needed)
    if missing:
        await update.effective_message.reply_text(
            f"⚠️ I'm missing a required permission to do that: {describe_missing(missing)}.\n\n"
            "Please make me an admin with that permission and try again."
        )
        return False
    return True


# =============================================================================
# HANDLERS -- moderation commands
# =============================================================================
async def ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _group_only(update) or not await _require_issuer_admin(update, context):
        return
    if not await _require_bot_permission(update, context, ["can_restrict_members"]):
        return

    chat = update.effective_chat
    target = await resolve_target_user(update, context)
    if target is None:
        await update.effective_message.reply_text("Reply to the user's message with /ban to ban them.")
        return
    if await is_user_admin(chat.id, target.id, context):
        await update.effective_message.reply_text("🚫 I won't ban an admin or the group owner.")
        return
    try:
        await context.bot.ban_chat_member(chat.id, target.id)
        await update.effective_message.reply_text(f"✅ Banned {target.mention_html()}", parse_mode="HTML")
    except TelegramError as e:
        logger.error("Ban failed in chat=%s target=%s: %s", chat.id, target.id, e)
        await update.effective_message.reply_text(f"❌ Failed to ban user: {e.message}")


async def mute_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _group_only(update) or not await _require_issuer_admin(update, context):
        return
    if not await _require_bot_permission(update, context, ["can_restrict_members"]):
        return

    chat = update.effective_chat
    target = await resolve_target_user(update, context)
    if target is None:
        await update.effective_message.reply_text("Reply to the user's message with /mute to mute them.")
        return
    if await is_user_admin(chat.id, target.id, context):
        await update.effective_message.reply_text("🚫 I won't mute an admin or the group owner.")
        return
    try:
        await context.bot.restrict_chat_member(chat.id, target.id, permissions=MUTED_PERMISSIONS)
        await update.effective_message.reply_text(f"🔇 Muted {target.mention_html()}", parse_mode="HTML")
    except TelegramError as e:
        logger.error("Mute failed in chat=%s target=%s: %s", chat.id, target.id, e)
        await update.effective_message.reply_text(f"❌ Failed to mute user: {e.message}")


async def lock_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _group_only(update) or not await _require_issuer_admin(update, context):
        return
    if not await _require_bot_permission(update, context, ["can_change_info"]):
        return
    chat = update.effective_chat
    try:
        await context.bot.set_chat_permissions(chat.id, LOCKED_PERMISSIONS)
        await update.effective_message.reply_text("🔒 Group locked. Only admins can send messages now.")
    except TelegramError as e:
        logger.error("Lock failed in chat=%s: %s", chat.id, e)
        await update.effective_message.reply_text(f"❌ Failed to lock group: {e.message}")


async def unlock_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await _group_only(update) or not await _require_issuer_admin(update, context):
        return
    if not await _require_bot_permission(update, context, ["can_change_info"]):
        return
    chat = update.effective_chat
    try:
        await context.bot.set_chat_permissions(chat.id, UNLOCKED_PERMISSIONS)
        await update.effective_message.reply_text("🔓 Group unlocked. Members can send messages again.")
    except TelegramError as e:
        logger.error("Unlock failed in chat=%s: %s", chat.id, e)
        await update.effective_message.reply_text(f"❌ Failed to unlock group: {e.message}")


# =============================================================================
# HANDLERS -- welcome message
# =============================================================================
def _style_label(name: str, style: str) -> str:
    return f"{BUTTON_STYLES.get(style, BUTTON_STYLES['primary'])} {name}"


def build_welcome_keyboard(settings: GroupSettings) -> InlineKeyboardMarkup | None:
    buttons = []
    for i in (1, 2, 3):
        name = getattr(settings, f"button{i}_name")
        url = getattr(settings, f"button{i}_url")
        style = getattr(settings, f"button{i}_style")
        if name and url:
            buttons.append(InlineKeyboardButton(_style_label(name, style), url=url))
    if not buttons:
        return None
    return InlineKeyboardMarkup([[b] for b in buttons])


def render_welcome_text(template: str, *, user, chat_title: str) -> str:
    mention = f"[{user.full_name}](tg://user?id={user.id})"
    try:
        return template.format(
            name=user.full_name,
            mention=mention,
            username=f"@{user.username}" if user.username else user.full_name,
            chat_title=chat_title,
        )
    except (KeyError, IndexError):
        logger.warning("Bad placeholder in welcome_message template for a chat; using raw text.")
        return template


async def handle_new_members(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    chat = update.effective_chat
    if not message or not message.new_chat_members:
        return

    settings = db.get_settings(chat.id)
    if not settings.welcome_enabled:
        return

    keyboard = build_welcome_keyboard(settings)

    for new_user in message.new_chat_members:
        if new_user.id == context.bot.id:
            continue
        if not db.mark_join_processed(chat.id, new_user.id, update.update_id):
            continue  # duplicate delivery of an already-handled join

        text = render_welcome_text(settings.welcome_message, user=new_user, chat_title=chat.title or "")
        try:
            await context.bot.send_message(
                chat_id=chat.id, text=text, parse_mode=ParseMode.MARKDOWN,
                reply_markup=keyboard, disable_web_page_preview=True,
            )
        except TelegramError as e:
            logger.error("Failed to send welcome message in chat=%s: %s", chat.id, e)


# =============================================================================
# HANDLERS -- anti-link / anti-inline-button-spam protection
# =============================================================================
URL_REGEX = re.compile(
    r"(?:(?:https?://|www\.)[^\s]+)"
    r"|(?:(?:t\.me|telegram\.me|telegram\.dog)/[^\s]+)"
    r"|(?:\b[a-zA-Z0-9-]+\.(?:com|net|org|io|me|xyz|info|biz|co|gg|link|click)\b(?:/[^\s]*)?)",
    re.IGNORECASE,
)
LINK_ENTITY_TYPES = {MessageEntityType.URL, MessageEntityType.TEXT_LINK, MessageEntityType.MENTION}


def message_contains_link(message) -> bool:
    text = message.text or message.caption or ""
    entities = message.entities or message.caption_entities or []
    if any(e.type in LINK_ENTITY_TYPES for e in entities):
        return True
    return bool(URL_REGEX.search(text))


def message_has_inline_url_button(message) -> bool:
    if not message.reply_markup or not message.reply_markup.inline_keyboard:
        return False
    return any(getattr(b, "url", None) for row in message.reply_markup.inline_keyboard for b in row)


async def _safe_delete(message, context: ContextTypes.DEFAULT_TYPE) -> bool:
    missing = await get_bot_permission_gaps(message.chat_id, context, ["can_delete_messages"])
    if missing:
        logger.warning("Cannot delete message in chat=%s: missing %s", message.chat_id, describe_missing(missing))
        return False
    try:
        await message.delete()
        return True
    except TelegramError as e:
        logger.error("Delete failed in chat=%s msg=%s: %s", message.chat_id, message.message_id, e)
        return False


async def handle_potential_link_spam(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    NOTE ON SCOPE: a normal Telegram user cannot attach an inline keyboard to
    their own message -- that's bot-only (or via a bot's inline mode). So
    "button/inline-link spam" here means a member used an inline-mode
    promo/spam bot to post a message-with-button (message.via_bot is set).
    """
    message = update.effective_message
    if message is None or message.from_user is None:
        return
    chat = update.effective_chat
    user = message.from_user

    if await is_user_admin(chat.id, user.id, context):  # requirement: never touch admins
        return

    settings = db.get_settings(chat.id)
    if not settings.antilink_enabled:
        return

    via_inline_bot_button = bool(message.via_bot) and message_has_inline_url_button(message)
    has_link_text = message_contains_link(message)
    if not via_inline_bot_button and not has_link_text:
        return

    if not await _safe_delete(message, context):
        return

    if via_inline_bot_button:
        if settings.automute_on_link_button:
            missing = await get_bot_permission_gaps(chat.id, context, ["can_restrict_members"])
            if not missing:
                try:
                    await context.bot.restrict_chat_member(chat.id, user.id, permissions=MUTED_PERMISSIONS)
                    await context.bot.send_message(
                        chat.id,
                        f"🔇 {user.mention_html()} was muted for posting a promotional/link "
                        "button. Contact an admin if you think this is a mistake.",
                        parse_mode="HTML",
                    )
                except TelegramError as e:
                    logger.error("Auto-mute failed in chat=%s user=%s: %s", chat.id, user.id, e)
            else:
                logger.warning("Wanted to auto-mute in chat=%s but missing: %s", chat.id, describe_missing(missing))
        else:
            await context.bot.send_message(
                chat.id,
                f"⚠️ A message from {user.mention_html()} was removed: promotional/link "
                "buttons are not allowed here.",
                parse_mode="HTML",
            )
    else:
        await context.bot.send_message(
            chat.id,
            f"⚠️ A message from {user.mention_html()} was removed: links are not allowed "
            "for regular members in this group.",
            parse_mode="HTML",
        )


# =============================================================================
# HANDLERS -- admin panel (in-group quick menu + DM free-text editor)
# =============================================================================
def _next_style(current: str) -> str:
    try:
        idx = STYLE_ORDER.index(current)
    except ValueError:
        idx = -1
    return STYLE_ORDER[(idx + 1) % len(STYLE_ORDER)]


async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    user = update.effective_user

    if chat.type == ChatType.PRIVATE:
        await update.effective_message.reply_text(
            "Use /settings inside your group -- I'll show you the admin panel there."
        )
        return
    if not await is_user_admin(chat.id, user.id, context):
        await update.effective_message.reply_text("🚫 Only group admins can open the settings panel.")
        return

    settings = db.get_settings(chat.id)
    bot_username = (await context.bot.get_me()).username
    token = sign_chat_token(chat.id)  # fresh, expiring, tamper-proof each time /settings is opened
    deep_link = f"https://t.me/{bot_username}?start=cfg_{token}"

    text = (
        f"⚙️ *Settings for {chat.title}*\n\n"
        f"Welcome messages: {'✅ ON' if settings.welcome_enabled else '❌ OFF'}\n"
        f"Anti-link protection: {'✅ ON' if settings.antilink_enabled else '❌ OFF'}\n"
        f"Auto-mute on link-button spam: {'✅ ON' if settings.automute_on_link_button else '❌ OFF'}\n\n"
        "Tap below to toggle things, cycle button styles, or open the full "
        "text editor in a DM (needed for editing the welcome message and "
        "button names/links)."
    )
    keyboard = [
        [InlineKeyboardButton(f"Welcome: {'Disable' if settings.welcome_enabled else 'Enable'}", callback_data="toggle:welcome")],
        [InlineKeyboardButton(f"Anti-Link: {'Disable' if settings.antilink_enabled else 'Enable'}", callback_data="toggle:antilink")],
        [InlineKeyboardButton(f"Auto-Mute on Link-Button: {'Disable' if settings.automute_on_link_button else 'Enable'}", callback_data="toggle:automute")],
        [InlineKeyboardButton(f"Button 1 style: {BUTTON_STYLES[settings.button1_style]}", callback_data="cyclestyle:1")],
        [InlineKeyboardButton(f"Button 2 style: {BUTTON_STYLES[settings.button2_style]}", callback_data="cyclestyle:2")],
        [InlineKeyboardButton(f"Button 3 style: {BUTTON_STYLES[settings.button3_style]}", callback_data="cyclestyle:3")],
        [InlineKeyboardButton("✏️ Edit text/links in DM", url=deep_link)],
    ]
    await update.effective_message.reply_text(
        text, parse_mode=ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def settings_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    chat = update.effective_chat
    user = update.effective_user

    if not await is_user_admin(chat.id, user.id, context):
        await query.answer("Only group admins can change settings.", show_alert=True)
        return

    data = query.data
    if data == "toggle:welcome":
        new_val = db.toggle_welcome(chat.id)
        await query.answer(f"Welcome messages {'enabled' if new_val else 'disabled'}.")
    elif data == "toggle:antilink":
        new_val = db.toggle_antilink(chat.id)
        await query.answer(f"Anti-link protection {'enabled' if new_val else 'disabled'}.")
    elif data == "toggle:automute":
        new_val = db.toggle_automute(chat.id)
        await query.answer(f"Auto-mute on link-button {'enabled' if new_val else 'disabled'}.")
    elif data.startswith("cyclestyle:"):
        index = int(data.split(":")[1])
        settings = db.get_settings(chat.id)
        new_style = _next_style(getattr(settings, f"button{index}_style"))
        db.set_button(chat.id, index, style=new_style)
        await query.answer(f"Button {index} style set to {new_style}.")
    else:
        await query.answer()
        return

    await settings_command(update, context)  # redraw menu with fresh state
    try:
        await query.message.delete()
    except Exception:
        pass


EDITABLE_FIELDS = {
    "welcome_text": ("welcome_message", "the welcome message text"),
    "btn1_name": ("button1_name", "Button 1's name"),
    "btn1_url": ("button1_url", "Button 1's URL"),
    "btn2_name": ("button2_name", "Button 2's name"),
    "btn2_url": ("button2_url", "Button 2's URL"),
    "btn3_name": ("button3_name", "Button 3's name"),
    "btn3_url": ("button3_url", "Button 3's URL"),
}


def _dm_menu_keyboard(chat_id: int) -> InlineKeyboardMarkup:
    def cb(field_key):
        return f"dmedit:{chat_id}:{field_key}"
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✏️ Welcome message", callback_data=cb("welcome_text"))],
        [InlineKeyboardButton("Button 1 name", callback_data=cb("btn1_name")),
         InlineKeyboardButton("Button 1 URL", callback_data=cb("btn1_url"))],
        [InlineKeyboardButton("Button 2 name", callback_data=cb("btn2_name")),
         InlineKeyboardButton("Button 2 URL", callback_data=cb("btn2_url"))],
        [InlineKeyboardButton("Button 3 name", callback_data=cb("btn3_name")),
         InlineKeyboardButton("Button 3 URL", callback_data=cb("btn3_url"))],
    ])


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args or not args[0].startswith("cfg_"):
        await update.effective_message.reply_text(
            "👋 Hi! Add me to a group and make me an admin to get started.\n"
            "Group admins can run /settings inside the group to configure me."
        )
        return

    token = args[0].removeprefix("cfg_")
    target_chat_id = verify_chat_token(token)
    if target_chat_id is None:
        await update.effective_message.reply_text(
            "⚠️ That settings link is invalid or has expired. Go back to your group "
            "and run /settings again to get a fresh one."
        )
        return

    user = update.effective_user
    if not await is_user_admin(target_chat_id, user.id, context):
        await update.effective_message.reply_text("🚫 You need to be an admin of that group to edit its settings.")
        return

    try:
        chat = await context.bot.get_chat(target_chat_id)
        chat_title = chat.title or str(target_chat_id)
    except Exception:
        chat_title = str(target_chat_id)

    await update.effective_message.reply_text(
        f"✏️ Editing settings for *{chat_title}*.\nPick a field to update:",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=_dm_menu_keyboard(target_chat_id),
    )


async def dm_edit_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    _, chat_id_str, field_key = query.data.split(":", 2)
    chat_id = int(chat_id_str)
    user = update.effective_user

    if not await is_user_admin(chat_id, user.id, context):
        await query.answer("You're no longer an admin of that group.", show_alert=True)
        return
    if field_key not in EDITABLE_FIELDS:
        await query.answer("Unknown field.", show_alert=True)
        return

    db_field, human_label = EDITABLE_FIELDS[field_key]
    context.user_data["awaiting_edit"] = {"chat_id": chat_id, "db_field": db_field, "label": human_label}

    await query.answer()
    hint = ""
    if db_field == "welcome_message":
        hint = "\n\nYou can use these placeholders: `{name}`, `{mention}`, `{username}`, `{chat_title}`."
    await query.message.reply_text(f"Send me the new value for *{human_label}* now.{hint}", parse_mode=ParseMode.MARKDOWN)


async def dm_text_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    pending = context.user_data.get("awaiting_edit")
    if not pending:
        return

    chat_id = pending["chat_id"]
    db_field = pending["db_field"]
    label = pending["label"]
    new_value = update.effective_message.text

    if not new_value:
        await update.effective_message.reply_text("Please send text, not a photo/file/etc.")
        return
    if db_field.endswith("_url") and not (new_value.startswith("http://") or new_value.startswith("https://")):
        await update.effective_message.reply_text("That doesn't look like a valid URL -- it must start with http:// or https://.")
        return

    try:
        db.update_field(chat_id, db_field, new_value)
    except ValueError as e:
        logger.error("Rejected settings update: %s", e)
        await update.effective_message.reply_text("❌ Couldn't save that field.")
        return

    context.user_data.pop("awaiting_edit", None)
    await update.effective_message.reply_text(f"✅ Saved! {label} has been updated.", reply_markup=_dm_menu_keyboard(chat_id))


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(
        "🛡️ *Group Moderation Bot*\n\n"
        "*Moderation (admins only, reply to a message):*\n"
        "/ban - ban the replied user\n"
        "/mute - mute the replied user\n"
        "/lock - lock the group (only admins can post)\n"
        "/unlock - unlock the group\n\n"
        "*Configuration:*\n"
        "/settings - open the admin panel (in-group)\n\n"
        "Add me as a group *admin* with ban/restrict/delete/change-info "
        "permissions for everything to work.",
        parse_mode="Markdown",
    )


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Unhandled exception while processing update %s", update, exc_info=context.error)


# =============================================================================
# MAIN
# =============================================================================
def main():
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))

    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, handle_new_members))

    app.add_handler(CommandHandler("ban", ban_command))
    app.add_handler(CommandHandler("mute", mute_command))
    app.add_handler(CommandHandler("lock", lock_command))
    app.add_handler(CommandHandler("unlock", unlock_command))

    app.add_handler(CommandHandler("settings", settings_command))
    app.add_handler(CallbackQueryHandler(settings_callback, pattern=r"^(toggle:|cyclestyle:)"))

    app.add_handler(CallbackQueryHandler(dm_edit_callback, pattern=r"^dmedit:"))
    app.add_handler(MessageHandler(filters.ChatType.PRIVATE & filters.TEXT & ~filters.COMMAND, dm_text_input))

    app.add_handler(
        MessageHandler(
            filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND,
            handle_potential_link_spam,
        ),
        group=1,
    )

    app.add_error_handler(on_error)

    if WEBHOOK_URL:
        logger.info("Bot starting in WEBHOOK mode at %s ...", WEBHOOK_URL)
        app.run_webhook(
            listen=WEBHOOK_LISTEN,
            port=WEBHOOK_PORT,
            url_path=BOT_TOKEN,
            webhook_url=f"{WEBHOOK_URL.rstrip('/')}/{BOT_TOKEN}",
            secret_token=WEBHOOK_SECRET_TOKEN,
            allowed_updates=Update.ALL_TYPES,
        )
    else:
        logger.info("Bot starting in POLLING mode...")
        app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
