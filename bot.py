import asyncio
import io
import json
import logging
import os
import re
import subprocess
import threading
import time
from html import escape as html_escape
from urllib.parse import parse_qs, urlparse

import aiosqlite
import cv2
import numpy as np
import pytesseract
from curl_cffi.requests import AsyncSession
from pyzbar.pyzbar import ZBarSymbol, decode as decode_qr
from telethon import TelegramClient
from telethon.errors import (
    FloodWaitError,
    PhoneNumberInvalidError,
    PasswordHashInvalidError,
    PhoneCodeExpiredError,
    PhoneCodeInvalidError,
    SessionPasswordNeededError,
)
from telethon.sessions import StringSession

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
)

# ============================================================
# CONFIGURATION
# ============================================================

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
API_ID = int(os.getenv("API_ID", "0") or 0)
API_HASH = os.getenv("API_HASH", "").strip()

ADMIN_IDS = [
    int(x) for x in re.findall(r"-?\d+", os.getenv("ADMIN_IDS", ""))
]

ENV_SOURCE_URL = os.getenv("SOURCE_URL", "").strip()
ENV_COOKIES = os.getenv("ITV_COOKIES", "").strip()
ENV_BEARER_TOKEN = os.getenv("ITV_BEARER_TOKEN", "").strip()
ENV_PROXY_URL = os.getenv("PROXY_URL", "").strip()

DEFAULT_FRAME_INTERVAL = float(os.getenv("FRAME_INTERVAL", "2"))

TARGET_BOT = "Milliydaman_bot"

DUPLICATE_WINDOW_SEC = 600

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

M3U8_RE = re.compile(
    r'https?:\\?/\\?/[^\s"\'<>]+?\.m3u8[^\s"\'<>]*',
    re.IGNORECASE,
)

AD_MARKERS = (
    "vast",
    "doubleclick",
    "imasdk",
    "/ads/",
    "adserver",
    "googlesyndication",
    "adservice",
)

BLOCKED_URL_MARKERS = (
    "doubleclick.net",
    "googlesyndication.com",
    "googletagmanager.com",
    "google-analytics.com",
    "yandex.ru/metrika",
    "mc.yandex.ru",
    "sentry.io",
    "hotjar.com",
    "amplitude.com",
    "mixpanel.com",
    "facebook.net",
)

DATA_DIR = "/data" if os.path.isdir("/data") else "./data"
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "milliydaman_pro.db")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger("MilliyScannerPro")

if not BOT_TOKEN:
    raise SystemExit("BOT_TOKEN не задан.")

bot = Bot(
    token=BOT_TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML),
)

dp = Dispatcher(storage=MemoryStorage())
router = Router()
user_router = Router()
dp.include_router(router)       # админ
dp.include_router(user_router)  # обычные пользователи

# ============================================================
# GLOBAL STATE
# ============================================================

auth_clients: dict[int, dict] = {}
active_clients: dict[int, TelegramClient] = {}

scanner_running = False
scanner_task: asyncio.Task | None = None
scanner_stop = threading.Event()

frame_interval = DEFAULT_FRAME_INTERVAL
cached_m3u8: str | None = None

capture_lock = threading.Lock()

scan_stats = {
    "frames": 0,
    "last_frame_ts": 0.0,
    "stream": False,
    "last_jpeg": None,
    "last_error": "",
    "last_code": "",
}

# ============================================================
# ADMIN
# ============================================================

def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS


# ============================================================
# DATABASE
# ============================================================

async def init_db():
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=30000")

        await db.execute("""
            CREATE TABLE IF NOT EXISTS userbots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT UNIQUE,
                full_name TEXT,
                session_string TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                last_points TEXT DEFAULT '—'
            )
        """)

        # Миграция: владелец аккаунта (для аккаунтов, подключённых пользователями)
        try:
            await db.execute("ALTER TABLE userbots ADD COLUMN owner_id INTEGER")
        except Exception:
            pass  # колонка уже есть

        await db.execute("""
            CREATE TABLE IF NOT EXISTS sent_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE,
                method TEXT,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        settings = (
            ("source_url", ENV_SOURCE_URL),
            ("cookies", ENV_COOKIES),
            ("bearer_token", ENV_BEARER_TOKEN),
            ("proxy_url", ENV_PROXY_URL),
            ("frame_interval", str(DEFAULT_FRAME_INTERVAL)),
        )

        for key, value in settings:
            await db.execute(
                """
                INSERT OR IGNORE INTO settings (key, value)
                VALUES (?, ?)
                """,
                (key, value),
            )

        await db.commit()

    logger.info("База данных инициализирована: %s", DB_PATH)


async def get_setting(key: str) -> str:
    env_map = {
        "source_url": ENV_SOURCE_URL,
        "cookies": ENV_COOKIES,
        "bearer_token": ENV_BEARER_TOKEN,
        "proxy_url": ENV_PROXY_URL,
        "frame_interval": str(DEFAULT_FRAME_INTERVAL),
    }

    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        async with db.execute(
            "SELECT value FROM settings WHERE key = ?",
            (key,),
        ) as cur:
            row = await cur.fetchone()

    return (row[0] if row and row[0] else env_map.get(key, "")) or ""


async def set_setting(key: str, value: str):
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        await db.execute(
            """
            INSERT OR REPLACE INTO settings (key, value)
            VALUES (?, ?)
            """,
            (key, value),
        )
        await db.commit()


async def load_frame_interval() -> float:
    global frame_interval
    try:
        value = float(await get_setting("frame_interval"))
        if not 0.5 <= value <= 600:
            raise ValueError
        frame_interval = value
    except (ValueError, TypeError):
        frame_interval = DEFAULT_FRAME_INTERVAL
    return frame_interval


async def add_or_update_userbot(
    phone: str,
    full_name: str,
    session_string: str,
    owner_id: int | None = None,
):
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        await db.execute(
            """
            INSERT INTO userbots (
                phone,
                full_name,
                session_string,
                is_active,
                owner_id
            )
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(phone) DO UPDATE SET
                full_name = excluded.full_name,
                session_string = excluded.session_string,
                is_active = 1,
                owner_id = COALESCE(excluded.owner_id, owner_id)
            """,
            (phone, full_name, session_string, owner_id),
        )
        await db.commit()


async def get_owner_map() -> dict[int, int | None]:
    """{id аккаунта: Telegram ID владельца (None — добавлен админом)}"""
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        async with db.execute("SELECT id, owner_id FROM userbots") as cur:
            return {row[0]: row[1] for row in await cur.fetchall()}


async def count_user_accounts(owner_id: int) -> int:
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        async with db.execute(
            "SELECT COUNT(*) FROM userbots WHERE owner_id = ?",
            (owner_id,),
        ) as cur:
            row = await cur.fetchone()
    return int(row[0]) if row else 0


async def get_user_accounts(owner_id: int):
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        async with db.execute(
            """
            SELECT id, phone, full_name, is_active, last_points
            FROM userbots
            WHERE owner_id = ?
            ORDER BY id
            """,
            (owner_id,),
        ) as cur:
            return await cur.fetchall()


async def get_userbot(acc_id: int):
    """(id, phone, full_name, session_string, is_active, last_points, owner_id)"""
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        async with db.execute(
            """
            SELECT id, phone, full_name, session_string,
                   is_active, last_points, owner_id
            FROM userbots
            WHERE id = ?
            """,
            (acc_id,),
        ) as cur:
            return await cur.fetchone()


async def delete_userbot(acc_id: int):
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        await db.execute("DELETE FROM userbots WHERE id = ?", (acc_id,))
        await db.commit()


async def get_all_userbots():
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        async with db.execute("""
            SELECT
                id,
                phone,
                full_name,
                session_string,
                is_active,
                last_points
            FROM userbots
            ORDER BY id
        """) as cur:
            return await cur.fetchall()


async def is_code_recently_sent(code: str) -> bool:
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        async with db.execute(
            """
            SELECT 1
            FROM sent_codes
            WHERE code = ?
            AND sent_at > datetime('now', ?)
            """,
            (code, f"-{DUPLICATE_WINDOW_SEC} seconds"),
        ) as cur:
            return (await cur.fetchone()) is not None


async def mark_code_sent(code: str, method: str):
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        await db.execute(
            """
            INSERT OR REPLACE INTO sent_codes (
                code,
                method,
                sent_at
            )
            VALUES (?, ?, CURRENT_TIMESTAMP)
            """,
            (code, method),
        )
        await db.commit()


# ============================================================
# COOKIES
# ============================================================

def parse_itv_cookies(raw: str) -> tuple[dict[str, str], str]:
    raw = (raw or "").strip()
    if not raw:
        return {}, ""

    cookies: dict[str, str] = {}
    token = ""

    def absorb(item: dict):
        nonlocal token
        domain = str(item.get("domain", ""))
        if domain and "itv.uz" not in domain:
            return
        name = str(item.get("name", "") or "").strip()
        if not name:
            return
        value = str(item.get("value", ""))
        cookies[name] = value
        if any(k in name.lower() for k in ("token", "auth", "jwt", "access")):
            token = value

    if "{" in raw and '"name"' in raw:
        try:
            cleaned = raw
            if not cleaned.startswith("["):
                start = cleaned.find("{")
                end = cleaned.rfind("}")
                if start < 0 or end < start:
                    raise ValueError("Некорректный JSON Cookies")
                cleaned = "[" + cleaned[start:end + 1] + "]"

            parsed = json.loads(cleaned)
            if isinstance(parsed, dict):
                parsed = [parsed]
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        absorb(item)
        except Exception:
            for block in re.findall(r"\{[^{}]+\}", raw):
                try:
                    item = json.loads(block)
                    if isinstance(item, dict):
                        absorb(item)
                except Exception:
                    continue

        if cookies:
            return cookies, token

    for part in raw.split(";"):
        if "=" not in part:
            continue
        key, value = part.strip().split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        cookies[key] = value
        if any(item in key.lower() for item in ("token", "auth", "jwt", "access")):
            token = value

    return cookies, token


# ============================================================
# PROXY
# ============================================================

def normalize_proxy(proxy_url: str) -> str:
    proxy_url = (proxy_url or "").strip()
    if not proxy_url:
        return ""

    if proxy_url.startswith("tcp://"):
        proxy_url = "http://" + proxy_url[6:]

    parsed = urlparse(proxy_url)
    if parsed.scheme.lower() not in ("http", "https", "socks5", "socks5h"):
        raise ValueError(
            "Поддерживаются HTTP, HTTPS или SOCKS5 прокси (например, http://host:port)."
        )

    if not parsed.hostname:
        raise ValueError("Некорректный адрес Proxy.")

    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("Некорректный порт Proxy.")

    return proxy_url


def playwright_proxy(proxy_url: str) -> dict | None:
    if not proxy_url:
        return None

    parsed = urlparse(proxy_url)
    if not parsed.hostname:
        return {"server": proxy_url}

    server = (
        f"{parsed.scheme or 'http'}://{parsed.hostname}"
        + (f":{parsed.port}" if parsed.port else "")
    )
    config: dict[str, str] = {"server": server}
    if parsed.username:
        config["username"] = parsed.username
        config["password"] = parsed.password or ""
    return config


# ============================================================
# M3U8 EXTRACTION
# ============================================================

def extract_m3u8(text: str) -> list[str]:
    result: list[str] = []
    for match in M3U8_RE.findall(text or ""):
        url = (
            match
            .replace("\\/", "/")
            .replace("\\u0026", "&")
            .rstrip("),;\"'")
        )
        if not url.lower().startswith(("http://", "https://")):
            continue
        if any(marker in url.lower() for marker in AD_MARKERS):
            continue
        if url not in result:
            result.append(url)
    return result


# ============================================================
# ITV API / DIRECT RESOLVER
# ============================================================

async def resolve_fresh_m3u8_url() -> str | None:
    source_url = (await get_setting("source_url")).strip()
    if not source_url:
        logger.warning("SOURCE_URL не задан.")
        return None

    if ".m3u8" in source_url.lower():
        return source_url

    cookies, auto_token = parse_itv_cookies(await get_setting("cookies"))
    bearer = (await get_setting("bearer_token")).strip() or auto_token
    proxy_url = normalize_proxy(await get_setting("proxy_url"))

    headers = {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, text/html, */*",
        "Origin": "https://itv.uz",
        "Referer": source_url if "itv.uz" in source_url else "https://itv.uz/",
    }
    if bearer:
        headers["Authorization"] = (
            bearer if bearer.lower().startswith("bearer ") else f"Bearer {bearer}"
        )

    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

    try:
        async with AsyncSession(
            impersonate="chrome124",
            proxies=proxies,
            verify=False,
            timeout=20,
        ) as session:
            if "itv.uz" in source_url.lower():
                match = (
                    re.search(r"/channels/player/(\d+)", source_url)
                    or re.search(r"/tv/(\d+)", source_url)
                )
                channel_id = match.group(1) if match else "138"

                # Пробуем актуальные варианты эндпоинтов iTV
                api_candidates = [
                    f"https://api.itv.uz/v2/cards/channels/show?channelId={channel_id}",
                    f"https://api.itv.uz/v2/channels/{channel_id}/stream",
                    f"https://api.itv.uz/v2/channels/{channel_id}",
                ]

                for api_url in api_candidates:
                    try:
                        resp = await session.get(
                            api_url,
                            cookies=cookies,
                            headers=headers,
                            timeout=12,
                        )
                        if resp.status_code == 200:
                            found = extract_m3u8(resp.text)
                            if found:
                                logger.info("M3U8 получен через API: %s", api_url)
                                return found[0]
                        else:
                            logger.debug("ITV API HTTP %s: %s", resp.status_code, api_url)
                    except Exception as e:
                        logger.debug("Ошибка запроса ITV API %s: %s", api_url, e)

            # Прямой запрос страницы источника (иногда .m3u8 зашит в HTML/SSR/скриптах)
            resp = await session.get(
                source_url,
                cookies=cookies,
                headers=headers,
                timeout=18,
            )
            if resp.status_code == 200:
                found = extract_m3u8(resp.text)
                if found:
                    logger.info("M3U8 получен напрямую со страницы источника.")
                    return found[0]
            else:
                logger.warning("Источник вернул HTTP %s", resp.status_code)

    except Exception as e:
        logger.warning("Ошибка получения M3U8 через HTTP-клиент: %s", e)

    return None


# ============================================================
# PLAYWRIGHT (С ПЕРЕХВАТОМ ОТВЕТОВ И БЛОКИРОВКОЙ МУСОРА)
# ============================================================

async def _click_text(page, regex: re.Pattern) -> bool:
    for frame in page.frames:
        try:
            locator = frame.get_by_text(regex)
            count = min(await locator.count(), 6)
            for index in range(count):
                element = locator.nth(index)
                if await element.is_visible():
                    await element.click(force=True, timeout=2000)
                    return True
        except Exception:
            continue
    return False


KORISH_RE = re.compile(r"^\s*Ko['’ʻ`‘]?rish\s*$", re.IGNORECASE)
SKIP_RE = re.compile(
    r"^\s*(Skip\s*Ad|Пропустить(\s+рекламу)?|Reklamani\s+o['’ʻ`]?tkazish)\s*$",
    re.IGNORECASE,
)
QOLISH_RE = re.compile(r"^\s*Qolish\s*$", re.IGNORECASE)


async def browser_open_player(
    url: str,
    total_timeout: int = 55,
) -> tuple[bytes | None, str | None, str]:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None, None, "Playwright не установлен"

    cookies, _ = parse_itv_cookies(await get_setting("cookies"))
    proxy_url = normalize_proxy(await get_setting("proxy_url"))

    pw_cookies = [
        {
            "name": key,
            "value": value,
            "domain": ".itv.uz",
            "path": "/",
        }
        for key, value in cookies.items()
    ]

    sniffed: list[str] = []
    steps: list[str] = []
    shot: bytes | None = None

    def remember_url(url_value: str):
        if not url_value:
            return
        if ".m3u8" in url_value.lower():
            clean = (
                url_value.replace("\\/", "/")
                .replace("\\u0026", "&")
                .rstrip("),;\"'")
            )
            if (
                clean.lower().startswith(("http://", "https://"))
                and not any(m in clean.lower() for m in AD_MARKERS)
                and clean not in sniffed
            ):
                sniffed.append(clean)

    async def on_response(response):
        remember_url(response.url)
        try:
            ct = (response.headers.get("content-type") or "").lower()
            if any(x in ct for x in ("json", "javascript", "text", "mpegurl", "xml")):
                body = await response.text()
                for found in extract_m3u8(body):
                    if found not in sniffed:
                        sniffed.append(found)
        except Exception:
            pass

    async def on_route(route):
        req_url = route.request.url.lower()
        res_type = route.request.resource_type
        if any(marker in req_url for marker in BLOCKED_URL_MARKERS):
            await route.abort()
            return
        if res_type in ("font", "image", "media") and "itv.uz" not in req_url and ".m3u8" not in req_url:
            await route.abort()
            return
        await route.continue_()

    try:
        async with async_playwright() as p:
            launch = {
                "headless": True,
                "args": [
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--ignore-certificate-errors",
                    "--autoplay-policy=no-user-gesture-required",
                    "--disable-background-networking",
                    "--disable-renderer-backgrounding",
                    "--mute-audio",
                ],
            }
            pw_proxy = playwright_proxy(proxy_url)
            if pw_proxy:
                launch["proxy"] = pw_proxy

            browser = await p.chromium.launch(**launch)

            try:
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    ignore_https_errors=True,
                    user_agent=UA,
                )
                context.set_default_timeout(20000)

                if pw_cookies:
                    await context.add_cookies(pw_cookies)

                page = await context.new_page()
                await page.route("**/*", on_route)
                page.on("request", lambda req: remember_url(req.url))
                page.on("response", on_response)

                logger.info("Chromium открывает источник: %s", url)

                nav_ok = False
                for wait_mode, nav_timeout in (("commit", 35000), ("domcontentloaded", 45000)):
                    try:
                        await page.goto(url, wait_until=wait_mode, timeout=nav_timeout)
                        nav_ok = True
                        break
                    except Exception as nav_err:
                        logger.warning(
                            "Навигация (%s) не завершилась вовремя: %s",
                            wait_mode,
                            nav_err,
                        )
                        if sniffed:
                            nav_ok = True
                            break

                if not nav_ok and not sniffed:
                    return None, None, "Таймаут загрузки страницы в Chromium"

                await page.wait_for_timeout(2000)

                started = time.monotonic()
                korish_at = None
                skip_at = None

                while time.monotonic() - started < total_timeout:
                    if sniffed and (skip_at is not None or korish_at is not None):
                        await page.wait_for_timeout(1000)
                        break

                    if korish_at is None:
                        if await _click_text(page, KORISH_RE):
                            korish_at = time.monotonic()
                            steps.append("Ko'rish")
                            logger.info("Нажата кнопка Ko'rish.")
                            await page.wait_for_timeout(1800)
                            continue
                    else:
                        if await _click_text(page, QOLISH_RE):
                            if "Qolish" not in steps:
                                steps.append("Qolish")

                        if skip_at is None and await _click_text(page, SKIP_RE):
                            skip_at = time.monotonic()
                            steps.append("Skip Ad")
                            logger.info("Нажата кнопка Skip Ad.")
                            await page.wait_for_timeout(1500)

                    # Проверяем <video src="..."> на случай прямой ссылки или blob/m3u8
                    if not sniffed:
                        try:
                            video_urls = await page.evaluate("""() => {
                                const res = [];
                                for (const v of document.querySelectorAll('video')) {
                                    if (v.currentSrc) res.push(v.currentSrc);
                                    if (v.src) res.push(v.src);
                                    for (const s of v.querySelectorAll('source')) {
                                        if (s.src) res.push(s.src);
                                    }
                                }
                                return res;
                            }""")
                            for vu in video_urls or []:
                                remember_url(vu)
                        except Exception:
                            pass

                    if sniffed and (skip_at is not None or time.monotonic() - korish_at > 8):
                        break

                    await page.wait_for_timeout(800)

                try:
                    shot = await page.screenshot(
                        type="jpeg",
                        quality=80,
                        timeout=15000,
                    )
                except Exception as shot_err:
                    logger.warning("Не удалось сделать скриншот страницы: %s", shot_err)
                    shot = None

            finally:
                await browser.close()

        info = " → ".join(steps) if steps else "Кнопка Ko'rish не найдена"
        if sniffed:
            logger.info("Chromium перехватил M3U8: %s", sniffed[-1][:100])
        else:
            logger.warning("Chromium не обнаружил M3U8.")

        return shot, (sniffed[-1] if sniffed else None), info

    except Exception as e:
        logger.exception("Ошибка Playwright: %s", e)
        return None, None, f"Ошибка: {e}"


# ============================================================
# STREAM URL
# ============================================================

async def acquire_stream_url() -> str | None:
    url = await resolve_fresh_m3u8_url()
    if url:
        return url

    source = (await get_setting("source_url")).strip()
    if source.lower().startswith(("http://", "https://")):
        _, sniffed, info = await browser_open_player(source)
        logger.info("Браузер: %s | M3U8=%s", info, bool(sniffed))
        return sniffed

    return None


# ============================================================
# QR DETECTION
# ============================================================

def extract_code_from_qr_payload(text: str) -> str | None:
    text = (text or "").strip()
    if not text:
        return None

    low = text.lower()
    if "milliydaman" in low or "t.me/" in low or low.startswith("tg:"):
        params = parse_qs(urlparse(text).query)
        start = (params.get("start") or [""])[0].strip()
        if re.fullmatch(r"[A-Za-z0-9_\-]{3,64}", start):
            # "c_3172" -> "3172": боту нужны только цифры
            m = re.fullmatch(r"(?:[A-Za-z]+_)?(\d{4})", start)
            return m.group(1) if m else start
        return None

    digits = re.sub(r"\D", "", text)
    if len(digits) == 4 and digits == text.strip():
        return digits

    return None


def _qr_candidates(gray: np.ndarray):
    yield gray
    yield cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(gray)
    yield cv2.adaptiveThreshold(
        gray,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31,
        8,
    )
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield otsu


def decode_qr_from_frame(frame: np.ndarray) -> str | None:
    height = frame.shape[0]
    detector = cv2.QRCodeDetector()

    for region in (frame[int(height * 0.40):], frame):
        gray = cv2.cvtColor(region, cv2.COLOR_BGR2GRAY)
        for scale in (1.0, 2.0, 3.0):
            image = (
                gray
                if scale == 1.0
                else cv2.resize(
                    gray,
                    None,
                    fx=scale,
                    fy=scale,
                    interpolation=cv2.INTER_CUBIC,
                )
            )
            for candidate in _qr_candidates(image):
                try:
                    objects = decode_qr(candidate, symbols=[ZBarSymbol.QRCODE])
                    for obj in objects:
                        payload = obj.data.decode("utf-8", errors="ignore")
                        code = extract_code_from_qr_payload(payload)
                        if code:
                            return code
                except Exception as e:
                    logger.debug("QR ZBar: %s", e)

            try:
                data, _, _ = detector.detectAndDecode(image)
                code = extract_code_from_qr_payload(data)
                if code:
                    return code
            except cv2.error:
                continue

    return None


# ============================================================
# OCR DETECTION
# ============================================================

def _ocr_digits(img: np.ndarray) -> str | None:
    for psm in (7, 8, 13):
        try:
            text = pytesseract.image_to_string(
                img,
                config=f"--psm {psm} -c tessedit_char_whitelist=0123456789",
            ).strip()
        except Exception as e:
            logger.error("Tesseract: %s", e)
            return None

        digits = re.sub(r"\D", "", text)
        if len(digits) == 4:
            return digits
    return None


def extract_yellow_code_ocr(frame: np.ndarray) -> str | None:
    height, width = frame.shape[:2]
    y0 = int(height * 0.40)
    roi = frame[y0:]

    hsv = cv2.cvtColor(roi, cv2.COLOR_BGR2HSV)
    mask = cv2.inRange(
        hsv,
        np.array([14, 75, 130]),
        np.array([45, 255, 255]),
    )

    if np.count_nonzero(mask) < mask.size * 0.0003:
        return None

    kx = max(5, int(width * 0.010))
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (kx, 3))
    merged = cv2.dilate(mask, kernel)

    contours, _ = cv2.findContours(
        merged,
        cv2.RETR_EXTERNAL,
        cv2.CHAIN_APPROX_SIMPLE,
    )

    boxes = []
    for contour in contours:
        x, y, bw, bh = cv2.boundingRect(contour)
        if bh < height * 0.016 or bh > height * 0.24:
            continue
        if not (1.4 <= bw / max(1, bh) <= 8.5):
            continue
        boxes.append((bw * bh, x, y, bw, bh))

    boxes.sort(reverse=True)
    gray_roi = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)

    for _, x, y, bw, bh in boxes[:5]:
        pad = max(4, bh // 6)
        xa = max(0, x - pad)
        ya = max(0, y - pad)
        xb = min(width, x + bw + pad)
        yb = min(roi.shape[0], y + bh + pad)

        variants = [255 - mask[ya:yb, xa:xb]]
        gray = gray_roi[ya:yb, xa:xb]
        _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        variants.append(otsu if np.mean(otsu) > 127 else 255 - otsu)

        for variant in variants:
            scale = 90.0 / max(1, variant.shape[0])
            resized = cv2.resize(
                variant,
                None,
                fx=scale,
                fy=scale,
                interpolation=cv2.INTER_CUBIC,
            )
            bordered = cv2.copyMakeBorder(
                resized,
                12,
                12,
                12,
                12,
                cv2.BORDER_CONSTANT,
                value=255,
            )
            code = _ocr_digits(bordered)
            if code:
                return code

    return None


# ============================================================
# FRAME ANALYSIS
# ============================================================

def analyze_frame(frame: np.ndarray) -> tuple[str | None, str | None]:
    if frame is None or frame.size == 0:
        return None, None

    if frame.shape[1] > 1600:
        scale = 1600 / frame.shape[1]
        frame = cv2.resize(
            frame,
            None,
            fx=scale,
            fy=scale,
            interpolation=cv2.INTER_AREA,
        )

    code = decode_qr_from_frame(frame)
    if code:
        return code, "QR-код"

    code = extract_yellow_code_ocr(frame)
    if code:
        return code, "4 цифры (OCR)"

    return None, None


def banner_likely(frame: np.ndarray) -> bool:
    height = frame.shape[0]
    hsv = cv2.cvtColor(frame[int(height * 0.45):], cv2.COLOR_BGR2HSV)
    mask = cv2.inRange(
        hsv,
        np.array([115, 60, 60]),
        np.array([170, 255, 255]),
    )
    return (np.count_nonzero(mask) / mask.size) > 0.04


# ============================================================
# OPENCV / FFMPEG STREAM CONNECTION
# ============================================================

def _build_ffmpeg_headers(m3u8_url: str, cookie_header: str) -> str:
    headers = (
        "Referer: https://itv.uz/\r\n"
        "Origin: https://itv.uz\r\n"
        f"User-Agent: {UA}\r\n"
    )
    hostname = (urlparse(m3u8_url).hostname or "").lower()
    if cookie_header and (hostname == "itv.uz" or hostname.endswith(".itv.uz")):
        headers += f"Cookie: {cookie_header}\r\n"
    return headers


def open_capture(
    m3u8_url: str,
    proxy_url: str,
    cookie_header: str,
) -> cv2.VideoCapture:
    if not m3u8_url.lower().startswith(("http://", "https://")):
        raise ValueError("Некорректный M3U8 URL.")

    proxy_url = normalize_proxy(proxy_url)
    headers = _build_ffmpeg_headers(m3u8_url, cookie_header)

    options = [
        "protocol_whitelist;file,http,https,tcp,tls,crypto,httpproxy",
        "tls_verify;0",
        "rw_timeout;15000000",
        "reconnect;1",
        "reconnect_streamed;1",
        "reconnect_delay_max;4",
        f"headers;{headers}",
    ]
    if proxy_url and proxy_url.startswith(("http://", "https://")):
        options.append(f"http_proxy;{proxy_url}")

    params = [
        cv2.CAP_PROP_OPEN_TIMEOUT_MSEC,
        15000,
        cv2.CAP_PROP_READ_TIMEOUT_MSEC,
        15000,
    ]

    with capture_lock:
        previous_options = os.environ.get("OPENCV_FFMPEG_CAPTURE_OPTIONS")
        os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "|".join(options)
        try:
            try:
                cap = cv2.VideoCapture(m3u8_url, cv2.CAP_FFMPEG, params)
            except (cv2.error, TypeError):
                cap = cv2.VideoCapture(m3u8_url, cv2.CAP_FFMPEG)
        finally:
            if previous_options is None:
                os.environ.pop("OPENCV_FFMPEG_CAPTURE_OPTIONS", None)
            else:
                os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = previous_options

    if not cap.isOpened():
        cap.release()
        raise RuntimeError("FFmpeg не смог открыть видеопоток.")

    logger.info("FFmpeg успешно открыл видеопоток.")
    return cap


def grab_single_frame_ffmpeg_cli(
    m3u8_url: str,
    proxy_url: str,
    cookie_header: str,
    insecure: bool = False,
    timeout: int = 75,
) -> tuple[np.ndarray | None, str]:
    """Один кадр через системный ffmpeg. Возвращает (кадр, текст ошибки)."""
    proxy_url = normalize_proxy(proxy_url)
    headers = _build_ffmpeg_headers(m3u8_url, cookie_header)

    cmd = ["ffmpeg", "-nostdin", "-y", "-hide_banner", "-loglevel", "error"]
    if insecure:
        cmd += ["-tls_verify", "0"]
    if proxy_url and proxy_url.startswith(("http://", "https://")):
        cmd += ["-http_proxy", proxy_url]
    cmd += [
        "-headers",
        headers,
        "-rw_timeout",
        "30000000",
        "-i",
        m3u8_url,
        "-an",
        "-sn",
        "-frames:v",
        "1",
        "-f",
        "image2pipe",
        "-vcodec",
        "mjpeg",
        "-q:v",
        "3",
        "pipe:1",
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, f"таймаут ffmpeg ({timeout} с)"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

    err = proc.stderr.decode("utf-8", errors="ignore").strip()[-300:]
    if proc.returncode == 0 and proc.stdout:
        frame = cv2.imdecode(np.frombuffer(proc.stdout, np.uint8), cv2.IMREAD_COLOR)
        if frame is not None:
            return frame, ""
    return None, err or f"ffmpeg завершился с кодом {proc.returncode}"


def grab_single_frame(
    m3u8_url: str,
    proxy_url: str,
    cookie_header: str,
) -> np.ndarray | None:
    # Через прокси старт HLS занимает до ~50 с, поэтому таймаут большой.
    frame, err = grab_single_frame_ffmpeg_cli(m3u8_url, proxy_url, cookie_header)

    if frame is None and re.search(r"certificate|ssl|tls", err, re.IGNORECASE):
        logger.warning("Скриншот: ошибка TLS, повторяю с -tls_verify 0.")
        frame, err = grab_single_frame_ffmpeg_cli(
            m3u8_url, proxy_url, cookie_header, insecure=True
        )

    if frame is None:
        logger.warning("Скриншот: кадр не получен: %s", err)
    return frame


def _ffmpeg_stream_cmd(
    m3u8_url: str,
    proxy_url: str,
    cookie_header: str,
    interval: float,
    insecure: bool = False,
) -> list[str]:
    """ffmpeg отдаёт в stdout один MJPEG-кадр раз в `interval` секунд."""
    proxy_url = normalize_proxy(proxy_url)
    headers = _build_ffmpeg_headers(m3u8_url, cookie_header)

    cmd = ["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error"]
    if insecure:
        cmd += ["-tls_verify", "0"]
    if proxy_url and proxy_url.startswith(("http://", "https://")):
        cmd += ["-http_proxy", proxy_url]
    cmd += [
        "-headers",
        headers,
        "-rw_timeout",
        "15000000",
        "-i",
        m3u8_url,
        "-an",
        "-sn",
        "-vf",
        f"fps={1.0 / interval:.6f}",
        "-q:v",
        "4",
        "-flush_packets",
        "1",
        "-f",
        "image2pipe",
        "-vcodec",
        "mjpeg",
        "pipe:1",
    ]
    return cmd


def _run_ffmpeg_stream(
    m3u8_url: str,
    proxy_url: str,
    cookie_header: str,
    loop: asyncio.AbstractEventLoop,
    insecure: bool,
) -> tuple[str, int, str]:
    """Запускает ffmpeg и анализирует кадры. Возвращает (причина, кадров, stderr)."""
    from collections import deque

    interval = max(0.5, float(frame_interval))
    cmd = _ffmpeg_stream_cmd(m3u8_url, proxy_url, cookie_header, interval, insecure)

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    err_lines: deque[str] = deque(maxlen=15)
    state = {"activity": time.monotonic(), "reason": ""}
    done = threading.Event()

    def drain_stderr():
        try:
            for raw in iter(proc.stderr.readline, b""):
                line = raw.decode("utf-8", errors="ignore").strip()
                if line:
                    err_lines.append(line)
        except Exception:
            pass

    def watchdog():
        stall_limit = max(60.0, interval * 2 + 45)
        while not done.is_set():
            if proc.poll() is not None:
                return
            if scanner_stop.is_set():
                state["reason"] = "остановлено администратором"
            elif abs(frame_interval - interval) > 1e-6:
                state["reason"] = "интервал анализа изменён"
            elif time.monotonic() - state["activity"] > stall_limit:
                state["reason"] = f"поток завис (нет кадров {int(stall_limit)} с)"
            if state["reason"]:
                proc.kill()
                return
            done.wait(0.5)

    threading.Thread(target=drain_stderr, daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()

    frames = 0
    local_seen: dict[str, float] = {}
    buf = bytearray()

    try:
        while True:
            chunk = proc.stdout.read1(65536)
            if not chunk:
                break
            state["activity"] = time.monotonic()
            buf += chunk

            while True:
                start = buf.find(b"\xff\xd8")
                if start < 0:
                    del buf[:-1]  # вдруг последний байт — начало маркера
                    break
                end = buf.find(b"\xff\xd9", start + 2)
                if end < 0:
                    if start > 0:
                        del buf[:start]
                    break

                jpeg = bytes(buf[start:end + 2])
                del buf[:end + 2]

                frame = cv2.imdecode(np.frombuffer(jpeg, np.uint8), cv2.IMREAD_COLOR)
                if frame is None:
                    continue

                if frames == 0:
                    scan_stats["stream"] = True
                    scan_stats["last_error"] = ""
                    logger.info("Постоянное соединение с эфиром установлено (ffmpeg CLI).")

                frames += 1
                scan_stats["frames"] += 1
                scan_stats["last_frame_ts"] = time.time()
                scan_stats["last_jpeg"] = jpeg

                try:
                    code, method = analyze_frame(frame)
                except Exception as e:
                    logger.exception("Ошибка анализа кадра: %s", e)
                    continue

                now = time.monotonic()
                if code and now - local_seen.get(code, -1e9) > DUPLICATE_WINDOW_SEC:
                    local_seen[code] = now
                    scan_stats["last_code"] = code
                    logger.info("Найден код: %s (%s)", code, method)

                    future = asyncio.run_coroutine_threadsafe(
                        handle_detected_code(code, method),
                        loop,
                    )

                    def report_future_error(fut):
                        try:
                            fut.result()
                        except Exception:
                            logger.exception("Ошибка обработки найденного кода.")

                    future.add_done_callback(report_future_error)
    finally:
        done.set()
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        scan_stats["stream"] = False

    stderr_tail = " | ".join(err_lines)
    reason = state["reason"] or (
        f"ffmpeg завершился (код {proc.returncode})"
        + (f": {stderr_tail[-300:]}" if stderr_tail else "")
    )
    return reason, frames, stderr_tail


def scan_stream_blocking(
    m3u8_url: str,
    proxy_url: str,
    cookie_header: str,
    loop: asyncio.AbstractEventLoop,
) -> str:
    try:
        reason, frames, err = _run_ffmpeg_stream(
            m3u8_url, proxy_url, cookie_header, loop, insecure=False
        )

        # Если упёрлись в сертификат и кадров не было — повторяем без проверки TLS.
        if (
            frames == 0
            and not scanner_stop.is_set()
            and re.search(r"certificate|ssl|tls", err, re.IGNORECASE)
        ):
            logger.warning("Ошибка TLS в ffmpeg, повторяю с -tls_verify 0.")
            reason, frames, err = _run_ffmpeg_stream(
                m3u8_url, proxy_url, cookie_header, loop, insecure=True
            )

        if not reason.startswith(("остановлено", "интервал")):
            scan_stats["last_error"] = reason
        return reason

    except FileNotFoundError:
        msg = "ffmpeg не найден в системе (установите пакет ffmpeg)."
        scan_stats["last_error"] = msg
        logger.error(msg)
        return msg
    except Exception as e:
        scan_stats["last_error"] = str(e)
        logger.exception("Ошибка чтения видеопотока.")
        return str(e)
    finally:
        scan_stats["stream"] = False
        logger.info("Соединение с видеопотоком закрыто.")


# ============================================================
# TELETHON USERBOTS
# ============================================================

_userbot_locks: dict[int, asyncio.Lock] = {}


def _make_userbot_client(session_str: str) -> TelegramClient:
    return TelegramClient(
        StringSession(session_str),
        API_ID,
        API_HASH,
        connection_retries=-1,   # не сдаваться при таймаутах до DC Telegram
        retry_delay=1,
        timeout=10,
        auto_reconnect=True,
        request_retries=5,
    )


async def get_or_connect_userbot(
    acc_id: int,
    session_str: str,
) -> TelegramClient | None:
    lock = _userbot_locks.setdefault(acc_id, asyncio.Lock())
    async with lock:
        client = active_clients.get(acc_id)
        if client:
            if not client.is_connected():
                await asyncio.wait_for(client.connect(), timeout=60)
            if await client.is_user_authorized():
                return client
            await client.disconnect()
            active_clients.pop(acc_id, None)

        client = _make_userbot_client(session_str)
        await asyncio.wait_for(client.connect(), timeout=60)
        if await client.is_user_authorized():
            active_clients[acc_id] = client
            return client

        await client.disconnect()
        return None


async def warmup_userbots() -> None:
    """Подключает все активные юзерботы заранее, чтобы код уходил мгновенно."""
    try:
        accounts = [a for a in await get_all_userbots() if a[4] == 1]
    except Exception:
        logger.exception("warmup: не удалось получить аккаунты")
        return
    for acc in accounts:
        acc_id, phone, session_str = acc[0], acc[1], acc[3]
        try:
            client = active_clients.get(acc_id)
            if client and client.is_connected():
                continue
            await get_or_connect_userbot(acc_id, session_str)
            logger.info("Юзербот %s подключён заранее.", phone)
        except Exception as e:
            logger.warning("warmup %s: %s", phone, e)


async def userbot_keepalive_loop() -> None:
    while True:
        await warmup_userbots()
        await asyncio.sleep(45)


async def send_from_single_account(
    acc: tuple,
    code: str,
) -> tuple[bool, str, TelegramClient | None]:
    acc_id, phone, full_name, session_str, _, _ = acc
    name = (
        f"{full_name} (<code>{phone}</code>)"
        if full_name
        else f"<code>{phone}</code>"
    )
    try:
        last_err: Exception | None = None
        for attempt in range(3):
            try:
                client = await get_or_connect_userbot(acc_id, session_str)
                if not client:
                    return False, f"❌ {name} — сессия истекла", None
                await asyncio.wait_for(
                    client.send_message(TARGET_BOT, str(code)), timeout=30
                )
                return True, name, client
            except (ConnectionError, asyncio.TimeoutError, OSError) as e:
                last_err = e
                logger.warning(
                    "Отправка с %s: попытка %d не удалась (%s)", phone, attempt + 1, e
                )
                bad = active_clients.pop(acc_id, None)
                if bad:
                    try:
                        await bad.disconnect()
                    except Exception:
                        pass
                await asyncio.sleep(1)
        raise last_err or ConnectionError("отправка не удалась")
    except Exception as e:
        logger.exception("Ошибка отправки с аккаунта %s", phone)
        return False, f"❌ {name} — ошибка: <code>{e}</code>", None


async def read_points(
    acc: tuple,
    client: TelegramClient,
    name: str,
) -> str:
    await asyncio.sleep(2.5)
    info = ""
    try:
        messages = await client.get_messages(TARGET_BOT, limit=2)
        for message in messages:
            if message.out or not message.text:
                continue

            match = re.search(
                r"Jami ballingiz:\s*(\d+)",
                message.text,
                re.IGNORECASE,
            )
            if match:
                points = match.group(1)
                info = f" | Баллов: <b>{points}</b>"
                async with aiosqlite.connect(DB_PATH, timeout=30) as db:
                    await db.execute("PRAGMA busy_timeout=30000")
                    await db.execute(
                        "UPDATE userbots SET last_points = ? WHERE id = ?",
                        (points, acc[0]),
                    )
                    await db.commit()
                break

            if "qabul qilindi" in message.text.lower():
                info = " | Принят"
                break
    except Exception as e:
        logger.warning("Не удалось прочитать ответ бота: %s", e)

    return f"✅ {name}{info}"


async def notify_admins(text: str):
    for admin_id in ADMIN_IDS:
        try:
            await bot.send_message(admin_id, text)
        except Exception as e:
            logger.error("Не удалось уведомить админа %s: %s", admin_id, e)


async def dispatch_code(code: str, method: str):
    accounts = [
        account
        for account in await get_all_userbots()
        if account[4] == 1
    ]

    if not accounts:
        await notify_admins(
            f"⚠️ Найден код <code>{code}</code> ({method}), но нет активных юзерботов!"
        )
        return

    owners = await get_owner_map()

    results = await asyncio.gather(
        *(send_from_single_account(account, code) for account in accounts),
        return_exceptions=True,
    )

    lines: list[str] = []
    per_account: list[tuple[tuple, str]] = []
    points_jobs: list[tuple[tuple, object]] = []
    ok_count = 0

    for account, result in zip(accounts, results):
        if isinstance(result, Exception):
            line = (
                f"❌ <code>{account[1]}</code> — ошибка: "
                f"<code>{html_escape(str(result))}</code>"
            )
            lines.append(line)
            per_account.append((account, line))
            continue

        ok, name, client = result
        if ok and client:
            ok_count += 1
            points_jobs.append((account, read_points(account, client, name)))
        else:
            lines.append(name)
            per_account.append((account, name))

    if points_jobs:
        points_results = await asyncio.gather(
            *(job[1] for job in points_jobs),
            return_exceptions=True,
        )
        for (account, _), result in zip(points_jobs, points_results):
            if isinstance(result, Exception):
                line = f"❌ Ошибка чтения баллов: <code>{html_escape(str(result))}</code>"
            else:
                line = result
            lines.append(line)
            per_account.append((account, line))

    await notify_admins(
        f"📡 <b>Код из эфира:</b> <code>{code}</code> ({method})\n"
        f"📊 Отправлено: <b>{ok_count} из {len(accounts)}</b> → @{TARGET_BOT}\n\n"
        + "\n".join(lines)
    )

    # Каждый пользователь получает результат только по своему аккаунту.
    for account, line in per_account:
        owner = owners.get(account[0])
        if owner and owner not in ADMIN_IDS:
            try:
                await bot.send_message(
                    owner,
                    f"🎯 <b>Код из эфира:</b> <code>{code}</code>\n{line}",
                )
            except Exception as e:
                logger.warning("Не удалось уведомить пользователя %s: %s", owner, e)


async def handle_detected_code(code: str, method: str):
    if await is_code_recently_sent(code):
        logger.info("Повторный код пропущен: %s", code)
        return

    await mark_code_sent(code, method)
    await dispatch_code(code, method)


# ============================================================
# BACKGROUND SCANNER
# ============================================================

async def stream_scanner_worker():
    global scanner_running
    global cached_m3u8

    logger.info("Сканер эфира запущен.")
    loop = asyncio.get_running_loop()
    last_warn = 0.0

    while scanner_running and not scanner_stop.is_set():
        await load_frame_interval()

        if not cached_m3u8:
            cached_m3u8 = await acquire_stream_url()

        if not scanner_running or scanner_stop.is_set():
            break

        if not cached_m3u8:
            scan_stats["last_error"] = "Не удалось получить ссылку .m3u8"
            if time.monotonic() - last_warn > 300:
                last_warn = time.monotonic()
                await notify_admins(
                    "⚠️ Не удалось получить ссылку <code>.m3u8</code>.\n"
                    "Проверьте URL, Cookies, Bearer Token и Proxy.\n"
                    "Повторяю попытку через 20 секунд."
                )
            await asyncio.sleep(20)
            continue

        proxy_url = await get_setting("proxy_url")
        cookies, _ = parse_itv_cookies(await get_setting("cookies"))
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())

        logger.info(
            "Подключение к потоку. Интервал анализа: %s сек.",
            frame_interval,
        )

        reason = await asyncio.to_thread(
            scan_stream_blocking,
            cached_m3u8,
            proxy_url,
            cookie_header,
            loop,
        )

        logger.warning("Чтение потока завершено: %s", reason)

        if not scanner_running or scanner_stop.is_set():
            break

        # При обрыве сбрасываем кэш .m3u8 (свежий токен/ссылка), кроме смены интервала
        if reason.startswith("интервал"):
            await asyncio.sleep(1)
            continue
        cached_m3u8 = None
        await asyncio.sleep(3)

    scan_stats["stream"] = False
    logger.info("Сканер эфира остановлен.")


# ============================================================
# FSM
# ============================================================

class AdminStates(StatesGroup):
    waiting_phone = State()
    waiting_code = State()
    waiting_2fa = State()

    waiting_source_url = State()
    waiting_cookies = State()
    waiting_token = State()
    waiting_proxy_url = State()

    waiting_custom_interval = State()


# ============================================================
# KEYBOARDS
# ============================================================

def admin_main_kb(
    is_scanning: bool,
    accounts_count: int,
    interval: float,
) -> InlineKeyboardMarkup:
    scan_btn = (
        InlineKeyboardButton(
            text="⏹ Остановить сканер эфира",
            callback_data="toggle_scan",
            style="danger",
        )
        if is_scanning
        else InlineKeyboardButton(
            text="▶️ Запустить сканер эфира",
            callback_data="toggle_scan",
            style="success",
        )
    )

    return InlineKeyboardMarkup(
        inline_keyboard=[
            [scan_btn],
            [
                InlineKeyboardButton(
                    text=f"👥 Юзерботы ({accounts_count})",
                    callback_data="manage_accounts",
                    style="primary",
                ),
                InlineKeyboardButton(
                    text="➕ Добавить аккаунт",
                    callback_data="add_account",
                    style="success",
                ),
            ],
            [
                InlineKeyboardButton(
                    text=f"⏱ Кадр каждые {interval:g} с",
                    callback_data="menu_interval",
                ),
                InlineKeyboardButton(
                    text="📸 Скриншот сайта",
                    callback_data="take_screenshot",
                    style="primary",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="🖼 Что видит сканер",
                    callback_data="last_frame",
                ),
                InlineKeyboardButton(
                    text="🔄 Обновить",
                    callback_data="back_main",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="🔗 URL канала / API",
                    callback_data="set_source_url",
                ),
                InlineKeyboardButton(
                    text="🌐 UZ Proxy URL",
                    callback_data="set_proxy_url",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="🍪 Cookies itv.uz",
                    callback_data="set_cookies",
                ),
                InlineKeyboardButton(
                    text="🔑 Bearer Token",
                    callback_data="set_token",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="📊 История кодов",
                    callback_data="history",
                ),
            ],
        ]
    )


def interval_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=f"{sec} с",
                    callback_data=f"set_int:{sec}",
                )
                for sec in ("1", "2", "3", "5", "10")
            ],
            [
                InlineKeyboardButton(
                    text="✏️ Свое значение (сек)",
                    callback_data="set_int_custom",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="⬅️ Назад",
                    callback_data="back_main",
                ),
            ],
        ]
    )


def accounts_list_kb(accounts: list) -> InlineKeyboardMarkup:
    rows = []
    for acc_id, phone, full_name, _, is_active, points in accounts:
        icon = "🟢" if is_active else "⏸"
        rows.append(
            [
                InlineKeyboardButton(
                    text=f"{icon} {full_name or phone} ({points} б.)",
                    callback_data=f"acc_toggle:{acc_id}",
                ),
                InlineKeyboardButton(
                    text="🗑",
                    callback_data=f"acc_del:{acc_id}",
                    style="danger",
                ),
            ]
        )

    rows.append(
        [
            InlineKeyboardButton(
                text="➕ Добавить еще аккаунт",
                callback_data="add_account",
                style="success",
            ),
        ]
    )
    rows.append(
        [
            InlineKeyboardButton(
                text="⬅️ Назад",
                callback_data="back_main",
            ),
        ]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def short(value: str, n: int = 32) -> str:
    return value[:n] + "..." if len(value) > n else (value or "Не задан")


# ============================================================
# ADMIN PANEL
# ============================================================

async def render_admin_panel(target: Message | CallbackQuery):
    accounts = await get_all_userbots()
    active_count = sum(1 for account in accounts if account[4] == 1)
    cookies, _ = parse_itv_cookies(await get_setting("cookies"))
    interval = await load_frame_interval()

    if scan_stats["last_frame_ts"]:
        age = int(time.time() - scan_stats["last_frame_ts"])
        frames_text = f"{scan_stats['frames']} шт., последний {age} с назад"
    else:
        frames_text = "пока нет"

    stream_text = "🟢 подключён" if scan_stats["stream"] else "🔴 нет соединения"
    error_text = (scan_stats.get("last_error") or "").strip()

    text = (
        "🎛 <b>Админ-панель: Milliy TV QR & OCR Сканер</b>\n\n"
        f"📡 <b>Сканер:</b> {'🟢 Активен' if scanner_running else '🔴 Остановлен'}\n"
        f"🎞 <b>Поток:</b> {stream_text}\n"
        f"🧮 <b>Кадров проанализировано:</b> {frames_text}\n"
        f"⏱ <b>Частота анализа:</b> каждые <b>{interval:g} с</b>\n"
        f"👥 <b>Юзерботов:</b> {active_count} из {len(accounts)}\n"
        f"🌐 <b>Proxy:</b> <code>{short(await get_setting('proxy_url'))}</code>\n"
        f"🔗 <b>Источник:</b> <code>{short(await get_setting('source_url'))}</code>\n"
        f"🍪 <b>Cookies:</b> {f'✅ ({len(cookies)} шт.)' if cookies else '❌'} | "
        f"🔑 <b>Token:</b> {'✅' if await get_setting('bearer_token') else '➖'}\n\n"
        f"🎯 <i>Ko'rish → Skip Ad → поток .m3u8 → QR, если нет — 4 цифры → @{TARGET_BOT}</i>"
    )

    if error_text:
        from html import escape as _esc
        text += f"\n\n⚠️ <b>Последняя ошибка:</b>\n<code>{_esc(short(error_text, 300))}</code>"

    keyboard = admin_main_kb(scanner_running, len(accounts), interval)

    if isinstance(target, Message):
        await target.answer(text, reply_markup=keyboard)
    else:
        try:
            await target.message.edit_text(text, reply_markup=keyboard)
        except TelegramBadRequest:
            if target.message.text is None:
                await target.message.answer(text, reply_markup=keyboard)


# ============================================================
# ADMIN FILTERS
# ============================================================

router.message.filter(
    lambda message: message.from_user is not None and is_admin(message.from_user.id)
)
router.callback_query.filter(
    lambda callback: is_admin(callback.from_user.id)
)


# ============================================================
# START
# ============================================================

@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    await render_admin_panel(message)


@router.callback_query(F.data == "back_main")
async def cb_back_main(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    await render_admin_panel(callback)
    await callback.answer()


# ============================================================
# START / STOP SCANNER
# ============================================================

@router.callback_query(F.data == "toggle_scan")
async def cb_toggle_scan(callback: CallbackQuery):
    global scanner_running
    global scanner_task
    global cached_m3u8

    if not scanner_running:
        accounts = await get_all_userbots()
        if not any(account[4] == 1 for account in accounts):
            await callback.answer(
                "Сначала добавьте активный юзербот!",
                show_alert=True,
            )
            return

        if not await get_setting("source_url"):
            await callback.answer(
                "Сначала задайте URL канала или .m3u8!",
                show_alert=True,
            )
            return

        if not API_ID or not API_HASH:
            await callback.answer(
                "Не заданы API_ID и API_HASH!",
                show_alert=True,
            )
            return

        if scanner_task and not scanner_task.done():
            await callback.answer(
                "Предыдущий цикл ещё завершается. Подождите 1–2 сек.",
                show_alert=True,
            )
            return

        try:
            normalize_proxy(await get_setting("proxy_url"))
        except ValueError as e:
            await callback.answer(str(e), show_alert=True)
            return

        scanner_stop.clear()
        scanner_running = True
        cached_m3u8 = None
        scan_stats["last_error"] = ""
        scanner_task = asyncio.create_task(stream_scanner_worker())
        await callback.answer("Сканер запущен!")
    else:
        scanner_running = False
        scanner_stop.set()
        await callback.answer("Останавливаю сканер...")

    await render_admin_panel(callback)


# ============================================================
# LAST FRAME
# ============================================================

@router.callback_query(F.data == "last_frame")
async def cb_last_frame(callback: CallbackQuery):
    jpg = scan_stats.get("last_jpeg")
    if not jpg:
        await callback.answer(
            "Кадров ещё нет — запустите сканер и подождите.",
            show_alert=True,
        )
        return

    age = int(time.time() - scan_stats["last_frame_ts"])
    await callback.message.answer_photo(
        BufferedInputFile(jpg, "last_frame.jpg"),
        caption=f"🖼 Последний кадр, который анализировал сканер ({age} с назад)",
    )
    await callback.answer()


# ============================================================
# PROXY
# ============================================================

@router.callback_query(F.data == "set_proxy_url")
async def cb_set_proxy_url(callback: CallbackQuery, state: FSMContext):
    await state.set_state(AdminStates.waiting_proxy_url)
    await callback.message.answer(
        f"🌐 Текущий прокси: <code>{await get_setting('proxy_url') or 'Не задан'}</code>\n\n"
        "Отправьте новый адрес (<code>http://host:port</code>) или <code>-</code> чтобы очистить:"
    )
    await callback.answer()


@router.message(AdminStates.waiting_proxy_url, F.text)
async def process_proxy_url(message: Message, state: FSMContext):
    global cached_m3u8
    value = message.text.strip()

    if value == "-":
        value = ""
    else:
        try:
            value = normalize_proxy(value)
        except ValueError as e:
            await message.answer(f"❌ {e}")
            return

    await set_setting("proxy_url", value)
    cached_m3u8 = None
    await state.clear()
    await message.answer("✅ Прокси сохранён. При следующем подключении будут применены новые настройки.")
    await render_admin_panel(message)


# ============================================================
# FRAME INTERVAL
# ============================================================

@router.callback_query(F.data == "menu_interval")
async def cb_menu_interval(callback: CallbackQuery):
    await callback.message.edit_text(
        f"⏱ <b>Как часто анализировать кадр</b>\n"
        f"Сейчас: <b>каждые {await load_frame_interval():g} с</b>\n"
        "Чем меньше интервал, тем меньше вероятность пропустить плашку, но выше нагрузка на CPU.",
        reply_markup=interval_kb(),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("set_int:"))
async def cb_set_int_preset(callback: CallbackQuery):
    sec = float(callback.data.split(":")[1])
    await set_setting("frame_interval", str(sec))
    await load_frame_interval()
    await callback.answer(f"Установлено: {sec:g} с")
    await render_admin_panel(callback)


@router.callback_query(F.data == "set_int_custom")
async def cb_set_int_custom(callback: CallbackQuery, state: FSMContext):
    await state.set_state(AdminStates.waiting_custom_interval)
    await callback.message.answer(
        "⏱ Введите интервал в секундах (от 0.5), например <code>1.5</code>:"
    )
    await callback.answer()


@router.message(AdminStates.waiting_custom_interval, F.text)
async def process_custom_interval(message: Message, state: FSMContext):
    try:
        sec = float(message.text.strip().replace(",", "."))
        if sec < 0.5 or sec > 600:
            raise ValueError
    except ValueError:
        await message.answer("❌ Введите число от 0.5 до 600:")
        return

    await set_setting("frame_interval", str(sec))
    await load_frame_interval()
    await state.clear()
    await message.answer(f"✅ Частота анализа: каждые <b>{sec:g} с</b>")
    await render_admin_panel(message)


# ============================================================
# WEBSITE SCREENSHOT
# ============================================================

@router.callback_query(F.data == "take_screenshot")
async def cb_take_screenshot(callback: CallbackQuery):
    source_url = (await get_setting("source_url")).strip()
    if not source_url:
        await callback.answer("Сначала укажите URL канала!", show_alert=True)
        return

    await callback.answer("Работаю...")
    status = await callback.message.answer("⏳ <b>Получаю кадр с ITV.uz...</b>\nЧерез прокси это может занять до 1–2 минут.")

    proxy_url = await get_setting("proxy_url")
    cookies, _ = parse_itv_cookies(await get_setting("cookies"))
    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())

    image_bytes = None
    method_text = ""
    frame = None
    web_shot = None

    # Если сканер работает и недавно получал кадр — берём его мгновенно.
    jpg = scan_stats.get("last_jpeg")
    age = time.time() - scan_stats["last_frame_ts"]
    if (
        jpg
        and scanner_running
        and scan_stats["stream"]
        and age <= max(frame_interval * 2, 45)
    ):
        frame = cv2.imdecode(np.frombuffer(jpg, np.uint8), cv2.IMREAD_COLOR)
        if frame is not None:
            image_bytes = jpg
            method_text = f"🎥 Кадр из эфира (сканер, {int(age)} с назад)"

    m3u8 = None
    if image_bytes is None:
        m3u8 = cached_m3u8 or await resolve_fresh_m3u8_url()

        if not m3u8 and source_url.lower().startswith(("http://", "https://")):
            web_shot, m3u8, steps = await browser_open_player(source_url)
            method_text = f"🌐 Chromium: {steps}"

    if m3u8:
        frame = await asyncio.to_thread(
            grab_single_frame,
            m3u8,
            proxy_url,
            cookie_header,
        )
        if frame is not None:
            ok, buffer = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 90])
            if ok:
                image_bytes = buffer.tobytes()
                method_text = "🎥 Живой кадр потока (.m3u8)"

    if image_bytes is None and web_shot:
        image_bytes = web_shot
        frame = cv2.imdecode(np.frombuffer(web_shot, np.uint8), cv2.IMREAD_COLOR)
        method_text += " | Скриншот Chromium (видеоплеер может отображаться чёрным)"

    if image_bytes is None:
        await status.edit_text(
            "❌ <b>Не удалось получить кадр.</b>\n\n"
            "Проверьте:\n"
            "• URL источника (или прямую ссылку <code>.m3u8</code>);\n"
            "• Cookies;\n"
            "• Bearer Token;\n"
            "• Proxy (включая доступ к TAS-IX / itv.uz)."
        )
        return

    code = None
    method = None
    banner = False

    if frame is not None:
        code, method = await asyncio.to_thread(analyze_frame, frame)
        banner = await asyncio.to_thread(banner_likely, frame)

    await status.delete()

    await callback.message.answer_photo(
        BufferedInputFile(image_bytes, "milliy_tv.jpg"),
        caption=(
            f"📸 <b>Снимок с сервера</b>\n"
            f"{method_text}\n"
            f"{'🟣 Плашка похоже в эфире' if banner else '⚪️ Плашки в кадре нет'}\n"
            f"{f'🎯 Код: <code>{code}</code> ({method})' if code else '🔍 Код в кадре не найден'}"
        ),
    )


# ============================================================
# USERBOTS
# ============================================================

@router.callback_query(F.data == "manage_accounts")
async def cb_manage_accounts(callback: CallbackQuery):
    await callback.message.edit_text(
        "👥 <b>Юзерботы</b>\n"
        "Нажмите на аккаунт, чтобы включить/выключить. Кнопка 🗑 удаляет аккаунт.",
        reply_markup=accounts_list_kb(await get_all_userbots()),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("acc_toggle:"))
async def cb_acc_toggle(callback: CallbackQuery):
    acc_id = int(callback.data.split(":")[1])
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        await db.execute(
            "UPDATE userbots SET is_active = 1 - is_active WHERE id = ?",
            (acc_id,),
        )
        await db.commit()

    await callback.message.edit_reply_markup(
        reply_markup=accounts_list_kb(await get_all_userbots())
    )
    await callback.answer("Готово")


@router.callback_query(F.data.startswith("acc_del:"))
async def cb_acc_del(callback: CallbackQuery):
    acc_id = int(callback.data.split(":")[1])
    client = active_clients.pop(acc_id, None)
    if client:
        try:
            await client.disconnect()
        except Exception as e:
            logger.warning("Ошибка отключения аккаунта: %s", e)

    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        await db.execute("DELETE FROM userbots WHERE id = ?", (acc_id,))
        await db.commit()

    await callback.message.edit_reply_markup(
        reply_markup=accounts_list_kb(await get_all_userbots())
    )
    await callback.answer("Удалено")


@router.callback_query(F.data == "add_account")
async def cb_add_account(callback: CallbackQuery, state: FSMContext):
    if not API_ID or not API_HASH:
        await callback.answer(
            "Задайте API_ID и API_HASH в переменных окружения.",
            show_alert=True,
        )
        return

    await state.set_state(AdminStates.waiting_phone)
    await callback.message.answer(
        "📱 Введите номер в формате <code>+998901234567</code>:"
    )
    await callback.answer()


# ============================================================
# TELETHON AUTHENTICATION
# ============================================================

@router.message(AdminStates.waiting_phone, F.text)
async def process_phone(message: Message, state: FSMContext):
    phone = message.text.strip().replace(" ", "")
    if not re.match(r"^\+\d{9,15}$", phone):
        await message.answer("❌ Формат: <code>+998901234567</code>")
        return

    msg = await message.answer("⏳ Запрашиваю код входа...")

    old = auth_clients.pop(message.from_user.id, None)
    if old:
        try:
            await old["client"].disconnect()
        except Exception:
            pass

    client = TelegramClient(StringSession(), API_ID, API_HASH)
    try:
        await client.connect()
        sent = await client.send_code_request(phone)
        auth_clients[message.from_user.id] = {
            "client": client,
            "phone": phone,
            "phone_code_hash": sent.phone_code_hash,
        }
        await state.set_state(AdminStates.waiting_code)
        await msg.edit_text(
            f"📩 Код отправлен на <code>{phone}</code>.\n"
            "Пришлите его с пробелом, например: <code>45 812</code>"
        )
    except Exception as e:
        await client.disconnect()
        await state.clear()
        logger.exception("Ошибка запроса кода Telegram.")
        await msg.edit_text(f"❌ Ошибка запроса кода: <code>{e}</code>")


@router.message(AdminStates.waiting_code, F.text)
async def process_code(message: Message, state: FSMContext):
    uid = message.from_user.id
    data = auth_clients.get(uid)
    if not data:
        await state.clear()
        await message.answer("⚠️ Сессия входа истекла. Нажмите /start.")
        return

    client = data["client"]
    try:
        await client.sign_in(
            phone=data["phone"],
            code=re.sub(r"\D", "", message.text),
            phone_code_hash=data["phone_code_hash"],
        )
        await finish_login(message, state, uid)
    except SessionPasswordNeededError:
        await state.set_state(AdminStates.waiting_2fa)
        await message.answer("🔐 Введите облачный пароль (2FA):")
    except (PhoneCodeInvalidError, PhoneCodeExpiredError):
        await message.answer("❌ Неверный или просроченный код. Введите ещё раз:")
    except Exception as e:
        logger.exception("Ошибка авторизации Telethon.")
        await client.disconnect()
        auth_clients.pop(uid, None)
        await state.clear()
        await message.answer(f"❌ Ошибка авторизации: <code>{e}</code>")


@router.message(AdminStates.waiting_2fa, F.text)
async def process_2fa(message: Message, state: FSMContext):
    uid = message.from_user.id
    password = message.text.strip()
    try:
        await message.delete()
    except Exception:
        pass

    data = auth_clients.get(uid)
    if not data:
        await state.clear()
        return

    try:
        await data["client"].sign_in(password=password)
        await finish_login(message, state, uid)
    except PasswordHashInvalidError:
        await message.answer("❌ Неверный пароль 2FA. Попробуйте снова:")
    except Exception as e:
        logger.exception("Ошибка 2FA.")
        await data["client"].disconnect()
        auth_clients.pop(uid, None)
        await state.clear()
        await message.answer(f"❌ Ошибка 2FA: <code>{e}</code>")


async def finish_login(message: Message, state: FSMContext, uid: int):
    data = auth_clients.pop(uid, None)
    if not data:
        await state.clear()
        return

    client = data["client"]
    full_name = ""
    try:
        me = await client.get_me()
        full_name = f"{me.first_name or ''} {me.last_name or ''}".strip()
        session_string = client.session.save()
        await add_or_update_userbot(data["phone"], full_name, session_string)
    finally:
        await client.disconnect()

    await state.clear()
    await message.answer(
        f"✅ <b>Юзербот добавлен:</b> {full_name} (<code>{data['phone']}</code>)"
    )
    await render_admin_panel(message)


# ============================================================
# SOURCE URL
# ============================================================

@router.callback_query(F.data == "set_source_url")
async def cb_set_source_url(callback: CallbackQuery, state: FSMContext):
    await state.set_state(AdminStates.waiting_source_url)
    await callback.message.answer(
        "🔗 Отправьте ссылку на плеер Milliy TV на <code>itv.uz</code> "
        "или прямую ссылку <code>https://...m3u8</code>:"
    )
    await callback.answer()


@router.message(AdminStates.waiting_source_url, F.text)
async def process_source_url(message: Message, state: FSMContext):
    global cached_m3u8
    url = message.text.strip()
    if not url.lower().startswith(("http://", "https://")):
        await message.answer("❌ Ссылка должна начинаться с http:// или https://")
        return

    await set_setting("source_url", url)
    cached_m3u8 = None
    await state.clear()
    await message.answer("✅ Источник сохранён!")
    await render_admin_panel(message)


# ============================================================
# COOKIES
# ============================================================

@router.callback_query(F.data == "set_cookies")
async def cb_set_cookies(callback: CallbackQuery, state: FSMContext):
    await state.set_state(AdminStates.waiting_cookies)
    await callback.message.answer(
        "🍪 Отправьте JSON-куки из Cookie-Editor (вкладка itv.uz) или строку формата <code>a=1; b=2</code>:"
    )
    await callback.answer()


@router.message(AdminStates.waiting_cookies, F.text)
async def process_cookies(message: Message, state: FSMContext):
    global cached_m3u8
    raw = message.text.strip()
    cookies, token = parse_itv_cookies(raw)

    try:
        await message.delete()
    except Exception:
        pass

    if not cookies:
        await message.answer(
            "⚠️ Не удалось распознать Cookies. Проверьте формат JSON или Cookie Header."
        )
        return

    await set_setting("cookies", raw)
    if token:
        await set_setting("bearer_token", token)

    cached_m3u8 = None
    await state.clear()
    await message.answer(f"✅ Cookies сохранены: <b>{len(cookies)}</b>")
    await render_admin_panel(message)


# ============================================================
# BEARER TOKEN
# ============================================================

@router.callback_query(F.data == "set_token")
async def cb_set_token(callback: CallbackQuery, state: FSMContext):
    await state.set_state(AdminStates.waiting_token)
    await callback.message.answer("🔑 Отправьте Bearer Token с itv.uz:")
    await callback.answer()


@router.message(AdminStates.waiting_token, F.text)
async def process_token(message: Message, state: FSMContext):
    global cached_m3u8
    token = message.text.strip()
    try:
        await message.delete()
    except Exception:
        pass

    await set_setting("bearer_token", token)
    cached_m3u8 = None
    await state.clear()
    await message.answer("✅ Token сохранён!")
    await render_admin_panel(message)


# ============================================================
# CODE HISTORY
# ============================================================

@router.callback_query(F.data == "history")
async def cb_history(callback: CallbackQuery):
    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        async with db.execute("""
            SELECT code, method, sent_at
            FROM sent_codes
            ORDER BY sent_at DESC
            LIMIT 15
        """) as cur:
            rows = await cur.fetchall()

    if not rows:
        await callback.answer("Кодов пока нет.", show_alert=True)
        return

    text = (
        "📋 <b>Последние коды:</b>\n\n"
        + "\n".join(
            f"• <code>{code}</code> ({method}) — {sent_at} UTC"
            for code, method, sent_at in rows
        )
    )
    await callback.message.answer(text)
    await callback.answer()


# ============================================================
# MANUAL PHOTO ANALYSIS
# ============================================================

@router.message(F.photo)
async def handle_manual_photo(message: Message):
    try:
        file = await bot.get_file(message.photo[-1].file_id)
        buffer = io.BytesIO()
        await bot.download_file(file.file_path, destination=buffer)

        frame = cv2.imdecode(
            np.frombuffer(buffer.getvalue(), np.uint8),
            cv2.IMREAD_COLOR,
        )
        if frame is None:
            await message.reply("⚠️ Не удалось прочитать изображение.")
            return

        code, method = await asyncio.to_thread(analyze_frame, frame)
        if not code:
            await message.reply("⚠️ Ни QR-код, ни 4 цифры не распознаны.")
            return

        if await is_code_recently_sent(code):
            await message.reply(f"⚠️ Код <code>{code}</code> уже отправлялся недавно.")
            return

        await mark_code_sent(code, f"{method} (вручную)")
        await message.reply(
            f"🎯 Распознан код <code>{code}</code> ({method}), отправляю..."
        )
        await dispatch_code(code, f"{method} (вручную)")

    except Exception as e:
        logger.exception("Ошибка ручного анализа фотографии.")
        await message.reply(f"❌ Ошибка анализа: <code>{e}</code>")


# ============================================================
# USER SELF-SERVICE: пользователи сами подключают свои аккаунты
# ============================================================

MAX_ACCOUNTS_PER_USER = int(os.getenv("MAX_ACCOUNTS_PER_USER", "2") or 2)
ALLOW_USER_SIGNUP = os.getenv("ALLOW_USER_SIGNUP", "1").strip().lower() not in (
    "0",
    "false",
    "no",
    "off",
)
CODE_REQUEST_COOLDOWN = 45
MAX_CODE_TRIES = 5

user_last_code_request: dict[int, float] = {}

USER_INTRO = (
    "👋 <b>Автоматизация кодов Milliy TV</b>\n\n"
    "Бот следит за эфиром и, когда появляется код, сам отправляет его "
    f"в @{TARGET_BOT} <b>от имени вашего аккаунта</b>. "
    "Баллы начисляются без ручного ввода.\n\n"
    "⚠️ <b>Что нужно знать перед подключением:</b>\n"
    "• Бот входит в ваш Telegram-аккаунт и хранит его сессию — это даёт доступ "
    "к аккаунту. Подключайте только свой аккаунт.\n"
    "• Пароль 2FA <b>нигде не сохраняется</b>.\n"
    f"• Сессия используется только для отправки кодов в @{TARGET_BOT}.\n"
    "• Владелец бота видит номер, имя и баллы подключённых аккаунтов.\n"
    "• Отключить можно в любой момент: «Мои аккаунты» → 🗑 "
    "(сессия будет завершена). Также можно закрыть её в Telegram: "
    "Настройки → Устройства.\n\n"
    "Нажимая кнопку ниже, вы соглашаетесь с этим."
)


class UserStates(StatesGroup):
    waiting_phone = State()
    waiting_code = State()
    waiting_2fa = State()


user_router.message.filter(
    lambda m: m.from_user is not None
    and not is_admin(m.from_user.id)
    and m.chat.type == "private"
)
user_router.callback_query.filter(
    lambda c: not is_admin(c.from_user.id)
    and c.message is not None
    and c.message.chat.type == "private"
)


def user_main_kb(has_accounts: bool) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton(
                text="✅ Согласен, подключить аккаунт",
                callback_data="u_add",
            )
        ]
    ]
    if has_accounts:
        rows.append(
            [InlineKeyboardButton(text="👤 Мои аккаунты", callback_data="u_list")]
        )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def phone_request_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text="📱 Отправить мой номер", request_contact=True)]],
        resize_keyboard=True,
        one_time_keyboard=True,
        input_field_placeholder="+998901234567",
    )


async def drop_auth_client(uid: int):
    data = auth_clients.pop(uid, None)
    if data:
        await safe_disconnect(data["client"])


async def render_user_accounts(uid: int) -> tuple[str, InlineKeyboardMarkup]:
    rows = await get_user_accounts(uid)
    if not rows:
        return (
            "У вас пока нет подключённых аккаунтов.",
            user_main_kb(False),
        )

    keyboard = []
    for acc_id, phone, full_name, is_active, points in rows:
        icon = "🟢" if is_active else "⏸"
        keyboard.append(
            [
                InlineKeyboardButton(
                    text=f"{icon} {full_name or phone} ({points} б.)",
                    callback_data=f"u_tog:{acc_id}",
                ),
                InlineKeyboardButton(text="🗑", callback_data=f"u_del:{acc_id}"),
            ]
        )
    if ALLOW_USER_SIGNUP and len(rows) < MAX_ACCOUNTS_PER_USER:
        keyboard.append(
            [InlineKeyboardButton(text="➕ Добавить аккаунт", callback_data="u_add")]
        )

    text = (
        "👤 <b>Мои аккаунты</b>\n"
        "Нажмите на аккаунт, чтобы поставить на паузу или включить.\n"
        "🗑 — отключить аккаунт и завершить сессию бота."
    )
    return text, InlineKeyboardMarkup(inline_keyboard=keyboard)


# ---------- команды ----------

@user_router.message(CommandStart())
async def user_start(message: Message, state: FSMContext):
    uid = message.from_user.id
    await drop_auth_client(uid)
    await state.clear()

    count = await count_user_accounts(uid)
    if not ALLOW_USER_SIGNUP and count == 0:
        await message.answer("🔒 Подключение новых аккаунтов сейчас закрыто.")
        return

    await message.answer(USER_INTRO, reply_markup=user_main_kb(count > 0))


@user_router.message(Command("cancel"))
async def user_cancel(message: Message, state: FSMContext):
    await drop_auth_client(message.from_user.id)
    await state.clear()
    await message.answer(
        "Отменено. Нажмите /start, чтобы начать заново.",
        reply_markup=ReplyKeyboardRemove(),
    )


@user_router.message(Command("accounts"))
async def user_accounts_cmd(message: Message, state: FSMContext):
    await state.clear()
    text, kb = await render_user_accounts(message.from_user.id)
    await message.answer(text, reply_markup=kb)


# ---------- подключение аккаунта ----------

@user_router.callback_query(F.data == "u_add")
async def user_add(callback: CallbackQuery, state: FSMContext):
    uid = callback.from_user.id

    if not ALLOW_USER_SIGNUP:
        await callback.answer("Подключение сейчас закрыто.", show_alert=True)
        return
    if not API_ID or not API_HASH:
        await callback.answer("Бот временно не принимает аккаунты.", show_alert=True)
        return
    if await count_user_accounts(uid) >= MAX_ACCOUNTS_PER_USER:
        await callback.answer(
            f"Лимит аккаунтов: {MAX_ACCOUNTS_PER_USER}.",
            show_alert=True,
        )
        return

    await state.set_state(UserStates.waiting_phone)
    await callback.message.answer(
        "📱 Отправьте номер телефона аккаунта — кнопкой ниже или текстом "
        "в формате <code>+998901234567</code>.\n"
        "Отмена — /cancel",
        reply_markup=phone_request_kb(),
    )
    await callback.answer()


async def safe_disconnect(client: TelegramClient):
    try:
        await asyncio.wait_for(client.disconnect(), timeout=10)
    except Exception:
        pass


async def replace_status(status: Message, message: Message, text: str, **kwargs):
    """Удаляет статус «Запрашиваю...» и присылает новое сообщение (без edit)."""
    try:
        await status.delete()
    except Exception:
        pass
    await message.answer(text, **kwargs)


async def user_request_code(message: Message, state: FSMContext, phone: str):
    uid = message.from_user.id

    wait = CODE_REQUEST_COOLDOWN - (
        time.monotonic() - user_last_code_request.get(uid, -1e9)
    )
    if wait > 0:
        await message.answer(f"⏳ Подождите {int(wait) + 1} с и отправьте номер снова.")
        return
    user_last_code_request[uid] = time.monotonic()

    status = await message.answer("⏳ Запрашиваю код входа...")
    await drop_auth_client(uid)

    client = TelegramClient(
        StringSession(),
        API_ID,
        API_HASH,
        flood_sleep_threshold=0,  # FloodWait сразу как ошибка, а не молчаливое ожидание
        request_retries=2,
        connection_retries=2,
        timeout=10,
    )

    try:
        logger.info("[user %s] connect", uid)
        await asyncio.wait_for(client.connect(), timeout=30)
        logger.info("[user %s] send_code_request %s", uid, phone)
        sent = await asyncio.wait_for(client.send_code_request(phone), timeout=45)
        logger.info("[user %s] код запрошен", uid)
    except FloodWaitError as e:
        await safe_disconnect(client)
        await state.clear()
        await replace_status(
            status, message,
            f"❌ Telegram просит подождать {e.seconds} с. Попробуйте позже: /start",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    except PhoneNumberInvalidError:
        await safe_disconnect(client)
        await state.clear()
        await replace_status(
            status, message,
            "❌ Неверный номер телефона. Нажмите /start и попробуйте снова.",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    except asyncio.TimeoutError:
        await safe_disconnect(client)
        await state.clear()
        logger.warning("[user %s] таймаут запроса кода", uid)
        await replace_status(
            status, message,
            "❌ Telegram не ответил вовремя. Попробуйте ещё раз: /start",
            reply_markup=ReplyKeyboardRemove(),
        )
        return
    except Exception as e:
        await safe_disconnect(client)
        await state.clear()
        logger.exception("[user %s] ошибка запроса кода Telegram.", uid)
        await replace_status(
            status, message,
            f"❌ Не удалось запросить код ({type(e).__name__}). Попробуйте ещё раз: /start",
            reply_markup=ReplyKeyboardRemove(),
        )
        return

    # Код уже отправлен — сначала сохраняем сессию входа и состояние,
    # и только потом сообщаем пользователю (сбой отправки не должен ломать вход).
    auth_clients[uid] = {
        "client": client,
        "phone": phone,
        "phone_code_hash": sent.phone_code_hash,
        "tries": 0,
    }
    await state.set_state(UserStates.waiting_code)

    try:
        await replace_status(
            status, message,
            f"📩 Код отправлен в Telegram на аккаунт <code>{phone}</code> "
            "(чат «Telegram» или SMS).\n\n"
            "Отправьте его <b>с пробелами между цифрами</b>, например "
            "<code>1 2 3 4 5</code> — иначе Telegram может аннулировать код.\n"
            "Отмена — /cancel",
            reply_markup=ReplyKeyboardRemove(),
        )
        logger.info("[user %s] ожидаю код", uid)
    except Exception:
        logger.exception("[user %s] не удалось отправить инструкцию.", uid)


@user_router.message(UserStates.waiting_phone, F.contact)
async def user_phone_contact(message: Message, state: FSMContext):
    contact = message.contact
    if contact.user_id != message.from_user.id:
        await message.answer("❌ Нужно отправить именно свой номер (кнопка ниже).")
        return

    phone = contact.phone_number.strip().replace(" ", "")
    if not phone.startswith("+"):
        phone = "+" + phone
    await user_request_code(message, state, phone)


@user_router.message(UserStates.waiting_phone, F.text)
async def user_phone_text(message: Message, state: FSMContext):
    phone = message.text.strip().replace(" ", "").replace("-", "")
    if not re.fullmatch(r"\+\d{9,15}", phone):
        await message.answer("❌ Формат: <code>+998901234567</code> (или /cancel)")
        return
    await user_request_code(message, state, phone)


async def user_abort_login(message: Message, state: FSMContext, uid: int, text: str):
    await drop_auth_client(uid)
    await state.clear()
    await message.answer(text, reply_markup=ReplyKeyboardRemove())


@user_router.message(UserStates.waiting_code, F.text)
async def user_code(message: Message, state: FSMContext):
    uid = message.from_user.id
    data = auth_clients.get(uid)
    if not data:
        await state.clear()
        await message.answer("⚠️ Сессия входа истекла. Нажмите /start.")
        return

    digits = re.sub(r"\D", "", message.text)
    try:
        await message.delete()  # код не должен оставаться в чате
    except Exception:
        pass

    if not digits:
        await message.answer("❌ Отправьте код цифрами, например <code>1 2 3 4 5</code>.")
        return

    client = data["client"]
    try:
        await client.sign_in(
            phone=data["phone"],
            code=digits,
            phone_code_hash=data["phone_code_hash"],
        )
        await user_finish_login(message, state, uid)
    except SessionPasswordNeededError:
        await state.set_state(UserStates.waiting_2fa)
        await message.answer(
            "🔐 На аккаунте включён облачный пароль (2FA). Введите его — "
            "сообщение будет сразу удалено, пароль не сохраняется:"
        )
    except PhoneCodeInvalidError:
        data["tries"] += 1
        if data["tries"] >= MAX_CODE_TRIES:
            await user_abort_login(
                message, state, uid, "❌ Слишком много неверных кодов. Начните заново: /start"
            )
            return
        await message.answer("❌ Неверный код. Введите ещё раз (или /cancel):")
    except PhoneCodeExpiredError:
        await user_abort_login(
            message, state, uid, "⌛ Код просрочен. Начните заново: /start"
        )
    except Exception:
        logger.exception("Ошибка авторизации Telethon (пользователь %s).", uid)
        await user_abort_login(
            message, state, uid, "❌ Ошибка авторизации. Начните заново: /start"
        )


@user_router.message(UserStates.waiting_2fa, F.text)
async def user_2fa(message: Message, state: FSMContext):
    uid = message.from_user.id
    password = message.text.strip()
    try:
        await message.delete()  # пароль не должен оставаться в чате
    except Exception:
        pass

    data = auth_clients.get(uid)
    if not data:
        await state.clear()
        await message.answer("⚠️ Сессия входа истекла. Нажмите /start.")
        return

    try:
        await data["client"].sign_in(password=password)
        await user_finish_login(message, state, uid)
    except PasswordHashInvalidError:
        data["tries"] += 1
        if data["tries"] >= MAX_CODE_TRIES:
            await user_abort_login(
                message, state, uid, "❌ Слишком много неверных паролей. Начните заново: /start"
            )
            return
        await message.answer("❌ Неверный пароль 2FA. Попробуйте снова (или /cancel):")
    except Exception:
        logger.exception("Ошибка 2FA (пользователь %s).", uid)
        await user_abort_login(
            message, state, uid, "❌ Ошибка входа. Начните заново: /start"
        )


async def user_finish_login(message: Message, state: FSMContext, uid: int):
    data = auth_clients.pop(uid, None)
    if not data:
        await state.clear()
        return

    client = data["client"]
    full_name = ""
    try:
        me = await client.get_me()
        full_name = f"{me.first_name or ''} {me.last_name or ''}".strip()
        session_string = client.session.save()
        await add_or_update_userbot(data["phone"], full_name, session_string, owner_id=uid)
    finally:
        await client.disconnect()

    await state.clear()
    await message.answer(
        f"✅ <b>Аккаунт подключён:</b> {html_escape(full_name)} (<code>{data['phone']}</code>)\n\n"
        f"Когда в эфире появится код, бот отправит его в @{TARGET_BOT} от вашего имени "
        "и пришлёт вам результат.\n"
        "Управление: /accounts",
        reply_markup=ReplyKeyboardRemove(),
    )

    username = f"@{message.from_user.username}" if message.from_user.username else "—"
    await notify_admins(
        f"👤 Пользователь <code>{uid}</code> ({html_escape(username)}) подключил аккаунт: "
        f"{html_escape(full_name)} (<code>{data['phone']}</code>)"
    )


# ---------- управление своими аккаунтами ----------

@user_router.callback_query(F.data == "u_list")
async def user_list(callback: CallbackQuery):
    text, kb = await render_user_accounts(callback.from_user.id)
    try:
        await callback.message.edit_text(text, reply_markup=kb)
    except TelegramBadRequest:
        pass
    await callback.answer()


@user_router.callback_query(F.data.startswith("u_tog:"))
async def user_toggle(callback: CallbackQuery):
    uid = callback.from_user.id
    acc_id = int(callback.data.split(":")[1])

    async with aiosqlite.connect(DB_PATH, timeout=30) as db:
        await db.execute("PRAGMA busy_timeout=30000")
        await db.execute(
            "UPDATE userbots SET is_active = 1 - is_active WHERE id = ? AND owner_id = ?",
            (acc_id, uid),
        )
        await db.commit()

    text, kb = await render_user_accounts(uid)
    try:
        await callback.message.edit_text(text, reply_markup=kb)
    except TelegramBadRequest:
        pass
    await callback.answer("Готово")


@user_router.callback_query(F.data.startswith("u_del:"))
async def user_delete(callback: CallbackQuery):
    uid = callback.from_user.id
    acc_id = int(callback.data.split(":")[1])

    row = await get_userbot(acc_id)
    if not row or row[6] != uid:  # чужой аккаунт трогать нельзя
        await callback.answer("Аккаунт не найден.", show_alert=True)
        return

    # Завершаем сессию бота на стороне Telegram.
    client = None
    try:
        client = await get_or_connect_userbot(acc_id, row[3])
        if client:
            await client.log_out()
    except Exception as e:
        logger.warning("Не удалось завершить сессию аккаунта %s: %s", acc_id, e)
        if client:
            try:
                await client.disconnect()
            except Exception:
                pass
    finally:
        active_clients.pop(acc_id, None)

    await delete_userbot(acc_id)

    text, kb = await render_user_accounts(uid)
    try:
        await callback.message.edit_text(text, reply_markup=kb)
    except TelegramBadRequest:
        pass
    await callback.answer("Аккаунт отключён")


@user_router.message()
async def user_fallback(message: Message):
    await message.answer(
        "Нажмите /start, чтобы подключить аккаунт, или /accounts — управление аккаунтами."
    )


# ============================================================
# SHUTDOWN
# ============================================================

async def shutdown():
    global scanner_running
    logger.info("Завершение работы приложения.")
    scanner_running = False
    scanner_stop.set()

    if scanner_task and not scanner_task.done():
        try:
            await asyncio.wait_for(scanner_task, timeout=25)
        except asyncio.TimeoutError:
            logger.warning("Сканер не завершился за 25 секунд.")
            scanner_task.cancel()
            try:
                await scanner_task
            except asyncio.CancelledError:
                pass

    for uid, data in list(auth_clients.items()):
        try:
            await data["client"].disconnect()
        except Exception:
            pass
        auth_clients.pop(uid, None)

    for acc_id, client in list(active_clients.items()):
        try:
            await client.disconnect()
        except Exception:
            pass
        active_clients.pop(acc_id, None)

    logger.info("Все Telethon-соединения закрыты.")


# ============================================================
# MAIN
# ============================================================

async def main():
    if not BOT_TOKEN:
        raise SystemExit("Задайте BOT_TOKEN в переменных окружения.")
    if not ADMIN_IDS:
        raise SystemExit("Задайте ADMIN_IDS в переменных окружения.")
    if not API_ID or not API_HASH:
        logger.warning(
            "API_ID или API_HASH не заданы. Авторизация новых Telethon-аккаунтов будет недоступна."
        )

    logger.info("Запуск MilliyScannerPro.")
    logger.info("OpenCV: %s", cv2.__version__)

    build_info = cv2.getBuildInformation()
    logger.info(
        "FFmpeg backend: %s",
        build_info.split("Video I/O:")[1].split("\n\n")[0]
        if "Video I/O:" in build_info
        else "информация недоступна",
    )

    await init_db()
    await load_frame_interval()

    keepalive_task = asyncio.create_task(userbot_keepalive_loop())
    try:
        await dp.start_polling(bot, close_bot_session=False)
    finally:
        keepalive_task.cancel()
        await shutdown()
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Приложение остановлено.")
