"""Ankah's command-line proof-of-work solver. Python 3 standard library only."""

import hashlib
import http.cookiejar
import math
import os
from pathlib import Path
import sys
import time
import urllib.parse
import urllib.request


MESSAGES = {
    "invalid_challenge": (
        "invalid challenge", "チャレンジが無効です", "desafío no válido"),
    "unsupported_difficulty": (
        "unsupported difficulty", "難易度に対応していません", "dificultad no compatible"),
    "progress": (
        "\r{0} guesses  {1}/s  {2}% chance of success by now",
        "\r試行 {0} 回  毎秒 {1} 回  現時点の成功確率 {2}%",
        "\r{0} intentos  {1}/s  {2}% de probabilidad de éxito hasta ahora"),
    "search_exhausted": (
        "search exhausted", "探索範囲を使い切りました", "se agotó la búsqueda"),
    "usage": (
        "usage: solver.py ORIGIN CHALLENGE [LANGUAGE]",
        "使用方法: solver.py ORIGIN CHALLENGE [LANGUAGE]",
        "uso: solver.py ORIGIN CHALLENGE [LANGUAGE]"),
    "https_required": (
        "challenge origin must use HTTPS",
        "チャレンジの送信元には HTTPS が必要です",
        "el origen del desafío debe usar HTTPS"),
    "network_error": (
        "could not complete the challenge",
        "チャレンジを完了できませんでした",
        "no se pudo completar el desafío"),
    "found": (
        "Found answer {0}; requesting pass...",
        "回答 {0} が見つかりました。通行許可を取得しています...",
        "Se encontró la respuesta {0}; solicitando el pase..."),
    "saved": (
        "Pass saved to {0}",
        "通行許可を {0} に保存しました",
        "Pase guardado en {0}"),
    "retry_curl": (
        "Retry your original request with: curl -b '{0}' URL",
        "元のリクエストを再試行: curl -b '{0}' URL",
        "Reintenta la solicitud original con: curl -b '{0}' URL"),
    "retry_wget": (
        "Or: wget --load-cookies='{0}' URL",
        "または: wget --load-cookies='{0}' URL",
        "O bien: wget --load-cookies='{0}' URL"),
}


def message(language, key):
    return MESSAGES[key][{"en": 0, "ja": 1, "es": 2}.get(language, 0)]


def number(value, language, precision=0):
    result = f"{value:,.{precision}f}"
    return result.replace(",", "X").replace(".", ",").replace("X", ".") if language == "es" else result


def solve(challenge, language="en"):
    pieces = challenge.split(".")
    if len(pieces) != 4 or len(pieces[0]) != 32:
        raise ValueError(message(language, "invalid_challenge"))
    nonce = pieces[0]
    try:
        bits = int(pieces[2])
    except ValueError as error:
        raise ValueError(message(language, "invalid_challenge")) from error
    if bits < 8 or bits > 24:
        raise ValueError(message(language, "unsupported_difficulty"))
    full, remainder = divmod(bits, 8)
    started = time.monotonic()
    next_report = started + 0.25
    for counter in range(1 << 35):
        digest = hashlib.sha256(f"{nonce}:{counter}".encode("ascii")).digest()
        if all(byte == 0 for byte in digest[:full]) and (
            remainder == 0 or digest[full] >> (8 - remainder) == 0
        ):
            return counter
        now = time.monotonic()
        if now >= next_report:
            guesses = counter + 1
            rate = guesses / max(now - started, 0.001)
            chance = -math.expm1(-guesses / (2**bits)) * 100
            print(
                message(language, "progress").format(
                    number(guesses, language), number(rate, language),
                    number(chance, language, 1)),
                end="" if sys.stderr.isatty() else "\n",
                file=sys.stderr,
                flush=True,
            )
            next_report = now + (0.25 if sys.stderr.isatty() else 5)
    raise RuntimeError(message(language, "search_exhausted"))


def main():
    language = sys.argv[3] if len(sys.argv) == 4 and sys.argv[3] in ("en", "ja", "es") else "en"
    if len(sys.argv) not in (3, 4):
        raise ValueError(message(language, "usage"))
    origin, challenge = sys.argv[1:3]
    parsed = urllib.parse.urlsplit(origin)
    if not parsed.hostname or (
        parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}
        )
    ):
        raise ValueError(message(language, "https_required"))
    counter = solve(challenge, language)
    if sys.stderr.isatty():
        print(file=sys.stderr)
    print(message(language, "found").format(number(counter, language)), file=sys.stderr)
    old_mask = os.umask(0o077)
    try:
        directory = Path.home() / ".ankah"
        directory.mkdir(mode=0o700, exist_ok=True)
        host = parsed.hostname.replace(".", "_")
        cookie_path = directory / f"{host}.cookies"
        jar = http.cookiejar.MozillaCookieJar(str(cookie_path))
        if cookie_path.exists():
            jar.load(ignore_discard=True, ignore_expires=True)
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        query = urllib.parse.urlencode({"challenge": challenge, "answer": counter})
        request = urllib.request.Request(
            origin.rstrip("/") + "/ankah/open?" + query,
            data=b"",
            method="POST",
        )
        with opener.open(request, timeout=20) as response:
            response.read()
        jar.save(ignore_discard=True, ignore_expires=True)
    finally:
        os.umask(old_mask)
    print(message(language, "saved").format(cookie_path))
    print(message(language, "retry_curl").format(cookie_path))
    print(message(language, "retry_wget").format(cookie_path))


if __name__ == "__main__":
    try:
        main()
    except OSError as error:
        language = sys.argv[3] if len(sys.argv) == 4 else "en"
        print(f"Ankah: {message(language, 'network_error')}: {error}", file=sys.stderr)
        raise SystemExit(1)
    except (ValueError, RuntimeError) as error:
        print(f"Ankah: {error}", file=sys.stderr)
        raise SystemExit(1)
