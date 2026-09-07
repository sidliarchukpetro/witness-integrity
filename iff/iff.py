#!/usr/bin/env python3
"""
iff.py — свій-чужий на захищеному елементі.

Опитувач кидає випадковий виклик. Відповідач підписує його ключем, що
живе в кремнії й ніколи не покидає чип. Опитувач перевіряє підпис за
реєстром довірених елементів.

Чужий — це не той, хто не вміє підписати. Чужий — це той, кого немає в
реєстрі, навіть якщо в нього свій справний елемент і бездоганний підпис.

    python3 iff.py responder --once     # підписати один виклик
    python3 iff.py selftest             # три сценарії на живому чипі
    python3 iff.py registry-add         # внести цей елемент у реєстр

Виклики cryptoauthlib не пишуться тут наново — беруться з sign.py, який
відпрацював на цих чипах.
"""

from __future__ import annotations

import json
import os
import sys
import time

REGISTRY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "iff_registry.json")
CHALLENGE_BYTES = 32


# ----------------------------------------------------------- реєстр

def load_registry(path: str = REGISTRY) -> dict[str, str]:
    """serial(hex) -> pubkey(hex). Реєстр — це церемонія, не автоматика."""
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return {k.lower(): v.lower() for k, v in json.load(f).items()}


def save_registry(reg: dict[str, str], path: str = REGISTRY) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=2, sort_keys=True)


# --------------------------------------------------------- опитувач

def make_challenge() -> bytes:
    """32 випадкові байти. Кожен раз нові — інакше відповідь можна повторити."""
    return os.urandom(CHALLENGE_BYTES)


def verify_response(challenge: bytes, response: dict,
                    registry: dict[str, str]) -> dict:
    """
    Вердикт опитувача. Програмна перевірка — приймальній стороні чип не
    потрібен, тільки ключ із реєстру.
    """
    from verify import verify_signature

    res = {
        "serial": response.get("serial", ""),
        "in_registry": False,
        "signature_valid": False,
        "key_matches_registry": False,
        "verdict": "ЧУЖИЙ",
        "reason": "",
    }

    serial = response.get("serial", "").lower()
    pub_hex = response.get("pubkey", "").lower()
    sig_hex = response.get("signature", "")

    if not (serial and pub_hex and sig_hex):
        res["reason"] = "неповна відповідь"
        return res

    # 1. чи є такий елемент у реєстрі
    if serial not in registry:
        res["reason"] = "елемента немає в реєстрі"
        return res
    res["in_registry"] = True

    # 2. чи той самий ключ, що записаний за цим елементом
    if registry[serial] != pub_hex:
        res["reason"] = "ключ не збігається з реєстровим"
        return res
    res["key_matches_registry"] = True

    # 3. чи підпис справді покриває наш виклик
    try:
        ok = verify_signature(challenge, bytes.fromhex(sig_hex),
                              bytes.fromhex(pub_hex))
    except Exception as e:
        res["reason"] = f"перевірка не виконалась: {e}"
        return res

    res["signature_valid"] = ok
    if not ok:
        res["reason"] = "підпис не покриває цей виклик"
        return res

    res["verdict"] = "СВІЙ"
    return res


# -------------------------------------------------------- відповідач

class Responder:
    """Той, хто доводить. Йому потрібен чип."""

    def __init__(self):
        import sign
        sign._init()
        self._sign = sign
        self.serial = sign.device_serial()
        self.pubkey = sign.public_key()

    def answer(self, challenge: bytes) -> dict:
        if len(challenge) != CHALLENGE_BYTES:
            raise ValueError(f"виклик має бути {CHALLENGE_BYTES} байтів")
        sig = self._sign.sign_digest(challenge)
        return {
            "serial": self.serial.hex(),
            "pubkey": self.pubkey.hex(),
            "signature": sig.hex(),
        }


# ------------------------------------------------------- сценарії

def _line(label: str, res: dict, ms: float | None = None) -> None:
    mark = "✓" if res["verdict"] == "СВІЙ" else "✗"
    t = f"   {ms:.0f} мс" if ms is not None else ""
    print(f"  {mark} {label:<34} {res['verdict']}{t}")
    if res["reason"]:
        print(f"      причина: {res['reason']}")


def selftest() -> None:
    print("\n=== СВІЙ-ЧУЖИЙ НА ЗАХИЩЕНОМУ ЕЛЕМЕНТІ ===\n")

    r = Responder()
    print(f"  елемент відповідача   {r.serial.hex()}")
    print(f"  ключ у слоті 0        {r.pubkey.hex()[:32]}…")

    registry = load_registry()
    if r.serial.hex().lower() not in registry:
        print(f"\n  УВАГА: цього елемента немає в реєстрі {REGISTRY}")
        print(f"  внести:  python3 iff.py registry-add\n")
    print(f"  у реєстрі елементів: {len(registry)}")

    print("\n  --- 1. свій ---")
    ch = make_challenge()
    t0 = time.perf_counter()
    resp = r.answer(ch)
    sign_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    res = verify_response(ch, resp, registry)
    ver_ms = (time.perf_counter() - t0) * 1000
    _line("елемент з реєстру, свіжий виклик", res, sign_ms + ver_ms)
    print(f"      підпис у кремнії {sign_ms:.0f} мс, перевірка {ver_ms:.1f} мс")

    print("\n  --- 2. чужий: елемент не в реєстрі ---")
    ch2 = make_challenge()
    resp2 = dict(r.answer(ch2))
    resp2["serial"] = "00" * 9          # справний підпис, невідомий елемент
    _line("бездоганний підпис, чужий елемент", verify_response(ch2, resp2, registry))

    print("\n  --- 3. чужий: ключ підмінено ---")
    ch3 = make_challenge()
    resp3 = dict(r.answer(ch3))
    bad = bytearray(bytes.fromhex(resp3["pubkey"]))
    bad[0] ^= 0x01
    resp3["pubkey"] = bad.hex()
    _line("ключ не збігається з реєстровим", verify_response(ch3, resp3, registry))

    print("\n  --- 4. повтор старої відповіді ---")
    ch_old = make_challenge()
    resp_old = r.answer(ch_old)
    ch_new = make_challenge()           # новий виклик, стара відповідь
    _line("валідна відповідь на інший виклик",
          verify_response(ch_new, resp_old, registry))

    print("\n  --- 5. зіпсований підпис ---")
    ch5 = make_challenge()
    resp5 = dict(r.answer(ch5))
    s = bytearray(bytes.fromhex(resp5["signature"]))
    s[10] ^= 0x01
    resp5["signature"] = s.hex()
    _line("один байт підпису змінено", verify_response(ch5, resp5, registry))

    print("\n  Свій — лише той, хто є в реєстрі і підписав ЦЕЙ виклик")
    print("  ключем, який не покидає кремній.\n")


def registry_add() -> None:
    r = Responder()
    reg = load_registry()
    serial = r.serial.hex().lower()
    reg[serial] = r.pubkey.hex().lower()
    save_registry(reg)
    print(f"внесено {serial} -> {r.pubkey.hex()[:32]}…")
    print(f"реєстр: {REGISTRY} ({len(reg)} елементів)")


def responder_once() -> None:
    """Читає виклик (hex) зі stdin, друкує відповідь у JSON."""
    r = Responder()
    line = sys.stdin.readline().strip()
    ch = bytes.fromhex(line)
    print(json.dumps(r.answer(ch), sort_keys=True))


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "selftest"
    if cmd == "selftest":
        selftest()
    elif cmd == "registry-add":
        registry_add()
    elif cmd == "responder":
        responder_once()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
