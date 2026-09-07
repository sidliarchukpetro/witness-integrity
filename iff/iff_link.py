#!/usr/bin/env python3
"""
iff_link.py — опитувач: Raspberry Pi питає ESP32 по послідовному порту.

Pi сам генерує виклик, шле його пристрою, приймає підпис і виносить
вердикт за реєстром. Нічого не копіюється руками: підпис народжується в
кремнії одного пристрою і перевіряється іншим.

    python3 iff_link.py                 # три сценарії
    python3 iff_link.py --port /dev/ttyACM0
"""

from __future__ import annotations

import argparse
import sys
import time

import iff

DEFAULT_PORT = "/dev/ttyACM0"
BAUD = 115200


def open_port(port: str, baud: int = BAUD):
    try:
        import serial
    except ImportError:
        sys.exit("немає pyserial:  pip install pyserial")
    s = serial.Serial(port, baud, timeout=3)
    time.sleep(0.3)
    s.reset_input_buffer()
    return s


def ask(ser, challenge: bytes) -> tuple[dict, float]:
    """Надіслати виклик, зібрати відповідь пристрою."""
    ser.write(b"\n")          # добити хвіст у буфері пристрою
    ser.flush()
    time.sleep(0.25)
    ser.reset_input_buffer()
    ser.write(challenge.hex().encode() + b"\n")
    ser.flush()

    resp, device_ms = {}, None
    t0 = time.perf_counter()
    deadline = t0 + 5.0

    while time.perf_counter() < deadline:
        raw = ser.readline()
        if not raw:
            continue
        line = raw.decode(errors="ignore").strip()
        if line.startswith("SERIAL"):
            resp["serial"] = line.split()[1]
        elif line.startswith("PUBKEY"):
            resp["pubkey"] = line.split()[1]
        elif line.startswith("SIG"):
            resp["signature"] = line.split()[1]
        elif line.startswith("MS"):
            device_ms = float(line.split()[1])
            break
        elif line.startswith("ERR"):
            raise RuntimeError(line)

    if "signature" not in resp:
        raise RuntimeError("пристрій не відповів")
    return resp, (time.perf_counter() - t0) * 1000


def show(label: str, res: dict, extra: str = "") -> None:
    mark = "✓" if res["verdict"] == "СВІЙ" else "✗"
    print(f"  {mark} {label:<38} {res['verdict']}  {extra}")
    if res["reason"]:
        print(f"      причина: {res['reason']}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=DEFAULT_PORT)
    args = ap.parse_args()

    registry = iff.load_registry()
    print("\n=== СВІЙ-ЧУЖИЙ: ДВА ПРИСТРОЇ, ДВА ЗАХИЩЕНІ ЕЛЕМЕНТИ ===\n")
    print(f"  опитувач    Raspberry Pi (перевіряє програмно, чипа не потребує)")
    print(f"  відповідач  ESP32-S3 на {args.port} (підписує в кремнії)")
    print(f"  у реєстрі   {len(registry)} елементів")

    ser = open_port(args.port)

    # прогрів: перший виклик cryptography тягне бібліотеку і спотворює час
    _ser, _pub = next(iter(registry.items()))
    iff.verify_response(iff.make_challenge(),
                        {"serial": _ser, "pubkey": _pub, "signature": "00" * 64},
                        registry)

    print("\n  --- 1. свій ---")
    ch = iff.make_challenge()
    print(f"  виклик згенеровано: {ch.hex()[:32]}…")
    resp, rt = ask(ser, ch)
    print(f"  відповів елемент:   {resp['serial']}")
    t0 = time.perf_counter()
    res = iff.verify_response(ch, resp, registry)
    ver_ms = (time.perf_counter() - t0) * 1000
    show("елемент з реєстру, свіжий виклик", res,
         f"{rt:.0f} мс обмін, {ver_ms:.1f} мс перевірка")

    print("\n  --- 2. чужий: елемента немає в реєстрі ---")
    ch2 = iff.make_challenge()
    resp2, _ = ask(ser, ch2)
    resp2 = dict(resp2)
    resp2["serial"] = "00" * 9
    show("бездоганний підпис, чужий елемент",
         iff.verify_response(ch2, resp2, registry))

    print("\n  --- 3. повтор старої відповіді ---")
    ch_old = iff.make_challenge()
    resp_old, _ = ask(ser, ch_old)
    ch_new = iff.make_challenge()
    show("валідна відповідь на інший виклик",
         iff.verify_response(ch_new, resp_old, registry))

    ser.close()
    print("\n  Підпис народився в кремнії ESP32 і перевірений на Pi.")
    print("  Свій — лише той, хто є в реєстрі і підписав ЦЕЙ виклик.\n")


if __name__ == "__main__":
    main()
