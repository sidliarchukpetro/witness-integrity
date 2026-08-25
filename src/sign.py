#!/usr/bin/env python3
"""
sign.py — підпис свідчення в захищеному елементі.

Виклики cryptoauthlib узяті з робочого `sign_test.py`, який відпрацював на
цьому чипі, а не з пам'яті. Це не педантизм: провізіонування й API
захищеного елемента — рутина, яку легко пам'ятати неправильно, а помилка
тут незворотна.

ЩО ТУТ РОБИТЬСЯ І В ЯКОМУ ПОРЯДКУ

    1. перевірка внутрішньої узгодженості   <- ДО підпису
    2. канонізація
    3. SHA-256 канонічної форми
    4. підпис відбитка слотом 0 ATECC608B
    5. складання запису: свідчення + підпис + публічний ключ

Крок 1 стоїть першим навмисно. Підпис доводить авторство, не істину:
свідчення, у якому кадрів у ядрі більше, ніж кадрів усього, буде
підписане бездоганно й лишиться безглуздим. Тому несуперечність
перевіряється до того, як чип щось підпише.

ЧОГО ТУТ НЕМАЄ

Немає нічого, що пише в чип: ні genkey, ні provision, ні lock. Слот 0
цього чипа вже містить ключ, зони замкнені незворотно 02.07. Все, що
робиться, — читання публічного ключа й підпис. Незворотних операцій нема.

    python3 sign.py            # самоперевірка на живому чипі
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from witness import Witness, check_consistency

I2C_BUS = 1
SIGN_SLOT = 0          # слот 0 — підписний ключ; слот 1 — ECDH, не тут


class SignError(Exception):
    pass


# ------------------------------------------------------------------ чип

def _init():
    from cryptoauthlib import cfg_ateccx08a_i2c_default, atcab_init
    cfg = cfg_ateccx08a_i2c_default()
    cfg.cfg.atcai2c.bus = I2C_BUS
    if atcab_init(cfg) != 0:
        raise SignError("не вдалось відкрити захищений елемент")


def device_serial() -> bytes:
    from cryptoauthlib import atcab_read_serial_number
    sn = bytearray(9)
    if atcab_read_serial_number(sn) != 0:
        raise SignError("не читається серійник")
    return bytes(sn)


def public_key() -> bytes:
    from cryptoauthlib import atcab_get_pubkey
    pub = bytearray(64)
    if atcab_get_pubkey(SIGN_SLOT, pub) != 0:
        raise SignError(f"слот {SIGN_SLOT} не віддає публічний ключ")
    return bytes(pub)


def sign_digest(digest: bytes) -> bytes:
    if len(digest) != 32:
        raise SignError(f"відбиток має бути 32 байти, а не {len(digest)}")
    from cryptoauthlib import atcab_sign
    sig = bytearray(64)
    if atcab_sign(SIGN_SLOT, digest, sig) != 0:
        raise SignError("чип відмовився підписати")
    return bytes(sig)


def verify_extern(digest: bytes, sig: bytes, pub: bytes) -> bool:
    """
    Вердикт про підпис виносить сам чип.

    Межа, названа в протоколі 12.08 і чинна тут: ключ передається
    параметром, тобто код теоретично може підсунути свій. На цих чипах
    шлях із ключем усередині слота закритий конфігурацією назавжди.
    Для приймальної сторони це не проблема — вона перевіряє програмно,
    маючи ключ із реєстру пристроїв.
    """
    from cryptoauthlib import atcab_verify_extern, AtcaReference
    ok = AtcaReference(False)
    if atcab_verify_extern(digest, sig, pub, ok) != 0:
        raise SignError("виклик перевірки не виконався")
    return bool(ok.value)


# --------------------------------------------------------------- запис

@dataclass
class SignedWitness:
    """Те, що йде в чергу й далі в ефір."""
    witness: dict
    digest_hex: str
    signature_hex: str
    pubkey_hex: str
    serial_hex: str
    signed_at_ms: int

    def to_json(self) -> str:
        return json.dumps({
            "witness": self.witness,
            "digest": self.digest_hex,
            "signature": self.signature_hex,
            "pubkey": self.pubkey_hex,
            "serial": self.serial_hex,
            "signed_at_ms": self.signed_at_ms,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def from_json(s: str) -> "SignedWitness":
        d = json.loads(s)
        return SignedWitness(
            witness=d["witness"],
            digest_hex=d["digest"],
            signature_hex=d["signature"],
            pubkey_hex=d["pubkey"],
            serial_hex=d["serial"],
            signed_at_ms=d["signed_at_ms"],
        )


class Signer:
    """
    Тримає відкритий чип і публічний ключ. Ключ читається один раз:
    він не міняється, а кожне читання — це обмін по шині.
    """

    def __init__(self):
        _init()
        self.serial = device_serial()
        self.pubkey = public_key()

    def sign(self, w: Witness) -> SignedWitness:
        check_consistency(w)          # блокує підпис безглуздого
        digest = w.digest()
        sig = sign_digest(digest)
        return SignedWitness(
            witness=w.to_dict(),
            digest_hex=digest.hex(),
            signature_hex=sig.hex(),
            pubkey_hex=self.pubkey.hex(),
            serial_hex=self.serial.hex(),
            signed_at_ms=int(time.time() * 1000),
        )


# ------------------------------------------------------- самоперевірка

def selftest():
    print("\n=== ПІДПИС СВІДЧЕННЯ В КРЕМНІЇ ===\n")
    s = Signer()
    print(f"  елемент   {s.serial.hex()}")
    print(f"  слот {SIGN_SLOT}    {s.pubkey.hex()[:32]}…")

    w = Witness(
        device_id=int.from_bytes(s.serial[:8], "big"),
        session_id=1,
        epoch_start_ms=int(time.time() * 1000) - 20000,
        epoch_end_ms=int(time.time() * 1000),
        core_freq_mhz=604000, core_spread_mhz=8000,
        frames_total=79, frames_saturated=0,
        frames_with_series=79, frames_in_core=79, longest_run=79,
        band_snr_mdb=41600, flatness_milli=26, harmonics_found=4,
        bg_tones_mhz=[60000, 118000, 172000],
        temp_mc=21500, humidity_milli=520, pressure_pa=99800,
    )

    t0 = time.perf_counter()
    sw = s.sign(w)
    dt = (time.perf_counter() - t0) * 1000

    print(f"\n  канонічна форма   {len(w.canonical())} байтів")
    print(f"  відбиток          {sw.digest_hex[:32]}…")
    print(f"  підпис            {sw.signature_hex[:32]}…")
    print(f"  час підпису       {dt:.0f} мс")
    print(f"  запис у JSON      {len(sw.to_json())} байтів")

    print("\n  --- перевірка на боці чипа ---")
    dg = bytes.fromhex(sw.digest_hex)
    sg = bytes.fromhex(sw.signature_hex)
    print(f"  дійсний підпис          {verify_extern(dg, sg, s.pubkey)}")

    bad_sig = bytearray(sg)
    bad_sig[10] ^= 0x01
    print(f"  зіпсований байт підпису {verify_extern(dg, bytes(bad_sig), s.pubkey)}")

    bad_dg = bytearray(dg)
    bad_dg[0] ^= 0x01
    print(f"  інший відбиток          {verify_extern(bytes(bad_dg), sg, s.pubkey)}")

    print("\n  --- підпис недетермінований (ECDSA) ---")
    a = sign_digest(dg).hex()
    b = sign_digest(dg).hex()
    print(f"  два підписи того самого відбитка різні: {a != b}")
    print("  обидва дійсні:",
          verify_extern(dg, bytes.fromhex(a), s.pubkey)
          and verify_extern(dg, bytes.fromhex(b), s.pubkey))

    print("\n  --- підпис безглуздого блокується ---")
    from witness import Inconsistent
    w.frames_in_core = 999
    try:
        s.sign(w)
        print("  ПРОПУЩЕНО (погано)")
    except Inconsistent as e:
        print(f"  заблоковано до підпису: {e}")

    print()


if __name__ == "__main__":
    selftest()
