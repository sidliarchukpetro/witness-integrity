#!/usr/bin/env python3
"""
verify.py — приймальна сторона. Перевіряє підпис і ПЕРЕРАХОВУЄ вердикт.

Заради цього все й будувалось.

Вузол не каже «ціль». Вузол каже «ось що я виміряв», підписує ці числа в
кремнії й віддає. Приймальна сторона робить дві незалежні речі:

    1. перевіряє, що числа не підмінені    -> підпис
    2. виносить вердикт із цих чисел сама  -> перерахунок

Перше доводить авторство. Друге доводить, що висновок випливає з показів,
а не з довіри до пристрою. Підпис без перерахунку дав би незаперечний
запис невідомо чого; перерахунок без підпису — красивий висновок з чисел,
які міг підмінити будь-хто дорогою.

ЧОМУ ПЕРЕВІРКА ТУТ ПРОГРАМНА, А НЕ НА ЧИПІ

Приймальна сторона не має захищеного елемента й не повинна мати. Її
задача зворотна до задачі вузла: не берегти таємницю, а перевірити чуже
свідчення. Для цього потрібен лише публічний ключ, і перевірка робиться
звичайною криптографією.

Це також означає, що перевірити може БУДЬ-ХТО — маючи запис і реєстр
відомих ключів. Ніякого привілейованого становища в оператора немає.

РЕЄСТР ПРИСТРОЇВ

Публічний ключ, доданий у сам запис, нічого не доводить: підробник
підпише своїм ключем і покладе поруч свій же публічний. Ключ мусить
звірятися з реєстром, заповненим при розгортанні. Без реєстру перевірка
підпису перевіряє лише внутрішню несуперечність запису.

    python3 verify.py record.json                  # перевірити запис
    python3 verify.py record.json --registry r.json
    python3 verify.py --selftest
"""

from __future__ import annotations

import json
import sys

from witness import (Inconsistent, Witness, check_consistency, verdict,
                     VERDICT_RULE_VERSION)


class VerifyError(Exception):
    pass


# --------------------------------------------------------------- підпис

def verify_signature(digest: bytes, sig: bytes, pub_raw: bytes) -> bool:
    """
    ECDSA P-256 програмно.

    ATECC віддає підпис як 64 сирі байти (r||s) і ключ як 64 байти (x||y).
    `cryptography` очікує підпис у DER і ключ як точку — обидва треба
    зібрати. Це те місце, де мовчазна помилка дає «підпис недійсний» на
    цілком дійсному підписі, тому формати складаються явно.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.exceptions import InvalidSignature

    if len(pub_raw) != 64:
        raise VerifyError(f"публічний ключ {len(pub_raw)} байтів, треба 64")
    if len(sig) != 64:
        raise VerifyError(f"підпис {len(sig)} байтів, треба 64")

    pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(pub_raw[:32], "big"),
        int.from_bytes(pub_raw[32:], "big"),
        ec.SECP256R1(),
    ).public_key()

    der = utils.encode_dss_signature(
        int.from_bytes(sig[:32], "big"),
        int.from_bytes(sig[32:], "big"),
    )

    try:
        pub.verify(der, digest, ec.ECDSA(utils.Prehashed(
            __import__("cryptography.hazmat.primitives.hashes",
                       fromlist=["SHA256"]).SHA256())))
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------- реєстр

def load_registry(path: str | None) -> dict[str, str]:
    """
    Реєстр: серійник елемента -> публічний ключ, обидва в hex.

    Заповнюється при розгортанні, коли пристрій фізично в руках. Це
    церемонія, а не автоматика: сенс реєстру в тому, що хтось відповідальний
    підтвердив, який ключ якому пристрою належить.
    """
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    return {k.lower(): v.lower() for k, v in d.items()}


# --------------------------------------------------------------- розбір

def check_record(rec: dict, registry: dict[str, str] | None = None) -> dict:
    """
    Повний розбір запису. Повертає результат кожної перевірки окремо —
    щоб було видно не «добре чи погано», а що саме зійшлось, а що ні.
    """
    res = {
        "serial": rec.get("serial", ""),
        "in_registry": None,
        "key_matches_registry": None,
        "digest_matches": False,
        "signature_valid": False,
        "consistent": False,
        "consistency_error": None,
        "verdict": None,
        "verdict_why": [],
        "node_claimed": rec.get("claimed_verdict"),
        "agrees_with_node": None,
    }

    # 1. Свідчення з запису -> та сама канонізація -> той самий відбиток.
    #    Якщо не збігається, числа правились після підпису.
    try:
        w = Witness.from_dict(rec["witness"])
    except Exception as e:
        raise VerifyError(f"свідчення не розбирається: {e}")

    digest = w.digest()
    res["digest_matches"] = digest.hex() == rec.get("digest", "").lower()

    # 2. Підпис під цим відбитком.
    pub_raw = bytes.fromhex(rec["pubkey"])
    sig = bytes.fromhex(rec["signature"])
    res["signature_valid"] = verify_signature(digest, sig, pub_raw)

    # 3. Чи цей ключ узагалі наш.
    if registry:
        serial = res["serial"].lower()
        res["in_registry"] = serial in registry
        if res["in_registry"]:
            res["key_matches_registry"] = (
                registry[serial] == rec["pubkey"].lower())

    # 4. Внутрішня несуперечність — незалежно від підпису.
    try:
        check_consistency(w)
        res["consistent"] = True
    except Inconsistent as e:
        res["consistency_error"] = str(e)

    # 5. Перерахунок вердикту з підписаних ознак.
    #
    #    Тільки якщо числа несуперечливі. Рахувати вердикт із запису, де
    #    кадрів у ядрі більше, ніж усього, означає видати висновок із
    #    даних, які не могли існувати. Раніше тут рахувалось завжди, і
    #    свідчення з 999 кадрами в ядрі з 79 отримувало бадьоре ЦІЛЬ.
    if res["consistent"]:
        v, why = verdict(w)
        res["verdict"] = v
        res["verdict_why"] = why
        if res["node_claimed"] is not None:
            res["agrees_with_node"] = (v == res["node_claimed"])
    else:
        res["verdict"] = "НЕ РАХУЄТЬСЯ"
        res["verdict_why"] = ["числа суперечливі, вердикт не обчислюється"]

    return res


def trusted(res: dict, require_registry: bool = True) -> bool:
    """
    Чи можна брати це свідчення до відома.

    Розбіжність між заявленим вузлом і перерахованим тут ЗАБОРОНЯЄ довіру,
    навіть коли підпис бездоганний. Дійсний підпис під хибним висновком —
    гірший випадок за підроблений запис: він означає, що справний на вигляд
    вузол видає неправду, і причина невідома (інша версія правил,
    пошкоджена прошивка, підміна логіки).

    Раніше тут цього не було: сценарій, де вузол заявив ЦІЛЬ при -3.2 дБ
    над фоном, отримував «до відома: ТАК» разом із виявленою розбіжністю.
    """
    if not (res["digest_matches"] and res["signature_valid"]
            and res["consistent"]):
        return False
    if res["agrees_with_node"] is False:
        return False
    if require_registry:
        if not res["in_registry"] or not res["key_matches_registry"]:
            return False
    return True


def report(res: dict, require_registry: bool = True) -> None:
    def mark(v):
        return "так " if v is True else ("НІ  " if v is False else "—   ")

    print(f"\n  елемент            {res['serial']}")
    print(f"  відбиток збігається {mark(res['digest_matches'])}"
          "  (числа не правились після підпису)")
    print(f"  підпис дійсний      {mark(res['signature_valid'])}")
    if res["in_registry"] is None:
        print("  реєстр              не заданий — походження не перевірене")
    else:
        print(f"  є в реєстрі         {mark(res['in_registry'])}")
        print(f"  ключ той самий      {mark(res['key_matches_registry'])}")
    print(f"  несуперечливе       {mark(res['consistent'])}"
          + (f"  ({res['consistency_error']})"
             if res["consistency_error"] else ""))

    print(f"\n  ВЕРДИКТ (перерахований тут): {res['verdict']}")
    for r in res["verdict_why"]:
        print(f"    · {r}")
    if res["agrees_with_node"] is not None:
        print(f"\n  вузол заявляв: {res['node_claimed']}")
        if res["agrees_with_node"]:
            print("  збігається — свідчення й висновок узгоджені")
        else:
            print("  РОЗБІЖНІСТЬ: вузол і перерахунок дійшли різного.")
            print("  Або в вузла інші правила, або запис правлений.")

    ok = trusted(res, require_registry)
    print(f"\n  до відома: {'ТАК' if ok else 'НІ'}\n")


# ---------------------------------------------------------- самоперевірка

def selftest():
    """
    Працює без чипа: підпис робиться програмним ключем. Перевіряється
    сама логіка приймальної сторони, а не залізо.
    """
    import time
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes

    print("\n=== ПРИЙМАЛЬНА СТОРОНА: САМОПЕРЕВІРКА ===")
    print(f"  версія правила вердикту: {VERDICT_RULE_VERSION}")

    priv = ec.generate_private_key(ec.SECP256R1())
    n = priv.public_key().public_numbers()
    pub_raw = n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")
    serial = "01236c9ec37928f6ee"

    def make(**over):
        base = dict(
            device_id=0x01236C9EC37928F6, session_id=1,
            epoch_start_ms=1787577600000, epoch_end_ms=1787577620000,
            core_freq_mhz=604000, core_spread_mhz=8000,
            frames_total=79, frames_saturated=0, frames_with_series=79,
            frames_in_core=79, longest_run=79, band_snr_mdb=41600,
            flatness_milli=26, harmonics_found=4,
            bg_tones_mhz=[60000, 118000, 172000],
            temp_mc=21500, humidity_milli=520, pressure_pa=99800)
        base.update(over)
        return Witness(**base)

    def sign_sw(w, claimed=None, key=priv, pk=pub_raw):
        dg = w.digest()
        der = key.sign(dg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        rec = {"witness": w.to_dict(), "digest": dg.hex(),
               "signature": raw.hex(), "pubkey": pk.hex(),
               "serial": serial, "signed_at_ms": int(time.time() * 1000)}
        if claimed:
            rec["claimed_verdict"] = claimed
        return rec

    registry = {serial: pub_raw.hex()}

    print("\n--- 1. чесний запис ---")
    report(check_record(sign_sw(make(), claimed="ЦІЛЬ"), registry))

    print("--- 2. числа правлені після підпису ---")
    rec = sign_sw(make())
    rec["witness"]["band_snr_mdb"] = 99000     # накрутили рівень
    report(check_record(rec, registry))

    print("--- 3. підписано чужим ключем ---")
    other = ec.generate_private_key(ec.SECP256R1())
    on = other.public_key().public_numbers()
    other_raw = on.x.to_bytes(32, "big") + on.y.to_bytes(32, "big")
    report(check_record(sign_sw(make(), key=other, pk=other_raw), registry))

    print("--- 4. вузол заявив ЦІЛЬ, а ознаки цього не дають ---")
    weak = make(core_freq_mhz=170000, core_spread_mhz=2000,
                frames_with_series=40, frames_in_core=40, longest_run=40,
                band_snr_mdb=-3200)
    report(check_record(sign_sw(weak, claimed="ЦІЛЬ"), registry))

    print("--- 5. підписане, але внутрішньо безглузде ---")
    bad = make()
    bad.frames_in_core = 999          # обійшли перевірку вузла
    report(check_record(sign_sw(bad), registry))


def main():
    if "--selftest" in sys.argv or len(sys.argv) < 2:
        selftest()
        return
    path = sys.argv[1]
    reg_path = None
    if "--registry" in sys.argv:
        reg_path = sys.argv[sys.argv.index("--registry") + 1]
    with open(path, encoding="utf-8") as f:
        rec = json.load(f)
    report(check_record(rec, load_registry(reg_path)),
           require_registry=bool(reg_path))


if __name__ == "__main__":
    main()
