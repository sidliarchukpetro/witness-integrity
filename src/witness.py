#!/usr/bin/env python3
"""
witness.py — канонічна форма свідчення. Ці байти підписуються в кремнії.

ЩО ПІДПИСУЄТЬСЯ І ЧОМУ САМЕ ЦЕ

Вузол підписує ОЗНАКИ, не вердикт. Різниця принципова.

Підписаний вердикт «ЦІЛЬ» перевірити неможливо — лишається вірити
пристрою на слово. Підписані ознаки дають перерахунок: приймальна сторона
бере ті самі числа, застосовує ті самі правила й отримує той самий
висновок. Розбіжність означає, що хтось із двох помиляється, і це видно.

Це те саме, що зроблено в InfraVeritas з боку енергетики: агрегатор
публікує знімок усіх входів вердикту, і будь-хто перераховує сам. Підпис
доводить авторство, перерахунок доводить істину.

КАНОНІЗАЦІЯ

Підписується не структура, а конкретна послідовність байтів. Дві сторони
мусять отримати ту саму послідовність з тих самих даних, інакше підпис не
зійдеться. Тому:

  - порядок полів фіксований, не алфавітний і не за словником;
  - усі числа цілі, у визначених одиницях (мГц, мілідекибели, мілісекунди);
  - жодних чисел з рухомою комою: 0.1 + 0.2 на двох платформах може дати
    різні байти;
  - довжина кожного поля фіксована, big-endian;
  - рядків немає взагалі.

Урок з IPAS: канонізація має бути в ОДНОМУ місці й братись обома
сторонами звідти. Дві реалізації однієї канонізації розходяться —
сьогодні вже втретє за тиждень наступили на копію, що розійшлася з
оригіналом.

ВЕРСІЯ СХЕМИ

schema_version у першому байті. Будь-яка зміна складу полів — новий
номер. Стара версія має лишатись читабельною: свідчення, підписані вчора,
не мусять ставати недійсними завтра.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

SCHEMA_VERSION = 1

# Одиниці — цілі, щоб канонізація була детермінованою
# частота       мГц (мілігерци):      616.0 Гц  -> 616000
# рівень        мдБ (мілідецибели):   +41.6 дБ  -> 41600
# тональність   тисячні:              0.026     -> 26
# час           мс від епохи Unix


@dataclass
class Witness:
    """
    Одне свідчення. Усе, з чого приймальна сторона перерахує вердикт.

    Кожне поле тут існує тому, що воно входить у правило вердикту. Якщо
    поле не потрібне для перерахунку — його тут бути не повинно: зайве
    поле це зайвий байт у кожному пакеті й зайва можливість розійтись.
    """

    device_id: int                  # хто свідчить
    session_id: int                 # номер сеансу спостереження
    epoch_start_ms: int             # початок вікна спостереження
    epoch_end_ms: int               # кінець вікна

    # --- що виміряно ---
    core_freq_mhz: int              # ядро основного тону, мГц
    core_spread_mhz: int            # розкид ядра між кадрами, мГц
    frames_total: int               # усього кадрів у вікні
    frames_saturated: int           # відкинуто через перевантаження
    frames_with_series: int         # кадрів, де знайдено ряд гармонік
    frames_in_core: int             # з них лягли в ядро
    longest_run: int                # найдовша безперервна низка
    band_snr_mdb: int               # рівень смуги кандидата над фоном, мдБ
    flatness_milli: int             # плоскість спектру в смузі, тисячні
    harmonics_found: int            # скільки кратних стоять у спектрі

    # --- у яких умовах ---
    bg_tones_mhz: list[int] = field(default_factory=list)  # тони позиції
    temp_mc: int = 0                # температура, мілі-°C (BME280)
    humidity_milli: int = 0         # вологість, тисячні частки
    pressure_pa: int = 0            # тиск, Па

    def canonical(self) -> bytes:
        """
        Байти, які підписуються. Порядок фіксований назавжди.

        Список фонових тонів сортується перед серіалізацією: він
        описує МНОЖИНУ частот позиції, а не послідовність, і порядок
        виявлення не повинен впливати на підпис.
        """
        out = bytearray()
        out += struct.pack(">B", SCHEMA_VERSION)
        out += struct.pack(">Q", self.device_id)
        out += struct.pack(">Q", self.session_id)
        out += struct.pack(">Q", self.epoch_start_ms)
        out += struct.pack(">Q", self.epoch_end_ms)

        out += struct.pack(">I", self.core_freq_mhz)
        out += struct.pack(">I", self.core_spread_mhz)
        out += struct.pack(">H", self.frames_total)
        out += struct.pack(">H", self.frames_saturated)
        out += struct.pack(">H", self.frames_with_series)
        out += struct.pack(">H", self.frames_in_core)
        out += struct.pack(">H", self.longest_run)
        out += struct.pack(">i", self.band_snr_mdb)      # знаковий
        out += struct.pack(">H", self.flatness_milli)
        out += struct.pack(">B", self.harmonics_found)

        tones = sorted(self.bg_tones_mhz)
        out += struct.pack(">B", len(tones))
        for t in tones:
            out += struct.pack(">I", t)

        out += struct.pack(">i", self.temp_mc)           # знаковий, мороз
        out += struct.pack(">H", self.humidity_milli)
        out += struct.pack(">I", self.pressure_pa)
        return bytes(out)

    def digest(self) -> bytes:
        """SHA-256 канонічної форми. Саме він іде в ATECC на підпис."""
        return hashlib.sha256(self.canonical()).digest()

    # ------------------------------------------------------------ службове

    def to_dict(self) -> dict:
        """Для передачі й зберігання. Канонізація з цього відтворюється."""
        return {
            "schema_version": SCHEMA_VERSION,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "epoch_start_ms": self.epoch_start_ms,
            "epoch_end_ms": self.epoch_end_ms,
            "core_freq_mhz": self.core_freq_mhz,
            "core_spread_mhz": self.core_spread_mhz,
            "frames_total": self.frames_total,
            "frames_saturated": self.frames_saturated,
            "frames_with_series": self.frames_with_series,
            "frames_in_core": self.frames_in_core,
            "longest_run": self.longest_run,
            "band_snr_mdb": self.band_snr_mdb,
            "flatness_milli": self.flatness_milli,
            "harmonics_found": self.harmonics_found,
            "bg_tones_mhz": sorted(self.bg_tones_mhz),
            "temp_mc": self.temp_mc,
            "humidity_milli": self.humidity_milli,
            "pressure_pa": self.pressure_pa,
        }

    @staticmethod
    def from_dict(d: dict) -> "Witness":
        if d.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(
                f"схема {d.get('schema_version')}, очікується {SCHEMA_VERSION}")
        return Witness(
            device_id=d["device_id"],
            session_id=d["session_id"],
            epoch_start_ms=d["epoch_start_ms"],
            epoch_end_ms=d["epoch_end_ms"],
            core_freq_mhz=d["core_freq_mhz"],
            core_spread_mhz=d["core_spread_mhz"],
            frames_total=d["frames_total"],
            frames_saturated=d["frames_saturated"],
            frames_with_series=d["frames_with_series"],
            frames_in_core=d["frames_in_core"],
            longest_run=d["longest_run"],
            band_snr_mdb=d["band_snr_mdb"],
            flatness_milli=d["flatness_milli"],
            harmonics_found=d["harmonics_found"],
            bg_tones_mhz=list(d.get("bg_tones_mhz", [])),
            temp_mc=d.get("temp_mc", 0),
            humidity_milli=d.get("humidity_milli", 0),
            pressure_pa=d.get("pressure_pa", 0),
        )


# ---------------------------------------------------------------- перевірки
# Внутрішня узгодженість — ДО підпису, не після.
#
# Урок з IPAS дослівно: підпис доводить авторство, не істину. Якщо
# підписати свідчення, у якому кадрів у ядрі більше, ніж кадрів усього, —
# підпис буде дійсний, а свідчення безглузде. Тому перевірка тут, і вона
# блокує підпис, а не супроводжує його.

class Inconsistent(Exception):
    pass


def check_consistency(w: Witness) -> None:
    if w.epoch_end_ms <= w.epoch_start_ms:
        raise Inconsistent("кінець вікна не пізніше за початок")
    if w.frames_saturated > w.frames_total:
        raise Inconsistent("перевантажених кадрів більше, ніж усього")
    good = w.frames_total - w.frames_saturated
    if w.frames_with_series > good:
        raise Inconsistent("кадрів із рядом більше, ніж придатних")
    if w.frames_in_core > w.frames_with_series:
        raise Inconsistent("у ядрі більше кадрів, ніж із рядом")
    if w.longest_run > w.frames_in_core:
        raise Inconsistent("низка довша за кількість кадрів у ядрі")
    if w.core_freq_mhz <= 0 and w.frames_in_core > 0:
        raise Inconsistent("кадри в ядрі є, а ядра немає")
    if w.flatness_milli > 1000:
        raise Inconsistent("плоскість більша за одиницю")
    if w.harmonics_found > 16:
        raise Inconsistent("неправдоподібна кількість гармонік")


# ------------------------------------------------------------- правило
# Вердикт НЕ підписується. Він обчислюється з підписаних ознак — і тут,
# і на приймальному боці, тим самим кодом.

VERDICT_RULE_VERSION = 1

MIN_HIT_FRACTION = 0.30
MAX_SPREAD_PCT = 12.0
MIN_STABLE_FRAMES = 10
MIN_RUN = 6
MIN_BAND_SNR_MDB = 6000       # 6 дБ
MAX_TONAL_FLATNESS_MILLI = 350


def verdict(w: Witness) -> tuple[str, list[str]]:
    """
    Вердикт із ознак. Повертає рішення й перелік причин.

    Причини повертаються завжди — і коли ціль є, і коли немає. Приймальна
    сторона бачить не тільки ЩО вирішено, а й ЧОМУ, і може звірити кожен
    пункт із підписаними числами.
    """
    why: list[str] = []
    good = max(1, w.frames_total - w.frames_saturated)
    hit_frac = w.frames_with_series / good

    ok = True
    if w.core_freq_mhz <= 0:
        why.append("стабільного ядра немає")
        ok = False
    if hit_frac < MIN_HIT_FRACTION:
        why.append(f"ряд лише в {hit_frac*100:.0f}% кадрів "
                   f"(треба {MIN_HIT_FRACTION*100:.0f}%)")
        ok = False
    if w.band_snr_mdb < MIN_BAND_SNR_MDB:
        why.append(f"смуга {w.band_snr_mdb/1000:.1f} дБ над фоном "
                   f"(треба {MIN_BAND_SNR_MDB/1000:.0f})")
        ok = False
    if w.core_freq_mhz > 0:
        spread_pct = 100.0 * w.core_spread_mhz / w.core_freq_mhz
        if spread_pct > MAX_SPREAD_PCT:
            why.append(f"розкид ядра {spread_pct:.0f}% "
                       f"(треба до {MAX_SPREAD_PCT:.0f}%)")
            ok = False

    stable = w.frames_in_core >= MIN_STABLE_FRAMES
    contiguous = w.longest_run >= MIN_RUN
    if not stable:
        why.append(f"у ядрі {w.frames_in_core} кадрів "
                   f"(треба {MIN_STABLE_FRAMES})")
    if not contiguous:
        why.append(f"найдовша низка {w.longest_run} "
                   f"(треба {MIN_RUN} підряд)")

    if not ok or not (stable or contiguous):
        return "НЕМАЄ", why
    if stable and contiguous:
        why.append(f"ядро {w.core_freq_mhz/1000:.0f} Гц, "
                   f"{w.frames_in_core} кадрів у ядрі, "
                   f"{w.longest_run} підряд, "
                   f"{w.band_snr_mdb/1000:.1f} дБ над фоном")
        if w.flatness_milli <= MAX_TONAL_FLATNESS_MILLI:
            why.append(f"тональний спектр (плоскість "
                       f"{w.flatness_milli/1000:.3f})")
        return "ЦІЛЬ", why
    return "хитка", why


if __name__ == "__main__":
    # Показує канонічну форму й перерахунок на прикладі реального виміру
    # (болгарка на 30 м, серія 24.08).
    w = Witness(
        device_id=0x1A2B3C4D5E6F7788,
        session_id=1,
        epoch_start_ms=1787577600000,
        epoch_end_ms=1787577620000,
        core_freq_mhz=604000,
        core_spread_mhz=8000,
        frames_total=79,
        frames_saturated=0,
        frames_with_series=79,
        frames_in_core=79,
        longest_run=79,
        band_snr_mdb=41600,
        flatness_milli=26,
        harmonics_found=4,
        bg_tones_mhz=[172000, 118000, 60000],
        temp_mc=21500,
        humidity_milli=520,
        pressure_pa=99800,
    )
    check_consistency(w)
    c = w.canonical()
    print(f"канонічна форма: {len(c)} байтів")
    print(f"  {c.hex()}")
    print(f"відбиток SHA-256: {w.digest().hex()}")
    v, why = verdict(w)
    print(f"\nвердикт (перерахований, не підписаний): {v}")
    for r in why:
        print(f"  · {r}")
