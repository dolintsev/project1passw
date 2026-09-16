#!/usr/bin/env python3
"""
Password Strength Checker — проверка сложности пароля.

Возможности:
  * оценка энтропии и примерного времени подбора;
  * поиск слабых паттернов: словарные пароли, последовательности,
    клавиатурные ряды, повторы, даты, leet-замены (p@ssw0rd);
  * проверка утечек через Have I Been Pwned (k-anonymity:
    на сервер уходят только первые 5 символов SHA-1 хеша);
  * генерация стойкого пароля через модуль secrets.

Запуск:
  python password_checker.py            # интерактивный ввод (пароль скрыт)
  python password_checker.py --hibp     # + проверка в базе утечек
  python password_checker.py --generate 20
"""

import argparse
import getpass
import hashlib
import math
import re
import secrets
import string
import urllib.request
from dataclasses import dataclass, field

# Небольшой встроенный словарь. Для реального использования можно
# подгрузить rockyou.txt или SecLists через --wordlist.
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123",
    "football", "monkey", "letmein", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321",
    "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx",
    "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
    "asdfgh", "hunter", "buster", "soccer", "harley", "batman", "andrew",
    "tigger", "sunshine", "iloveyou", "2000", "charlie", "robert",
    "thomas", "hockey", "ranger", "daniel", "starwars", "klaster",
    "112233", "george", "computer", "michelle", "jessica", "pepper",
    "admin", "welcome", "login", "passw0rd", "privet", "parol", "qwerty123",
}

KEYBOARD_ROWS = [
    "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "йцукенгшщзхъ", "фывапролджэ", "ячсмитьбю",
]

LEET_MAP = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "i", "!": "i",
                          "3": "e", "$": "s", "5": "s", "7": "t"})

# Сколько хешей в секунду перебирает атакующий (офлайн, быстрый хеш, GPU).
GUESSES_PER_SECOND = 1e10


@dataclass
class Report:
    password_length: int
    entropy_bits: float
    score: int                      # 0..4
    crack_time: str
    warnings: list = field(default_factory=list)
    suggestions: list = field(default_factory=list)
    pwned_count: int | None = None

    @property
    def label(self) -> str:
        return ["Очень слабый", "Слабый", "Средний", "Хороший", "Отличный"][self.score]


def charset_size(password: str) -> int:
    """Размер алфавита, из которого, судя по всему, составлен пароль."""
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[а-яё]", password):
        size += 33
    if re.search(r"[А-ЯЁ]", password):
        size += 33
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^\w\s]|_", password):
        size += 33
    if re.search(r"\s", password):
        size += 1
    return max(size, 1)


def has_sequence(password: str, min_len: int = 4) -> bool:
    """abcd, 1234, 9876 и т.п."""
    p = password.lower()
    run = 1
    for i in range(1, len(p)):
        step = ord(p[i]) - ord(p[i - 1])
        prev = ord(p[i - 1]) - ord(p[i - 2]) if i >= 2 else step
        if step in (1, -1) and (run == 1 or step == prev):
            run += 1
            if run >= min_len:
                return True
        else:
            run = 1
    return False


def has_keyboard_pattern(password: str, min_len: int = 4) -> bool:
    p = password.lower()
    for row in KEYBOARD_ROWS:
        for line in (row, row[::-1]):
            for i in range(len(line) - min_len + 1):
                if line[i:i + min_len] in p:
                    return True
    return False


def human_time(seconds: float) -> str:
    units = [("лет", 31_536_000), ("дней", 86_400), ("часов", 3_600),
             ("минут", 60), ("секунд", 1)]
    if seconds < 1:
        return "мгновенно"
    if seconds > 31_536_000 * 1e6:
        return "больше миллиона лет"
    for name, size in units:
        if seconds >= size:
            return f"~{seconds / size:,.0f} {name}".replace(",", " ")
    return "мгновенно"


def check_hibp(password: str, timeout: float = 5.0) -> int:
    """Сколько раз пароль встречался в утечках. Сам пароль не отправляется."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    req = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "password-checker-pet-project"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        for line in resp.read().decode().splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
    return 0


def analyze(password: str, wordlist: set[str] | None = None) -> Report:
    words = wordlist or COMMON_PASSWORDS
    warnings, suggestions = [], []
    length = len(password)

    entropy = length * math.log2(charset_size(password))
    penalty = 0.0

    lowered = password.lower()
    deleeted = lowered.translate(LEET_MAP)
    stripped = re.sub(r"[\d!@#$%^&*._-]+$", "", deleeted)  # password123! -> password

    if lowered in words:
        warnings.append("Пароль есть в списке самых популярных")
        entropy = min(entropy, 5)
    elif deleeted in words or stripped in words:
        warnings.append("Это популярный пароль с заменами символов или цифрами в конце")
        entropy = min(entropy, 15)

    if has_sequence(password):
        warnings.append("Есть последовательность символов (abcd, 1234)")
        penalty += 10
    if has_keyboard_pattern(password):
        warnings.append("Есть клавиатурный паттерн (qwer, asdf)")
        penalty += 10
    if re.search(r"(.)\1{2,}", password):
        warnings.append("Есть повторяющиеся символы (aaa, 111)")
        penalty += 8
    if re.search(r"(19|20)\d{2}", password):
        warnings.append("Похоже на год — даты легко угадать")
        penalty += 6

    entropy = max(entropy - penalty, 0)

    if length < 12:
        suggestions.append("Сделайте пароль длиннее — минимум 12 символов")
    if not re.search(r"[A-ZА-ЯЁ]", password):
        suggestions.append("Добавьте заглавные буквы")
    if not re.search(r"\d", password):
        suggestions.append("Добавьте цифры")
    if not re.search(r"[^\w\s]|_", password):
        suggestions.append("Добавьте спецсимволы")
    if warnings:
        suggestions.append("Избегайте словарных слов и предсказуемых паттернов")

    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 80:
        score = 3
    else:
        score = 4
    if length < 8:
        score = min(score, 1)

    seconds = (2 ** entropy) / 2 / GUESSES_PER_SECOND  # в среднем половина перебора
    return Report(length, round(entropy, 1), score, human_time(seconds),
                  warnings, suggestions)


def generate_password(length: int = 16) -> str:
    """Криптостойкий пароль, гарантированно со всеми классами символов."""
    if length < 8:
        raise ValueError("Длина должна быть не меньше 8")
    pools = [string.ascii_lowercase, string.ascii_uppercase,
             string.digits, "!@#$%^&*()-_=+[]{}?"]
    chars = [secrets.choice(p) for p in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def print_report(r: Report) -> None:
    bar = "█" * (r.score + 1) + "░" * (4 - r.score)
    print(f"\nОценка:        {bar}  {r.label} ({r.score}/4)")
    print(f"Длина:         {r.password_length}")
    print(f"Энтропия:      {r.entropy_bits} бит")
    print(f"Время подбора: {r.crack_time}")
    if r.pwned_count is not None:
        if r.pwned_count:
            print(f"Утечки:        ⚠ найден в утечках {r.pwned_count:,} раз".replace(",", " "))
        else:
            print("Утечки:        ✓ в известных утечках не найден")
    if r.warnings:
        print("\nПроблемы:")
        for w in r.warnings:
            print(f"  ✗ {w}")
    if r.suggestions:
        print("\nРекомендации:")
        for s in r.suggestions:
            print(f"  → {s}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Проверка сложности пароля")
    parser.add_argument("--hibp", action="store_true",
                        help="проверить пароль в базе утечек Have I Been Pwned")
    parser.add_argument("--wordlist", help="путь к словарю паролей (по одному в строке)")
    parser.add_argument("--generate", type=int, metavar="N",
                        help="сгенерировать стойкий пароль длиной N")
    args = parser.parse_args()

    if args.generate:
        pwd = generate_password(args.generate)
        print(f"Сгенерированный пароль: {pwd}")
        print_report(analyze(pwd))
        return

    wordlist = None
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8", errors="ignore") as f:
            wordlist = {line.strip().lower() for line in f if line.strip()}
        print(f"Загружено слов: {len(wordlist)}")

    password = getpass.getpass("Введите пароль (ввод скрыт): ")
    if not password:
        print("Пустой пароль.")
        return

    report = analyze(password, wordlist)
    if args.hibp:
        try:
            report.pwned_count = check_hibp(password)
            if report.pwned_count:
                report.score = 0
                report.warnings.insert(0, "Пароль уже есть в утечках — не используйте его")
        except OSError as e:
            print(f"Не удалось проверить утечки: {e}")
    print_report(report)


if __name__ == "__main__":
    main()
