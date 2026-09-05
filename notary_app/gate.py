"""notary gate — проверка подписанного разрешения на необратимую мутацию.

Контракт запроса (request.json):
    {action, target, scope, ts, sig}

    sig = HMAC-SHA256 (hex) над канонической строкой `action|target|scope|ts`
    ключом, лежащим в файле (путь — в env NOTARY_KEY_FILE). Значение ключа
    НИКОГДА не печатается.

Три проверки, все обязаны пройти для allow:
    1. подпись совпадает (иначе запрос подделан/повреждён);
    2. action входит в разрешённый scope (список действий или wildcard "*");
    3. ts в окне ±300 с от текущего времени (антиреплей).

Коды возврата (fail-safe: неизвестное = отказ):
    ALLOW         → rc 0   всё сошлось
    DENY          → rc 1   проверка прошла и дала «нет» (подпись/scope/replay)
    INDETERMINATE → rc 2   проверка НЕ СОСТОЯЛАСЬ (нет ключа/битый JSON/нет поля)

🔴 Различение rc=1 и rc=2 несущее: rc=2 опаснее, потому что похоже на rc=1.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

# Классы вердикта
ALLOW = "ALLOW"
DENY = "DENY"
INDETERMINATE = "INDETERMINATE"

_RC = {ALLOW: 0, DENY: 1, INDETERMINATE: 2}

# Окно антиреплея, секунды
TS_WINDOW = 300

REQUIRED_FIELDS = ("action", "target", "scope", "ts", "sig")


@dataclass
class Verdict:
    verdict: str
    reason: str
    action: str | None = None
    target: str | None = None
    checks: dict = field(default_factory=dict)

    @property
    def rc(self) -> int:
        return _RC[self.verdict]

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "rc": self.rc,
            "reason": self.reason,
            "action": self.action,
            "target": self.target,
            "checks": self.checks,
            "not_proven": (
                "Гейт проверяет ТОЛЬКО совпадение подписи, вхождение action в "
                "подписанный scope и свежесть ts. Он НЕ доказывает, что действие "
                "безопасно, что ключ не утёк, что подписант имел право подписывать, "
                "и что target действительно тот, за кого себя выдаёт."
            ),
        }


def canonical_scope(scope) -> str:
    """Детерминированная сериализация scope для подписи.

    И подписант, и проверяющий обязаны звать ЭТУ функцию — иначе разойдутся
    байты сообщения и подпись не сойдётся при верном ключе.
    """
    if isinstance(scope, str):
        return scope
    if isinstance(scope, (list, tuple)):
        return json.dumps(sorted(scope), ensure_ascii=False, separators=(",", ":"))
    # прочее (dict/число) — стабильно, но нетипично
    return json.dumps(scope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def signing_string(action: str, target: str, scope, ts) -> str:
    """Каноническая строка, над которой берётся HMAC."""
    return f"{action}|{target}|{canonical_scope(scope)}|{ts}"


def compute_sig(key: bytes, action: str, target: str, scope, ts) -> str:
    """HMAC-SHA256 в hex. Общая точка для подписанта и проверяющего."""
    msg = signing_string(action, target, scope, ts).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _load_key() -> bytes | None:
    """Прочитать ключ из файла (путь в env NOTARY_KEY_FILE). Значение не печатать."""
    path = os.environ.get("NOTARY_KEY_FILE")
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    data = p.read_bytes().strip()
    if not data:
        return None
    return data


def _action_in_scope(action: str, scope) -> bool:
    if isinstance(scope, str):
        return scope == "*"
    if isinstance(scope, (list, tuple)):
        if "*" in scope:
            return True
        return action in scope
    return False


def evaluate(request: dict, *, now: float | None = None) -> Verdict:
    """Разобрать уже-распарсенный запрос и вынести вердикт.

    now — для тестируемости; по умолчанию системное время.
    """
    if now is None:
        now = time.time()

    # (0) структура запроса — нет поля → не состоялась (rc=2)
    if not isinstance(request, dict):
        return Verdict(INDETERMINATE, "запрос не является объектом JSON")
    missing = [f for f in REQUIRED_FIELDS if f not in request]
    if missing:
        return Verdict(
            INDETERMINATE,
            f"в запросе нет обязательных полей: {', '.join(missing)}",
        )

    action = request["action"]
    target = request["target"]
    scope = request["scope"]
    ts = request["ts"]
    sig = request["sig"]

    if not isinstance(sig, str) or not sig:
        return Verdict(INDETERMINATE, "поле sig пустое или не строка",
                       action=str(action), target=str(target))
    try:
        ts_num = float(ts)
    except (TypeError, ValueError):
        return Verdict(INDETERMINATE, "поле ts не является числом",
                       action=str(action), target=str(target))

    # ключ — нет ключа → не состоялась (rc=2)
    key = _load_key()
    if key is None:
        return Verdict(
            INDETERMINATE,
            "ключ недоступен (env NOTARY_KEY_FILE не задан / файл пуст / не найден)",
            action=str(action), target=str(target),
        )

    checks: dict = {}

    # (1) подпись — первой: scope и ts подписаны, без ключа их не подделать
    expected = compute_sig(key, action, target, scope, ts)
    sig_ok = hmac.compare_digest(expected, sig)
    checks["signature"] = sig_ok
    if not sig_ok:
        return Verdict(DENY, "подпись не совпадает",
                       action=str(action), target=str(target), checks=checks)

    # (2) вхождение action в подписанный scope
    scope_ok = _action_in_scope(action, scope)
    checks["scope"] = scope_ok
    if not scope_ok:
        return Verdict(DENY, f"action '{action}' вне разрешённого scope",
                       action=str(action), target=str(target), checks=checks)

    # (3) окно антиреплея ±TS_WINDOW
    age = now - ts_num
    ts_ok = abs(age) <= TS_WINDOW
    checks["ts_window"] = ts_ok
    checks["ts_age_seconds"] = round(age, 3)
    if not ts_ok:
        return Verdict(
            DENY,
            f"ts вне окна ±{TS_WINDOW}с (возраст {age:.0f}с) — антиреплей",
            action=str(action), target=str(target), checks=checks,
        )

    return Verdict(ALLOW, "подпись верна, action в scope, ts свеж",
                   action=str(action), target=str(target), checks=checks)


def check_file(path: str, *, now: float | None = None) -> Verdict:
    """Прочитать request.json и вынести вердикт. Битый JSON → rc=2."""
    p = Path(path)
    if not p.is_file():
        return Verdict(INDETERMINATE, f"файл запроса не найден: {path}")
    try:
        raw = p.read_text(encoding="utf-8")
        request = json.loads(raw)
    except (OSError, json.JSONDecodeError) as e:
        return Verdict(INDETERMINATE, f"запрос не читается как JSON: {e}")
    return evaluate(request, now=now)
