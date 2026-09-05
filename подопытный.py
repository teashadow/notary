#!/usr/bin/env python3
"""Подопытный для notary: генерит СВОЙ случайный HMAC-ключ (не боевой),
подписывает запросы тем же алгоритмом, что проверяет гейт, и раскладывает
фикстуры по временному каталогу. Каждая фикстура — отдельный request.json,
на котором гейт обязан дать заранее известный код возврата.

Печатает JSON: {key_file, dir, cases:[{name, path, expect_rc, note}]}.
Значение ключа НЕ печатается — только путь к файлу (600).
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from notary_app.gate import compute_sig  # noqa: E402


def main() -> None:
    d = Path(tempfile.mkdtemp(prefix="notary_probe_"))

    # СВОЙ ключ — случайные 32 байта hex. Не боевой. Файл 600.
    key_file = d / "test.key"
    key = secrets.token_hex(32).encode("utf-8")
    key_file.write_bytes(key)
    os.chmod(key_file, 0o600)

    now = int(time.time())
    action = "delete_file"
    target = "/srv/data/report.csv"
    scope = ["delete_file", "rename_file"]  # список действий

    good_sig = compute_sig(key, action, target, scope, now)

    cases = []

    def write(name: str, req: dict, expect_rc: int, note: str) -> None:
        p = d / f"{name}.json"
        p.write_text(json.dumps(req, ensure_ascii=False, indent=2), encoding="utf-8")
        cases.append({"name": name, "path": str(p), "expect_rc": expect_rc, "note": note})

    # 1. валидная: верная подпись + action в scope + свежий ts → ALLOW rc0
    write("valid",
          {"action": action, "target": target, "scope": scope, "ts": now, "sig": good_sig},
          0, "верная подпись, action в scope, свежий ts")

    # 2a. битая подпись: тот же запрос, подпись испорчена на ОДИН символ → DENY rc1
    ch = "0" if good_sig[-1] != "0" else "1"
    bad_sig = good_sig[:-1] + ch
    write("badsig",
          {"action": action, "target": target, "scope": scope, "ts": now, "sig": bad_sig},
          1, "подпись испорчена на один символ — детектор обязан поймать подделку")

    # 2b. отсутствующая подпись → INDETERMINATE rc2 (нет поля)
    write("nosig",
          {"action": action, "target": target, "scope": scope, "ts": now},
          2, "нет поля sig — проверка не состоялась")

    # 3. ts −20ч (подпись верна для этого старого ts) → DENY rc1 антиреплей
    old_ts = now - 20 * 3600
    old_sig = compute_sig(key, action, target, scope, old_ts)
    write("replay",
          {"action": action, "target": target, "scope": scope, "ts": old_ts, "sig": old_sig},
          1, "ts на 20 часов в прошлом, подпись верна — ловит антиреплей, не подпись")

    # 4. action ВНЕ scope (подпись верна для этого action+scope) → DENY rc1
    ev_action = "exfiltrate"
    ev_sig = compute_sig(key, ev_action, target, scope, now)
    write("outofscope",
          {"action": ev_action, "target": target, "scope": scope, "ts": now, "sig": ev_sig},
          1, "action 'exfiltrate' не входит в scope, хотя подпись верна")

    # 5. битый JSON-запрос → INDETERMINATE rc2
    bad = d / "badjson.json"
    bad.write_text('{"action": "delete_file", "target": ', encoding="utf-8")
    cases.append({"name": "badjson", "path": str(bad), "expect_rc": 2,
                  "note": "оборванный JSON — проверка не состоялась"})

    # ЗДОРОВЫЙ контроль (см. 8.18): wildcard-scope, свежий ts, верная подпись → ALLOW rc0
    w_scope = "*"
    w_sig = compute_sig(key, "any_action", target, w_scope, now)
    write("wildcard_ok",
          {"action": "any_action", "target": target, "scope": w_scope, "ts": now, "sig": w_sig},
          0, "wildcard scope '*' — любое действие разрешено при верной подписи")

    print(json.dumps({"key_file": str(key_file), "dir": str(d), "cases": cases},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
