"""CLI for notary — гейт необратимых мутаций агента."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

from .banner import NOTARY_BANNER
from .gate import ALLOW, DENY, check_file

console = Console()


def _banner() -> None:
    console.print(f"[bold red]{NOTARY_BANNER}[/bold red]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD notary — нет подписи, нет мутации."""


@main.command("check")
@click.argument("request_path", type=click.Path())
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить JSON-вердикт")
def check_cmd(request_path: str, as_json: str | None) -> None:
    """Проверить подписанное разрешение на необратимую мутацию.

    rc=0 allow · rc=1 deny · rc=2 не состоялась (fail-safe: неизвестное = отказ).
    """
    v = check_file(request_path)

    if as_json:
        Path(as_json).write_text(
            json.dumps(v.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )

    цвет = {ALLOW: "green", DENY: "red"}.get(v.verdict, "yellow")
    console.print(f"Вердикт: [{цвет}]{v.verdict}[/{цвет}] (rc={v.rc}) — {v.reason}")
    if v.action:
        console.print(f"[dim]action={v.action} target={v.target}[/dim]")
    if v.checks:
        console.print(f"[dim]проверки: {v.checks}[/dim]")

    raise SystemExit(v.rc)


if __name__ == "__main__":
    main()
