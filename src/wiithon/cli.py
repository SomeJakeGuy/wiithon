from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

app = typer.Typer(help="Wii ISO patching and inspection tool.")
iso_app = typer.Typer(help="Operations on Wii ISO files.")

app.add_typer(iso_app,  name="iso")

console = Console()
err_console = Console(stderr=True, style="bold red")

# Helpers
def _abort(msg: str) -> None:
    err_console.print(f"Error: {msg}")
    raise typer.Exit(code=1)

def _require_file(path: Path) -> None:
    if not path.exists():
        _abort(f"{path} does not exist.")
    if not path.is_file():
        _abort(f"{path} is not a file.")

# iso info
@iso_app.command("info")
def iso_info(
    iso: Annotated[Path, typer.Argument(help="Path to the Wii ISO.")],
) -> None:
    """Display metadata from a Wii ISO disc header."""
    _require_file(iso)

    from wiithon.WiiIsoReader import WiiIsoReader

    with WiiIsoReader(str(iso)) as reader:
        h = reader.disc_header

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="bold cyan")
        table.add_column()

        table.add_row("Game ID",    h.game_id.decode("ascii").strip("\x00"))
        table.add_row("Title",      h.game_title.strip())
        table.add_row("Disc",       str(h.disc_num))
        table.add_row("Version",    str(h.disc_version))

        type_names = {0: "DATA", 1: "UPDATE", 2: "CHANNEL"}
        parts = ", ".join(
            type_names.get(p.part_type, f"#{p.part_type}")
            for p in reader.partitions
        )
        table.add_row("Partitions", parts)

        console.print(Panel(table, title=f"[bold]{iso.name}[/bold]", expand=False))


if __name__ == "__main__":
    app()