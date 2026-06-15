"""
restore_demo.py — Restaure la base de démo dans data/qready.db.

Usage :
    python scripts/restore_demo.py

Copie fixtures/demo.db → data/qready.db.
Lance ce script avant une démo pour repartir d'un état connu.
"""
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "fixtures" / "demo.db"
DST = ROOT / "data" / "qready.db"


def main() -> None:
    if not SRC.exists():
        print(f"[restore-demo] Aucun snapshot trouvé dans {SRC}")
        print("  → Lance d'abord : python scripts/save_demo.py")
        raise SystemExit(1)

    DST.parent.mkdir(exist_ok=True)
    shutil.copy2(SRC, DST)
    print(f"[restore-demo] {DST} restauré depuis {SRC}")


if __name__ == "__main__":
    main()
