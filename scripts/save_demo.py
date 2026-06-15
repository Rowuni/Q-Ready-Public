"""
save_demo.py — Sauvegarde l'état actuel de data/qready.db comme snapshot de démo.

Usage :
    python scripts/save_demo.py

Copie data/qready.db → fixtures/demo.db.
Commite ensuite fixtures/demo.db pour partager l'état avec l'équipe.
"""
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "data" / "qready.db"
DST = ROOT / "fixtures" / "demo.db"


def main() -> None:
    if not SRC.exists():
        print(f"[save-demo] Aucune base trouvée dans {SRC}")
        print("  → Lance le backend et effectue quelques scans d'abord.")
        raise SystemExit(1)

    DST.parent.mkdir(exist_ok=True)
    shutil.copy2(SRC, DST)
    print(f"[save-demo] Snapshot sauvegardé dans {DST}")
    print("  → git add fixtures/demo.db && git commit -m 'chore: update demo snapshot'")


if __name__ == "__main__":
    main()
