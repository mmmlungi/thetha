"""Start Dudu from any folder:  python C:\\Users\\27848\\thetha\\run.py [--seed]"""
import os
import sys
import webbrowser

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from app import create_app  # noqa: E402

if __name__ == "__main__":
    if "--seed" in sys.argv:
        from tools.seed_demo import main as seed
        seed()
    app = create_app()
    url = "http://127.0.0.1:5000"
    print(f"\n  Dudu is running at {url}  (Ctrl+C to stop)\n")
    if "--no-browser" not in sys.argv:
        webbrowser.open(url)
    app.run(host="127.0.0.1", port=5000)
