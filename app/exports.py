"""Printable exports of a survivor's records: PDF report and a ZIP evidence pack.

The incident report deliberately leaves out the safety plan: court papers are
usually seen by the other side, and the plan says where the survivor would go.
"""
import io
import json
import zipfile
from datetime import datetime, timezone

from fpdf import FPDF
from PIL import Image

from .crypto import DecryptionError
from .media import read_decrypted

LABELS = [
    ("setting", "Where"), ("location", "Place"), ("injuries", "Injuries"), ("witnesses", "Witnesses"),
]
WORK_LABELS = [
    ("employer", "Employer"), ("perpetrator_role", "Their role"), ("reported", "Reported"),
    ("report_ref", "Reference number"), ("work_impact", "Impact on my work"),
]

_PUNCT = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-",
                        "—": "-", "…": "...", "•": "-", " ": " "})


def pdf_text(value) -> str:
    """The built-in PDF fonts cover Latin-1 (all SA languages' letters); swap the rest safely."""
    return str(value or "").translate(_PUNCT).encode("latin-1", "replace").decode("latin-1")


def human_size(n: int) -> str:
    return f"{n / (1024 * 1024):.1f} MB" if n >= 1024 * 1024 else f"{max(1, n // 1024)} KB"


class ReportPDF(FPDF):
    def __init__(self, title):
        super().__init__(format="A4")
        self.report_title = title
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(18, 18, 18)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, pdf_text(f"{self.report_title} - page {self.page_no()}/{{nb}}"), align="C")


def _image_for_pdf(data: bytes):
    """Downscaled JPEG for embedding, or None if the image can't be read (e.g. HEIC)."""
    try:
        with Image.open(io.BytesIO(data)) as im:
            im = im.convert("RGB")
            im.thumbnail((1600, 1600))
            out = io.BytesIO()
            im.save(out, "JPEG", quality=82)
            return out, im.size
    except Exception:  # noqa: BLE001 - any undecodable image is simply listed instead
        return None


def build_pdf(entries, alias: str, vault, uid: int) -> bytes:
    title = "Incident record"
    pdf = ReportPDF(title)
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(30, 21, 48)
    pdf.cell(0, 12, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(90, 90, 90)
    generated = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    pdf.multi_cell(0, 5, pdf_text(
        f"Kept by: {alias}    Generated: {generated}    Incidents: {len(entries)}\n"
        "This record was written privately and stored encrypted in the Dudu app. Each attached file has a "
        "SHA-256 fingerprint, recorded when it was uploaded, so anyone can check the file has not been "
        "changed since."), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    for n, e in enumerate(entries, 1):
        if pdf.get_y() > 240:
            pdf.add_page()
        pdf.set_draw_color(255, 77, 0)
        pdf.set_line_width(0.6)
        pdf.line(18, pdf.get_y(), 192, pdf.get_y())
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(30, 21, 48)
        pdf.cell(0, 7, pdf_text(f"{n}. {e.get('date', '-')}  -  {str(e.get('type', '')).capitalize()}"),
                 new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 5.5, pdf_text(e.get("description")), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        labels = LABELS + (WORK_LABELS if e.get("setting") == "workplace" else [])
        for key, label in labels:
            if e.get(key):
                pdf.set_font("Helvetica", "B", 9.5)
                pdf.cell(38, 5.5, pdf_text(label + ":"))
                pdf.set_font("Helvetica", "", 9.5)
                pdf.multi_cell(0, 5.5, pdf_text(e[key]), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "I", 8.5)
        pdf.set_text_color(110, 110, 110)
        pdf.cell(0, 5, pdf_text(f"Recorded in Dudu: {e.get('created_at', '')}"), new_x="LMARGIN", new_y="NEXT")

        for m in e.get("media", []):
            pdf.set_text_color(40, 40, 40)
            embedded = False
            if m["kind"] == "image":
                try:
                    prepared = _image_for_pdf(read_decrypted(vault, uid, m["stored_name"]))
                except (DecryptionError, OSError):
                    prepared = None
                if prepared:
                    buf, (w, h) = prepared
                    max_w, max_h = 110, 80
                    scale = min(max_w / w, max_h / h)
                    if pdf.get_y() + h * scale > 270:
                        pdf.add_page()
                    pdf.ln(2)
                    pdf.image(buf, w=w * scale, h=h * scale)
                    embedded = True
            pdf.set_font("Helvetica", "B" if not embedded else "", 9)
            icon = {"image": "Photo", "video": "Video", "audio": "Voice note"}[m["kind"]]
            pdf.multi_cell(0, 5, pdf_text(f"{icon}: {m['name']} ({human_size(m['size'])})"
                                          f"{'' if embedded else ' - included in the evidence pack (ZIP)'}"),
                           new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Courier", "", 7.5)
            pdf.set_text_color(100, 100, 100)
            pdf.multi_cell(0, 4, pdf_text(f"SHA-256 {m['sha256']}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

    if not entries:
        pdf.set_font("Helvetica", "I", 11)
        pdf.cell(0, 8, "No incidents recorded yet.")
    return bytes(pdf.output())


def build_zip(entries, alias: str, vault, uid: int, pdf_bytes: bytes) -> bytes:
    buf = io.BytesIO()
    lines = ["Dudu evidence pack", f"Kept by: {alias}",
             f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}", "",
             "Each file below is the original, unchanged upload. Check it with any SHA-256 tool:",
             "  Windows:  certutil -hashfile <file> SHA256", "  Mac/Linux:  shasum -a 256 <file>", ""]
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("incident-record.pdf", pdf_bytes)
        clean = []
        for n, e in enumerate(entries, 1):
            item = {k: v for k, v in e.items() if k not in ("media", "id")}
            item["files"] = []
            for k, m in enumerate(e.get("media", []), 1):
                path = f"evidence/{n:02d}-{k}-{m['name']}"
                try:
                    z.writestr(path, read_decrypted(vault, uid, m["stored_name"]))
                    lines.append(f"{m['sha256']}  {path}")
                except (DecryptionError, OSError):
                    lines.append(f"[could not be decrypted]  {path}")
                item["files"].append({"file": path, "sha256": m["sha256"], "type": m["mime"]})
            clean.append(item)
        z.writestr("fingerprints.txt", "\n".join(lines) + "\n")
        z.writestr("incidents.json", json.dumps(clean, indent=2))
    return buf.getvalue()
