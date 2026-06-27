"""
main.py  —  PhishShield AI
Combines the original frontend (zero changes) with the real backend.

Run:
    python main.py

Dependencies:
    pip install opencv-python pyzbar Pillow scikit-learn numpy requests
"""

# ── Backend imports ──────────────────────────────────────────────────────────
import threading
from tkinter import filedialog, messagebox
from url_analyzer import analyze_url          # Feature extraction + scoring
from qr_scanner  import scan_qr_from_image   # Decode QR from image file
from qr_scanner  import scan_qr_from_webcam  # Decode QR from webcam
from logger      import log_scan             # Save results to CSV

# ── Frontend (original — zero changes to this block) ────────────────────────
import tkinter as tk
from tkinter import ttk
import random

class PhishShieldApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishShield AI — Desktop Defense")
        self.root.geometry("900x650")
        self.root.configure(bg="#0f172a")  # Dark slate background

        # Custom Styles
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background="#0f172a")
        style.configure("TLabel", background="#0f172a", foreground="#f8fafc", font=("Inter", 10))
        style.configure("Header.TLabel", font=("Inter", 18, "bold"), foreground="#7dd3fc")
        style.configure("TButton", font=("Inter", 10, "bold"), padding=10)

        # Layout Containers
        self.main_frame = ttk.Frame(self.root, padding="30")
        self.main_frame.pack(fill="both", expand=True)

        # Header
        self.header = ttk.Label(self.main_frame, text="PhishShield AI Scanner", style="Header.TLabel")
        self.header.pack(pady=(0, 20))

        # URL Input Section
        self.input_frame = ttk.Frame(self.main_frame)
        self.input_frame.pack(fill="x", pady=10)
        
        ttk.Label(self.input_frame, text="Enter URL or Image Path for QR Scan:").pack(anchor="w")
        self.url_entry = ttk.Entry(self.input_frame, font=("Inter", 12))
        self.url_entry.pack(fill="x", side="left", expand=True, padx=(0, 10))
        
        self.scan_btn = ttk.Button(self.input_frame, text="Analyze Threat", command=self.analyze)
        self.scan_btn.pack(side="right")

        # Result Dashboard
        self.dashboard = ttk.Frame(self.main_frame)
        self.dashboard.pack(fill="both", expand=True, pady=20)

        # Risk Gauge (Simplified for Tkinter)
        self.gauge_canvas = tk.Canvas(self.dashboard, width=300, height=180, bg="#1e293b", highlightthickness=0)
        self.gauge_canvas.grid(row=0, column=0, padx=10, pady=10)
        self.draw_gauge(0)

        # Threat Flags Panel
        self.flags_frame = tk.Frame(self.dashboard, bg="#1e293b", padx=15, pady=15)
        self.flags_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        
        tk.Label(self.flags_frame, text="Threat Analysis Flags", bg="#1e293b", fg="#7dd3fc", font=("Inter", 12, "bold")).pack(anchor="w")
        self.flags_text = tk.Label(self.flags_frame, text="Ready for scan...", bg="#1e293b", fg="#94a3b8", justify="left")
        self.flags_text.pack(anchor="w", pady=10)

        # Multilingual Warning Display
        self.warning_box = tk.Label(self.main_frame, text="", font=("Inter", 14, "bold"), pady=20, bg="#0f172a")
        self.warning_box.pack(fill="x")

        # ── Extra backend-powered buttons (added BELOW the original UI) ──────
        self._add_backend_controls()

    def draw_gauge(self, score):
        self.gauge_canvas.delete("all")
        # Draw background arc
        self.gauge_canvas.create_arc(50, 50, 250, 250, start=0, extent=180, outline="#334155", width=20, style="arc")
        # Draw risk arc
        color = "#22c55e" if score < 3 else "#eab308" if score < 5 else "#ef4444"
        extent = (score / 10) * 180
        self.gauge_canvas.create_arc(50, 50, 250, 250, start=180, extent=-extent, outline=color, width=20, style="arc")
        self.gauge_canvas.create_text(150, 140, text=f"{score}/10", fill="white", font=("Inter", 24, "bold"))
        self.gauge_canvas.create_text(150, 100, text="RISK LEVEL", fill="#94a3b8", font=("Inter", 10))

    def analyze(self):
        # ── REPLACED: was random — now calls real backend ────────────────────
        raw_input = self.url_entry.get().strip()
        if not raw_input:
            messagebox.showwarning("Input needed", "Please enter a URL or an image path.")
            return

        # Detect if input looks like a file path (QR image)
        if self._is_image_path(raw_input):
            self._run_qr_image_scan(raw_input)
        else:
            self._run_url_scan(raw_input)

    # ── Private helpers ──────────────────────────────────────────────────────

    def _is_image_path(self, text: str) -> bool:
        """Return True if the input ends with a known image extension."""
        return text.lower().endswith((".png", ".jpg", ".jpeg", ".bmp", ".webp"))

    def _run_url_scan(self, url: str) -> None:
        """Analyze a typed/pasted URL with the real backend."""
        result = analyze_url(url)
        self._update_ui(url, result)

    def _run_qr_image_scan(self, path: str) -> None:
        """Decode QR from an image file, then analyze the extracted URL."""
        url = scan_qr_from_image(path)
        if url:
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)
            result = analyze_url(url)
            self._update_ui(url, result)
        else:
            messagebox.showerror("QR Scan Failed",
                "No QR code found in the image.\n"
                "Make sure the image is clear and contains a single QR code.")

    def _update_ui(self, url: str, result: dict) -> None:
        """
        Push backend results into the existing frontend widgets.
        score    → gauge (0–10 already matches the frontend scale)
        flags    → flags_text label
        verdict  → warning_box color + multilingual message
        """
        score   = result["score"]
        verdict = result["verdict"]
        flags   = result["flags"]

        # Update gauge (uses the original draw_gauge — no changes)
        self.draw_gauge(score)

        # Update threat flags panel
        self.flags_text.config(text="\n".join(flags))

        # Update multilingual warning (same logic as original, now data-driven)
        if verdict == "PHISHING":
            self.warning_box.config(
                text="⚠️ హెచ్చరిక: ప్రమాదకరమైన లింక్ కనుగొనబడింది! (Telugu)\n"
                     "⚠️ चेतावनी: खतरनाक लिंक पाया गया! (Hindi)",
                fg="#ef4444"
            )
        elif verdict == "SUSPICIOUS":
            self.warning_box.config(
                text="⚠️ అనుమానాస్పద లింక్ — జాగ్రత్తగా కొనసాగండి (Telugu)\n"
                     "⚠️ संदिग्ध लिंक — सावधानी से आगे बढ़ें (Hindi)",
                fg="#eab308"
            )
        else:
            self.warning_box.config(
                text="✅ సురక్షితమైన లింక్ (Telugu) / सुरक्षित लिंक (Hindi)",
                fg="#22c55e"
            )

        # Save to history log (runs silently in background)
        threading.Thread(
            target=log_scan,
            args=(url, score, verdict, flags),
            daemon=True
        ).start()

    def _add_backend_controls(self):
        """
        Adds two extra buttons BELOW the original UI:
          • Upload QR Image  — opens file picker
          • Live Webcam QR   — opens webcam scanner
        These call the same backend functions and feed back into analyze().
        """
        btn_frame = tk.Frame(self.main_frame, bg="#0f172a")
        btn_frame.pack(pady=(0, 10))

        tk.Button(
            btn_frame,
            text="📷  Upload QR Image",
            command=self._pick_qr_image,
            bg="#1e40af", fg="blue",
            font=("Inter", 10, "bold"),
            padx=14, pady=7, relief="flat", cursor="hand2"
        ).pack(side="left", padx=8)

        tk.Button(
            btn_frame,
            text="📹  Live Webcam QR",
            command=self._webcam_qr,
            bg="#6d28d9", fg="blue",
            font=("Inter", 10, "bold"),
            padx=14, pady=7, relief="flat", cursor="hand2"
        ).pack(side="left", padx=8)

        tk.Button(
            btn_frame,
            text="📋  View Scan History",
            command=self._show_history,
            bg="#065f46", fg="blue",
            font=("Inter", 10, "bold"),
            padx=14, pady=7, relief="flat", cursor="hand2"
        ).pack(side="left", padx=8)

    def _pick_qr_image(self):
        """Open file dialog → decode QR → analyze URL."""
        path = filedialog.askopenfilename(
            title="Select QR Code Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.webp")]
        )
        if path:
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, path)
            self._run_qr_image_scan(path)

    def _webcam_qr(self):
        """
        Open webcam in a background thread so the Tkinter window
        stays responsive. Result is inserted into the URL field.
        """
        self.warning_box.config(text="📹 Opening webcam — point it at a QR code...", fg="#7dd3fc")
        self.root.update()

        def _scan():
            url = scan_qr_from_webcam(timeout_seconds=20)
            if url:
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, url)
                result = analyze_url(url)
                self.root.after(0, lambda: self._update_ui(url, result))
            else:
                self.root.after(0, lambda: self.warning_box.config(
                    text="No QR code detected via webcam. Try again or upload an image.",
                    fg="#94a3b8"
                ))

        threading.Thread(target=_scan, daemon=True).start()

    def _show_history(self):
        """Pop up a simple window showing the last 20 scans from the CSV log."""
        from logger import get_history

        records = get_history(20)
        win = tk.Toplevel(self.root)
        win.title("Scan History")
        win.geometry("700x400")
        win.configure(bg="#0f172a")

        tk.Label(win, text="Recent Scan History",
                 bg="#0f172a", fg="#7dd3fc",
                 font=("Inter", 14, "bold")).pack(pady=10)

        if not records:
            tk.Label(win, text="No scans recorded yet.",
                     bg="#0f172a", fg="#94a3b8").pack()
            return

        cols = ("Time", "URL", "Score", "Verdict")
        tree = ttk.Treeview(win, columns=cols, show="headings", height=14)
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=160 if col == "URL" else 90)

        for r in reversed(records):
            color_tag = r["verdict"].lower()
            tree.insert("", "end",
                        values=(r["timestamp"], r["url"][:40], r["score"], r["verdict"]),
                        tags=(color_tag,))

        tree.tag_configure("phishing",   foreground="#ef4444")
        tree.tag_configure("suspicious", foreground="#eab308")
        tree.tag_configure("safe",       foreground="#22c55e")
        tree.pack(fill="both", expand=True, padx=10, pady=5)


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app = PhishShieldApp(root)
    root.mainloop()
