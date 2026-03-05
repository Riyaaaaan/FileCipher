# =============================================================================
# app.py -- Flask-based XOR Encryption & Binary Analysis Tool
#
# Provides REST API endpoints for:
#   - File and text XOR encryption/decryption
#   - Binary file statistical analysis (NumPy + Pandas)
#   - Matplotlib chart generation (histogram, bar, line)
#   - Hex dump viewer
# =============================================================================

# -- Standard library imports --
import os
import sys
import array          # Fixed-type byte arrays for encryption keys
import io             # In-memory binary streams for chart export
import base64         # Base64 encoding for binary data transport
import json

# -- Third-party imports --
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Use non-interactive backend (no GUI needed for server)
import matplotlib.pyplot as plt
import matplotlib.style as mplstyle

from flask import Flask, request, jsonify, send_from_directory

# -- Flask app initialization --
app = Flask(__name__, static_folder="static")
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure upload directory exists

# Default 10-byte XOR key used when no custom key is provided
DEFAULT_KEY = array.array('B', [73, 42, 199, 88, 21, 156, 240, 9, 67, 134])

# -- Matplotlib dark style (green-on-black terminal aesthetic) --

PLOT_STYLE = {
    "figure.facecolor": "#0d0d0d",
    "axes.facecolor":   "#111111",
    "axes.edgecolor":   "#1a3a1a",
    "axes.labelcolor":  "#4ade80",
    "xtick.color":      "#2d6a3f",
    "ytick.color":      "#2d6a3f",
    "text.color":       "#4ade80",
    "grid.color":       "#1a3a1a",
    "grid.linestyle":   "--",
    "grid.alpha":       0.5,
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def parse_key(key_str):
    """Parse a comma-separated key string (e.g. '73,42,199') into a byte array.

    Each value must be in the range 0-255. Returns an array.array of
    unsigned bytes suitable for XOR encryption.
    """
    vals = [int(x.strip()) for x in key_str.split(",")]
    if not all(0 <= v <= 255 for v in vals):
        raise ValueError("Key values must be 0-255")
    return array.array('B', vals)

def xor_encrypt(data_bytes: np.ndarray, key: array.array) -> np.ndarray:
    """XOR-encrypt (or decrypt) a byte array using a repeating key.

    Uses NumPy for vectorized operation:
      1. Convert the key to a NumPy uint8 array
      2. Tile (repeat) the key to match the data length
      3. Apply bitwise XOR element-wise

    XOR is symmetric, so the same function handles both encrypt and decrypt.
    """
    key_np = np.array(list(key), dtype=np.uint8)
    # Repeat the key to cover the entire data length
    key_tiled = np.tile(key_np, int(np.ceil(len(data_bytes) / len(key_np))))[:len(data_bytes)]
    return np.bitwise_xor(data_bytes, key_tiled)

def make_chart_b64(fig) -> str:
    """Render a Matplotlib figure to a base64-encoded PNG string.

    Saves the figure to an in-memory buffer, encodes it as base64,
    and closes the figure to free memory.
    """
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=110)
    buf.seek(0)
    plt.close(fig)  # Free memory -- important in a long-running server
    return base64.b64encode(buf.read()).decode()

# =============================================================================
# API ROUTES
# =============================================================================

@app.route("/")
def index():
    """Serve the main frontend page."""
    return send_from_directory("static", "index.html")

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    """Encrypt or decrypt an uploaded file via XOR cipher.

    Expects multipart form data with:
      - file: the file to process
      - key (optional): comma-separated byte values for the XOR key
      - mode (optional): 'encrypt' or 'decrypt'

    Returns JSON with the base64-encoded result.
    """
    f = request.files.get("file")
    key_str = request.form.get("key", ",".join(str(b) for b in DEFAULT_KEY))
    mode = request.form.get("mode", "encrypt")

    # Validate and parse the encryption key
    try:
        key = parse_key(key_str)
    except Exception as e:
        return jsonify({"error": f"Invalid key: {e}"}), 400

    # Read file bytes into a NumPy array and apply XOR encryption
    raw = np.frombuffer(f.read(), dtype=np.uint8)
    processed = xor_encrypt(raw, key)
    result_b64 = base64.b64encode(processed.tobytes()).decode()

    return jsonify({
        "filename": f.filename,
        "mode": mode,
        "original_size": int(raw.size),
        "result_b64": result_b64,
    })

@app.route("/api/encrypt_text", methods=["POST"])
def api_encrypt_text():
    """Encrypt or decrypt a text string via XOR cipher.

    Expects JSON body with:
      - text: plaintext (encrypt mode) or base64 string (decrypt mode)
      - key (optional): comma-separated byte values
      - mode (optional): 'encrypt' or 'decrypt'

    Returns JSON with the processed result.
    """
    data = request.get_json()
    text = data.get("text", "")
    key_str = data.get("key", ",".join(str(b) for b in DEFAULT_KEY))
    mode = data.get("mode", "encrypt")

    # Validate and parse the encryption key
    try:
        key = parse_key(key_str)
    except Exception as e:
        return jsonify({"error": f"Invalid key: {e}"}), 400

    if mode == "encrypt":
        # Encode text to UTF-8 bytes, XOR-encrypt, and return as base64
        raw = np.frombuffer(text.encode("utf-8"), dtype=np.uint8)
        processed = xor_encrypt(raw, key)
        result = base64.b64encode(processed.tobytes()).decode()
    else:
        # Decode base64 input, XOR-decrypt, and return as UTF-8 text
        try:
            raw_bytes = base64.b64decode(text)
            raw = np.frombuffer(raw_bytes, dtype=np.uint8)
            processed = xor_encrypt(raw, key)
            result = processed.tobytes().decode("utf-8", errors="replace")
        except Exception as e:
            return jsonify({"error": f"Decryption failed: {e}"}), 400

    return jsonify({"result": result, "bytes": int(raw.size)})

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Analyze an uploaded file's byte distribution.

    Returns JSON with:
      - pandas_describe: summary statistics from pd.DataFrame.describe()
      - numpy_stats: unique byte count, most common byte, entropy
      - top20: top 20 most frequent byte values
      - charts: base64-encoded PNG images (histogram, bar, line)
    """
    f = request.files.get("file")
    raw = np.frombuffer(f.read(), dtype=np.uint8)  # Read file into NumPy array

    # -- Pandas: generate summary statistics via describe() --
    df = pd.DataFrame({"byte_value": raw})
    desc = df["byte_value"].describe()
    pandas_summary = {
        "count":  int(desc["count"]),
        "mean":   round(float(desc["mean"]), 4),
        "std":    round(float(desc["std"]), 4),
        "min":    int(desc["min"]),
        "25%":    int(desc["25%"]),
        "50%":    int(desc["50%"]),
        "75%":    int(desc["75%"]),
        "max":    int(desc["max"]),
    }

    # -- NumPy: compute additional statistics (unique bytes, entropy) --
    unique_vals, counts = np.unique(raw, return_counts=True)
    top_idx = np.argmax(counts)
    numpy_stats = {
        "unique_bytes": int(unique_vals.size),
        "most_common_byte": int(unique_vals[top_idx]),
        "most_common_count": int(counts[top_idx]),
        # Shannon entropy: measures randomness of byte distribution
        "entropy": float(
            -np.sum((counts / raw.size) * np.log2(counts / raw.size + 1e-12))
        ),
    }

    # -- Pandas: get the 20 most frequent byte values --
    top20 = df["byte_value"].value_counts().head(20).reset_index()
    top20.columns = ["byte", "count"]
    top20_list = top20.to_dict(orient="records")  # Convert to list of dicts for JSON

    # Chart 1: Matplotlib Histogram (byte frequency distribution)
    with plt.rc_context(PLOT_STYLE):
        fig, ax = plt.subplots(figsize=(7, 2.8))
        ax.hist(raw, bins=64, color="#16a34a", edgecolor="#0d0d0d", alpha=0.85, linewidth=0.4)
        ax.set_xlabel("Byte Value (0-255)", fontsize=9)
        ax.set_ylabel("Frequency", fontsize=9)
        ax.set_title("plt.hist() -- Byte Frequency Distribution", fontsize=10, color="#86efac")
        ax.grid(True)
        fig.tight_layout()
    chart_hist = make_chart_b64(fig)

    # Chart 2: Matplotlib bar -- top 20 most frequent bytes
    with plt.rc_context(PLOT_STYLE):
        fig2, ax2 = plt.subplots(figsize=(7, 2.8))
        colors = plt.cm.YlGn(np.linspace(0.4, 1.0, len(top20)))
        ax2.bar(
            [f"0x{b:02X}" for b in top20["byte"]],
            top20["count"],
            color=colors, edgecolor="#0d0d0d", linewidth=0.4
        )
        ax2.set_xlabel("Byte (hex)", fontsize=9)
        ax2.set_ylabel("Count", fontsize=9)
        ax2.set_title("plt.bar() -- Top 20 Most Frequent Bytes", fontsize=10, color="#86efac")
        ax2.tick_params(axis="x", rotation=45, labelsize=7)
        ax2.grid(True, axis="y")
        fig2.tight_layout()
    chart_bar = make_chart_b64(fig2)

    # -- Chart 3: Line plot of raw bytes with pandas rolling mean overlay --
    with plt.rc_context(PLOT_STYLE):
        sample = raw[:2000] if len(raw) > 2000 else raw  # Limit to 2000 points for performance
        roll_df = pd.DataFrame({"val": sample})
        rolled = roll_df["val"].rolling(window=20, min_periods=1).mean()
        fig3, ax3 = plt.subplots(figsize=(7, 2.8))
        ax3.plot(sample, color="#1a3a1a", linewidth=0.6, alpha=0.6, label="raw bytes")
        ax3.plot(rolled.values, color="#4ade80", linewidth=1.5, label="rolling mean (w=20)")
        ax3.set_xlabel("Byte Index", fontsize=9)
        ax3.set_ylabel("Value", fontsize=9)
        ax3.set_title("plt.plot() -- Raw Bytes + pandas.rolling().mean()", fontsize=10, color="#86efac")
        ax3.legend(fontsize=8, facecolor="#111", edgecolor="#1a3a1a", labelcolor="#86efac")
        ax3.grid(True)
        fig3.tight_layout()
    chart_line = make_chart_b64(fig3)

    return jsonify({
        "filename": f.filename,
        "pandas_describe": pandas_summary,
        "numpy_stats": numpy_stats,
        "top20": top20_list,
        "charts": {
            "histogram": chart_hist,
            "bar": chart_bar,
            "line": chart_line,
        }
    })

@app.route("/api/hexdump", methods=["POST"])
def api_hexdump():
    """Return a hex dump of the first 512 bytes of an uploaded file.

    Output format matches the classic `hexdump -C` style:
      offset  hex bytes                                  |ASCII|
    """
    f = request.files.get("file")
    raw = np.frombuffer(f.read(), dtype=np.uint8)
    lines = []
    for i in range(0, min(len(raw), 512), 16):  # Display at most 512 bytes
        chunk = raw[i:i+16]
        # Format each byte as two-digit hex
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Show printable ASCII chars; replace non-printable with '.'
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<47}  |{asc_part}|")
    return jsonify({"dump": "\n".join(lines), "total_bytes": int(raw.size)})

@app.route("/api/create_test", methods=["POST"])
def api_create_test():
    """Generate a sample test file as base64 for frontend use.

    Accepts optional JSON body with 'content' field;
    falls back to a default demo string if not provided.
    """
    content = request.get_json().get("content", "Hello, World!\nTest file for encryption.\nNumPy + Pandas + Matplotlib.")
    raw = np.frombuffer(content.encode("utf-8"), dtype=np.uint8)
    b64 = base64.b64encode(raw.tobytes()).decode()
    return jsonify({"b64": b64, "size": int(raw.size), "filename": "test.txt"})

# -- Entry point: start the Flask development server on port 5050 --
if __name__ == "__main__":
    app.run(debug=False, port=5050)
