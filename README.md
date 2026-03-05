# Binary File Encryptor

A Flask-based XOR encryption and binary analysis tool with a terminal-aesthetic web UI.

## Features

- **XOR Encryption/Decryption** — Encrypt and decrypt files or text using a repeating XOR key (symmetric cipher)
- **Binary Analysis** — Upload a file to get byte-distribution statistics powered by NumPy and Pandas
- **Chart Generation** — Matplotlib-rendered histogram, bar chart, and line plot of byte data (dark green-on-black theme)
- **Hex Dump Viewer** — Classic `hexdump -C` style view of uploaded file contents

## Tech Stack

| Layer    | Technology                        |
| -------- | --------------------------------- |
| Backend  | Python 3, Flask                   |
| Analysis | NumPy, Pandas                     |
| Charts   | Matplotlib (Agg backend)          |
| Frontend | Vanilla HTML/CSS/JS (single-page) |

## Getting Started

### Prerequisites

- Python 3.8+

### Installation

```bash
# Clone the repository
git clone <repo-url> && cd python-mini

# Create a virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install flask numpy pandas matplotlib
```

### Running

```bash
source .venv/bin/activate
python3 app.py
```

The server starts at **http://localhost:5050**.

## API Endpoints

### `POST /api/encrypt`

Encrypt or decrypt a file via XOR cipher.

- **Content-Type:** `multipart/form-data`
- **Fields:**
  - `file` — the file to process
  - `key` _(optional)_ — comma-separated byte values (0–255), e.g. `73,42,199`
  - `mode` _(optional)_ — `encrypt` or `decrypt`
- **Returns:** JSON with `result_b64` (base64-encoded output)

### `POST /api/encrypt_text`

Encrypt or decrypt a text string via XOR cipher.

- **Content-Type:** `application/json`
- **Body:** `{ "text": "...", "key": "73,42,199", "mode": "encrypt" }`
- **Returns:** JSON with `result` (base64 string on encrypt, plaintext on decrypt)

### `POST /api/analyze`

Analyze byte distribution of an uploaded file.

- **Content-Type:** `multipart/form-data`
- **Fields:** `file`
- **Returns:** JSON with:
  - `pandas_describe` — summary statistics (count, mean, std, quartiles)
  - `numpy_stats` — unique byte count, most common byte, Shannon entropy
  - `top20` — 20 most frequent byte values
  - `charts` — base64-encoded PNG images (histogram, bar, line)

### `POST /api/hexdump`

Returns a hex dump of the first 512 bytes of an uploaded file.

- **Content-Type:** `multipart/form-data`
- **Fields:** `file`
- **Returns:** JSON with `dump` (formatted hex dump string)

### `POST /api/create_test`

Generate a sample test file.

- **Content-Type:** `application/json`
- **Body:** `{ "content": "optional custom text" }`
- **Returns:** JSON with `b64` (base64-encoded file content)

## Project Structure

```
python-mini/
├── app.py              # Flask backend (API + XOR logic + chart generation)
├── static/
│   └── index.html      # Single-page frontend
├── uploads/            # Upload directory (created automatically)
└── README.md
```

## Default XOR Key

If no key is provided, the app uses a 10-byte default key:

```
[73, 42, 199, 88, 21, 156, 240, 9, 67, 134]
```

## License

MIT
