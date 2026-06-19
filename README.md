# 🛠️ MalFixer

**MalFixer** is a comprehensive toolkit for inspecting and recovering malformed Android APK files. It is designed to assist malware analysts, reverse engineers, and mobile security researchers in handling APKs that intentionally evade analysis by exploiting ZIP structure weaknesses, corrupting AndroidManifest.xml, or embedding obfuscated payloads within assets.

MalFixer inspects the APK structure, repairs corrupted ZIP entries, decodes and reconstructs malformed Android manifests, and extracts or sanitises problematic asset files. The output is a cleaned APK file suitable for static analysis.

---

## 🔍 Features

- 📦 **ZIP Structure Repair**: Detects and corrects malformed central/local directory entries (via `zipfixer.py`)
- 🧾 **Manifest Recovery**: Decodes and reconstructs broken or corrupted `AndroidManifest.xml` files (via `manfixer.py`)
- 📁 **Asset Sanitisation**: Identifies and recovers assets with malformed filenames (via `astfixer.py`)
- 🗂️ **Resource Table Repair**: Parses and repairs corrupted `resources.arsc` files, fixing bad chunk headers, invalid string pool offsets, and malformed entry data (via `arscfixer.py`)
- 🔄 **APK Repackaging**: Rebuilds a clean APK compatible with popular tools like JADX.
- ✍️ **APK Re-signing**: Optionally re-signs the recovered APK using a freshly generated RSA key pair and APK Signature Scheme v2, producing an installable artifact (via `apksigner.py`)

---

## 📂 Project Structure

```
malfixer/
├── malfixer.py    # Orchestrates all components to recover the APK
├── zipfixer.py    # Repairs malformed ZIP structures
├── manfixer.py    # Repairs malformed AndroidManifest.xml files
├── astfixer.py    # Recovers corrupted or obfuscated assets
├── arscfixer.py   # Parses and repairs corrupted resources.arsc files
├── apksigner.py   # Re-signs the recovered APK (pure-Python, no external tools)
```

---

## 🚀 Usage

```bash
python malfixer.py [-h] [--output-dir OUTPUT_DIR] [--resign]
                   [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                   [--version] apk_path
```

### Positional Arguments
- `apk_path`: Path to the input APK file

### Optional Arguments
- `-h`, `--help`: Show help message and exit
- `--output-dir OUTPUT_DIR`: Output directory for the recovered APK (default: same directory as input)
- `--resign`: Re-sign and zipalign the recovered APK using a freshly generated RSA-2048 key and APK Signature Scheme v2. **Note:** this replaces the original certificate — the output will not match the original developer's signature.
- `--log-level`, `-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}`: Set log verbosity (default: `ERROR`)
- `--version`: Display the tool version

---

### 🔧 Examples

Recover a malformed APK and write the result in the same directory (output file will be named `app-fixed.apk`):
```bash
python malfixer.py /path/to/app.apk
```

Recover an APK and output to a specified directory:
```bash
python malfixer.py /path/to/app.apk --output-dir /path/to/output
```

Recover and re-sign the APK so it can be installed or analysed by tools that require a valid signature:
```bash
python malfixer.py /path/to/app.apk --resign
```

Enable verbose logging for troubleshooting:
```bash
python malfixer.py /path/to/app.apk -l DEBUG
```

---

## 🧪 Compatibility

MalFixer is compatible with Python 3.8+ and tested on major platforms (Linux, macOS). It is designed for forensic and research purposes and should not be used for repackaging legitimate applications.

---

## 📜 License

[MIT License](https://github.com/Cleafy/Malfixer/blob/main/LICENSE)

---

## 🤝 Contributing

Pull requests are welcome! If you encounter a new form of APK malformation in the wild, feel free to open an issue or submit a patch.

---

## 🛡️ Disclaimer

This tool is intended for educational and research purposes only. Use responsibly and in accordance with local laws and regulations.
