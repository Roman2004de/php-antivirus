# Panelica Malware Signatures

This directory is used for attribution files generated when Panelica Malware Signatures hashes are imported.

The module does not bundle Panelica data by default and does not download it during installation. During local import it copies the source LICENSE file, writes `import_metadata.json`, and converts hash signatures into the delement.antivirus internal JSON format.

When the explicit download/import action is used, only `LICENSE`, `json/hashes.json`, and `hashes/sha256.txt` are downloaded into `downloads/` before the same importer runs.
