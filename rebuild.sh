#!/bin/bash
set -e

echo "Clean up remaining processes"
pgrep -f "multiprocessing-fork" | xargs -r kill -9


echo "Syncing media..."
./media/sync_media.sh
echo "Media sync done."

echo "Decrypt database..."
.venv/bin/python decrypt/decrypt_all.py
echo "Decrypted"

echo "Building with 8 threads"
python3 store/build_store.py --jobs 8
echo "Done"

echo "Data self-checking is in progress..."
python3 search/verify_store.py

