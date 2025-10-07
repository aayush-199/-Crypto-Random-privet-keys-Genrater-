# Crypto Random privet keys Genrater 

import hashlib, secrets
from pathlib import Path

WORDLIST_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
CACHE = Path.home() / ".bip39_wordlist.txt"

def load_wordlist():
    try:
        from mnemonic import Mnemonic
        return Mnemonic("english").wordlist
    except Exception:
        pass
    if CACHE.exists():
        w = [l.strip() for l in CACHE.read_text(encoding="utf-8").splitlines() if l.strip()]
        if len(w) == 2048: return w
    import urllib.request
    txt = urllib.request.urlopen(WORDLIST_URL, timeout=10).read().decode("utf-8")
    words = [l.strip() for l in txt.splitlines() if l.strip()]
    if len(words) == 2048:
        CACHE.write_text("\n".join(words), encoding="utf-8")
        return words
    raise RuntimeError("Wordlist not available.")

def bits_from_bytes(b: bytes) -> str:
    return "".join(f"{x:08b}" for x in b)

def generate_mnemonic():
    wordlist = load_wordlist()
    ent = secrets.token_bytes(16)  # 128 bits for 12 words
    checksum_len = 128 // 32
    ent_bits = bits_from_bytes(ent)
    chk = bits_from_bytes(hashlib.sha256(ent).digest())[:checksum_len]
    bits = ent_bits + chk
    chunks = [bits[i:i+11] for i in range(0, len(bits), 11)]
    words = [wordlist[int(c,2)] for c in chunks]
    return " ".join(words)

if __name__ == "__main__":
    print(generate_mnemonic())
