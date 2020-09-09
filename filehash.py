import subprocess
import hashlib


def get_file_hash(path: str, *, manual: bool = False) -> str:
    return _manual_hash(path) if manual else _os_hash(path)


def _manual_hash(path: str) -> str:
    """Calculates the SHA256 digest of a file with hashlib"""
    with open(path, 'rb') as f:
        content = f.read()
    return hashlib.sha256(content).hexdigest()


def _os_hash(path: str) -> str:
    """Calculates the SHA256 digest of a file with certutil"""
    sp = subprocess.Popen(['certutil', '-hashfile', path, 'SHA256'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True)
    return sp.stdout.read().split('\n')[1]  # Split the output string and return the SHA256 digest on the second line

