"""Download the CPU-side security encoders and the Indic translator into HF_HOME (D:\\hf-cache).

IndicTrans2: the official ai4bharat repo is gated; the naklitechie mirror is byte-identical
(model.safetensors sha256 0039e4304e98... matches the official LFS pointer) and MIT-licensed.
"""

import os
import sys

os.environ.setdefault("HF_HOME", r"D:\hf-cache")
from huggingface_hub import snapshot_download  # noqa: E402

REPOS = {
    "cisco-ai/SecureBERT2.0-biencoder": None,
    "cisco-ai/SecureBERT2.0-NER": None,
    "cisco-ai/SecureBERT2.0-cross_encoder": None,
    "naklitechie/indictrans2-en-indic-dist-200M": ["pytorch_model.bin"],  # safetensors is enough
}


def main() -> int:
    for repo, skip in REPOS.items():
        path = snapshot_download(repo, ignore_patterns=skip)
        size = sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(path) for f in fs)
        print(f"OK {repo} -> {path} ({size / 1e6:.0f} MB)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
