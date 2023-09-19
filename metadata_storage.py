import json
import hashlib
import base64
import os

def save_metadata(metadata, file_path=None):
    if file_path is None:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir, "metadata.json")
    print("Inside save_metadata function")
    with open(file_path, "w") as f:
        json.dump(metadata, f)
    print("Metadata saved.")

def load_metadata(file_path="metadata.json"):
    print("Inside load_metadata function")
    try:
        with open(file_path, "r") as f:
            print("Metadata loaded.")
            return json.load(f)
    except FileNotFoundError:
        return {}
    
def generate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def add_file_metadata(file_path, iv, tag, salt, metadata_file="metadata.json"):
    file_hash = generate_file_hash(file_path)
    file_type = file_path.split(".")[-1]
    metadata = load_metadata(metadata_file)
    
    metadata[file_hash] = {
        "file_type": file_type,
        "file_name": file_path.split("/")[-1],
        "iv": base64.b64encode(iv).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8')
    }
    
    save_metadata(metadata, metadata_file)

def get_file_metadata(file_hash, metadata_file="metadata.json"):
    metadata = load_metadata(metadata_file)
    if file_hash in metadata:
        return {
            "file_type": metadata[file_hash]["file_type"],
            "file_name": metadata[file_hash]["file_name"],
            "iv": base64.b64decode(metadata[file_hash]["iv"].encode('utf-8')),
            "tag": base64.b64decode(metadata[file_hash]["tag"].encode('utf-8')),
            "salt": base64.b64decode(metadata[file_hash]["salt"].encode('utf-8'))
        }
    else:
        return None
