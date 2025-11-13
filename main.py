import sys
import os
import zlib
import hashlib
import time
import urllib.request
import struct


def read_object(sha):
    """Read and decompress a Git object."""
    path = f".git/objects/{sha[:2]}/{sha[2:]}"
    with open(path, "rb") as f:
        compressed = f.read()
    decompressed = zlib.decompress(compressed)
    null_idx = decompressed.find(b"\x00")
    header = decompressed[:null_idx].decode()
    content = decompressed[null_idx + 1:]
    obj_type = header.split()[0]
    return obj_type, content


def checkout_tree(tree_sha, path="."):
    """Recursively checkout a tree object."""
    _, tree_content = read_object(tree_sha)
    
    i = 0
    while i < len(tree_content):
        # Find space after mode
        space_idx = tree_content.find(b" ", i)
        mode = tree_content[i:space_idx]
        
        # Find null after name
        null_idx = tree_content.find(b"\x00", space_idx)
        name = tree_content[space_idx + 1:null_idx].decode()
        
        # Read SHA (20 bytes)
        sha = tree_content[null_idx + 1:null_idx + 21]
        sha_hex = sha.hex()
        
        # Move to next entry
        i = null_idx + 21
        
        # Create path
        full_path = os.path.join(path, name)
        
        if mode == b"40000":
            # Directory
            os.makedirs(full_path, exist_ok=True)
            checkout_tree(sha_hex, full_path)
        else:
            # File
            _, content = read_object(sha_hex)
            with open(full_path, "wb") as f:
                f.write(content)
            
            # Set executable permission if needed
            if mode == b"100755":
                os.chmod(full_path, 0o755)
            else:
                os.chmod(full_path, 0o644)


def checkout_commit(commit_sha):
    """Checkout a commit by extracting its tree."""
    _, commit_content = read_object(commit_sha)
    
    # Parse commit to find tree SHA
    lines = commit_content.decode().split('\n')
    tree_sha = None
    
    for line in lines:
        if line.startswith('tree '):
            tree_sha = line.split()[1]
            break
    
    if not tree_sha:
        raise ValueError("Could not find tree in commit")
    
    # Checkout the tree
    checkout_tree(tree_sha)


def write_tree(directory="."):
    entries = []
    with os.scandir(directory) as it:
        sorted_entries = sorted(it, key=lambda e: e.name)
        for entry in sorted_entries:
            if entry.name == ".git":
                continue

            if entry.is_dir():
                mode = b"40000"
                sha = bytes.fromhex(write_tree(entry.path))
                entries.append((mode, entry.name.encode(), sha))
            else:
                if os.stat(entry.path).st_mode & 0o111:
                    mode = b"100755"
                else:
                    mode = b"100644"

                with open(entry.path, "rb") as f:
                    content = f.read()

                blob_object = b"blob %d\x00%s" % (len(content), content)
                hex_sha = hashlib.sha1(blob_object).hexdigest()

                object_dir = f".git/objects/{hex_sha[:2]}"
                os.makedirs(object_dir, exist_ok=True)
                object_path = f"{object_dir}/{hex_sha[2:]}"
                with open(object_path, "wb") as f:
                    f.write(zlib.compress(blob_object))

                sha = bytes.fromhex(hex_sha)
                entries.append((mode, entry.name.encode(), sha))

    tree_content = b"".join(
        mode + b" " + name + b"\x00" + sha for mode, name, sha in entries
    )

    tree_header = b"tree %d\x00" % len(tree_content)
    tree_object = tree_header + tree_content

    tree_hex_sha = hashlib.sha1(tree_object).hexdigest()

    object_dir = f".git/objects/{tree_hex_sha[:2]}"
    os.makedirs(object_dir, exist_ok=True)
    object_path = f"{object_dir}/{tree_hex_sha[2:]}"
    with open(object_path, "wb") as f:
        f.write(zlib.compress(tree_object))

    return tree_hex_sha


def read_varint(data, offset):
    """Read Git's variable-length integer encoding (MSB format)."""
    byte = data[offset]
    value = byte & 0x7f
    offset += 1
    
    while byte & 0x80:
        byte = data[offset]
        value = ((value + 1) << 7) | (byte & 0x7f)
        offset += 1
    
    return value, offset


def read_size_encoding(data, offset):
    """Read size from the packfile object header."""
    byte = data[offset]
    obj_type = (byte >> 4) & 0x07
    size = byte & 0x0f
    offset += 1
    shift = 4
    
    while byte & 0x80:
        byte = data[offset]
        size |= (byte & 0x7f) << shift
        shift += 7
        offset += 1
    
    return obj_type, size, offset


def apply_delta(base_data, delta_data):
    """Apply delta instructions to base data."""
    offset = 0
    
    # Read base object size
    base_size, offset = read_varint(delta_data, offset)
    
    # Read result object size
    result_size, offset = read_varint(delta_data, offset)
    
    result = bytearray()
    
    while offset < len(delta_data):
        instruction = delta_data[offset]
        offset += 1
        
        if instruction & 0x80:  # Copy instruction
            cp_offset = 0
            cp_size = 0
            
            # Read offset
            if instruction & 0x01:
                cp_offset = delta_data[offset]
                offset += 1
            if instruction & 0x02:
                cp_offset |= delta_data[offset] << 8
                offset += 1
            if instruction & 0x04:
                cp_offset |= delta_data[offset] << 16
                offset += 1
            if instruction & 0x08:
                cp_offset |= delta_data[offset] << 24
                offset += 1
            
            # Read size
            if instruction & 0x10:
                cp_size = delta_data[offset]
                offset += 1
            if instruction & 0x20:
                cp_size |= delta_data[offset] << 8
                offset += 1
            if instruction & 0x40:
                cp_size |= delta_data[offset] << 16
                offset += 1
            
            if cp_size == 0:
                cp_size = 0x10000
            
            result.extend(base_data[cp_offset:cp_offset + cp_size])
        else:  # Insert instruction
            if instruction == 0:
                raise ValueError("Invalid delta instruction")
            result.extend(delta_data[offset:offset + instruction])
            offset += instruction
    
    return bytes(result)


def unpack_object(data, offset, objects_by_offset):
    """Unpack a single object from the packfile."""
    start_offset = offset
    obj_type, size, offset = read_size_encoding(data, offset)
    
    # Type constants
    OBJ_COMMIT = 1
    OBJ_TREE = 2
    OBJ_BLOB = 3
    OBJ_TAG = 4
    OBJ_OFS_DELTA = 6
    OBJ_REF_DELTA = 7
    
    type_map = {
        OBJ_COMMIT: b"commit",
        OBJ_TREE: b"tree",
        OBJ_BLOB: b"blob",
        OBJ_TAG: b"tag",
    }
    
    if obj_type == OBJ_OFS_DELTA:
        # Read negative offset
        neg_offset = data[offset] & 0x7f
        offset += 1
        while data[offset - 1] & 0x80:
            neg_offset = ((neg_offset + 1) << 7) | (data[offset] & 0x7f)
            offset += 1
        
        base_offset = start_offset - neg_offset
        base_data = objects_by_offset[base_offset]
        
        # Decompress delta data
        decompressor = zlib.decompressobj()
        delta_data = decompressor.decompress(data[offset:])
        
        # Apply delta
        content = apply_delta(base_data, delta_data)
        offset += len(data[offset:]) - len(decompressor.unused_data)
        
    elif obj_type == OBJ_REF_DELTA:
        # Read base object SHA (20 bytes)
        base_sha = data[offset:offset + 20]
        offset += 20
        
        # Find base object
        base_sha_hex = base_sha.hex()
        base_path = f".git/objects/{base_sha_hex[:2]}/{base_sha_hex[2:]}"
        
        with open(base_path, "rb") as f:
            compressed = f.read()
        decompressed = zlib.decompress(compressed)
        null_idx = decompressed.find(b"\x00")
        base_data = decompressed[null_idx + 1:]
        
        # Decompress delta data
        decompressor = zlib.decompressobj()
        delta_data = decompressor.decompress(data[offset:])
        
        # Apply delta
        content = apply_delta(base_data, delta_data)
        offset += len(data[offset:]) - len(decompressor.unused_data)
        
    else:
        # Regular object
        decompressor = zlib.decompressobj()
        content = decompressor.decompress(data[offset:])
        offset += len(data[offset:]) - len(decompressor.unused_data)
    
    # Store object for delta resolution
    objects_by_offset[start_offset] = content
    
    # Write object to disk
    if obj_type in type_map:
        obj_type_name = type_map[obj_type]
    else:
        # For delta objects, we need to determine type from base
        # For now, we'll determine it when we have the full content
        # We'll store temporarily and fix later
        obj_header = b"blob %d\x00" % len(content)
        obj_data = obj_header + content
        sha1 = hashlib.sha1(obj_data).hexdigest()
        
        # Try to determine actual type from content structure
        if content.startswith(b"tree ") or (b"\x00" in content[:100] and b" " in content[:10]):
            obj_type_name = b"tree"
        elif content.startswith(b"parent ") or content.startswith(b"tree "):
            obj_type_name = b"commit"
        else:
            obj_type_name = b"blob"
    
    obj_header = b"%s %d\x00" % (obj_type_name, len(content))
    obj_data = obj_header + content
    sha1 = hashlib.sha1(obj_data).hexdigest()
    
    object_dir = f".git/objects/{sha1[:2]}"
    os.makedirs(object_dir, exist_ok=True)
    object_path = f"{object_dir}/{sha1[2:]}"
    
    with open(object_path, "wb") as f:
        f.write(zlib.compress(obj_data))
    
    return offset, sha1


def parse_sideband_data(data):
    """Parse side-band multiplexed data and extract packfile."""
    result = bytearray()
    offset = 0
    
    while offset < len(data):
        if offset + 4 > len(data):
            break
        
        # Read pkt-line length
        length_hex = data[offset:offset + 4]
        try:
            length = int(length_hex, 16)
        except ValueError:
            break
        
        if length == 0:
            # Flush packet
            offset += 4
            continue
        
        if length < 4 or offset + length > len(data):
            break
        
        # Get packet payload
        payload = data[offset + 4:offset + length]
        
        if len(payload) > 0:
            band = payload[0]
            packet_data = payload[1:]
            
            if band == 1:
                # Band 1: packfile data
                result.extend(packet_data)
            elif band == 2:
                # Band 2: progress messages
                print(packet_data.decode('utf-8', errors='ignore').strip(), file=sys.stderr)
            elif band == 3:
                # Band 3: error messages
                print("Error from server:", packet_data.decode('utf-8', errors='ignore').strip(), file=sys.stderr)
        
        offset += length
    
    return bytes(result)


def parse_pkt_line(data):
    """Parse Git pkt-line format."""
    lines = []
    offset = 0
    
    while offset < len(data):
        if offset + 4 > len(data):
            break
            
        length_hex = data[offset:offset + 4].decode('ascii')
        
        if length_hex == "0000":
            lines.append(None)  # Flush packet
            offset += 4
        else:
            length = int(length_hex, 16)
            if length < 4:
                break
            line_data = data[offset + 4:offset + length]
            lines.append(line_data)
            offset += length
    
    return lines


def clone_repository(repo_url, directory):
    """Clone a Git repository using Smart HTTP protocol."""
    print(f"Cloning into '{directory}'...", file=sys.stderr)
    
    # Create directory structure
    os.makedirs(directory, exist_ok=True)
    os.chdir(directory)
    os.makedirs(".git/objects", exist_ok=True)
    os.makedirs(".git/refs/heads", exist_ok=True)
    
    # Ensure URL ends properly
    if not repo_url.endswith('.git'):
        repo_url += '.git'
    
    # Step 1: Discover refs
    refs_url = f"{repo_url}/info/refs?service=git-upload-pack"
    
    req = urllib.request.Request(refs_url)
    with urllib.request.urlopen(req) as response:
        refs_data = response.read()
    
    lines = parse_pkt_line(refs_data)
    
    # Find HEAD and other refs
    head_sha = None
    refs = {}
    
    for line in lines:
        if line is None:
            continue
        
        line_str = line.decode('utf-8', errors='ignore')
        
        if line_str.startswith('#'):
            continue
        
        parts = line_str.strip().split('\x00')[0].split()
        if len(parts) >= 2:
            sha, ref = parts[0], parts[1]
            refs[ref] = sha
            
            if ref == "HEAD":
                head_sha = sha
    
    if not head_sha:
        print("Error: Could not find HEAD", file=sys.stderr)
        return
    
    print(f"Found HEAD at {head_sha}", file=sys.stderr)
    
    # Step 2: Create upload-pack request
    # Format: want <sha>\n capabilities (no capabilities for now, just want)
    capabilities = " multi_ack_detailed side-band-64k thin-pack ofs-delta"
    want_line = f"want {head_sha}{capabilities}\n"
    want_pkt = f"{len(want_line) + 4:04x}{want_line}"
    
    # Flush packet then done
    request_body = want_pkt.encode() + b"00000009done\n"
    
    print(f"Sending request: {request_body[:100]}", file=sys.stderr)
    
    upload_url = f"{repo_url}/git-upload-pack"
    
    req = urllib.request.Request(
        upload_url,
        data=request_body,
        headers={
            'Content-Type': 'application/x-git-upload-pack-request'
        }
    )
    
    with urllib.request.urlopen(req) as response:
        pack_response = response.read()
    
    print(f"Received {len(pack_response)} bytes from server", file=sys.stderr)
    
    # The response contains side-band multiplexed data
    # We need to extract the actual packfile from band 1
    pack_data = parse_sideband_data(pack_response)
    
    print(f"Extracted {len(pack_data)} bytes of packfile data", file=sys.stderr)
    
    # Step 3: Unpack packfile
    if not pack_data.startswith(b"PACK"):
        print(f"Error: Invalid packfile - starts with: {pack_data[:20]}", file=sys.stderr)
        return
    
    version = struct.unpack(">I", pack_data[4:8])[0]
    num_objects = struct.unpack(">I", pack_data[8:12])[0]
    
    print(f"Unpacking {num_objects} objects...", file=sys.stderr)
    
    offset = 12
    objects_by_offset = {}
    
    for i in range(num_objects):
        offset, sha = unpack_object(pack_data, offset, objects_by_offset)
    
    # Step 4: Update HEAD and refs
    with open(".git/HEAD", "w") as f:
        f.write("ref: refs/heads/main\n")
    
    with open(".git/refs/heads/main", "w") as f:
        f.write(head_sha + "\n")
    
    # Step 5: Checkout the working tree
    checkout_commit(head_sha)
    
    print(f"Successfully cloned repository", file=sys.stderr)


def main():
    print("Logs from your program will appear here!", file=sys.stderr)

    command = sys.argv[1]
    if command == "init":
        os.mkdir(".git")
        os.mkdir(".git/objects")
        os.mkdir(".git/refs")
        with open(".git/HEAD", "w") as f:
            f.write("ref: refs/heads/main\n")
        print("Initialized git directory")
    elif command == "cat-file":
        if sys.argv[2] == "-p":
            blob_sha = sys.argv[3]
            path = f".git/objects/{blob_sha[:2]}/{blob_sha[2:]}"
            with open(path, "rb") as f:
                compressed_contents = f.read()
                decompressed_contents = zlib.decompress(compressed_contents)
                content_start_index = decompressed_contents.find(b"\x00") + 1
                content = decompressed_contents[content_start_index:]
                sys.stdout.buffer.write(content)
    elif command == "hash-object":
        if sys.argv[2] == "-w":
            file_path = sys.argv[3]
            with open(file_path, "rb") as f:
                content = f.read()

            blob_object = b"blob %d\x00%s" % (len(content), content)
            sha1 = hashlib.sha1(blob_object).hexdigest()

            object_dir = f".git/objects/{sha1[:2]}"
            os.makedirs(object_dir, exist_ok=True)
            object_path = f"{object_dir}/{sha1[2:]}"
            with open(object_path, "wb") as f:
                f.write(zlib.compress(blob_object))

            print(sha1)
    elif command == "ls-tree":
        if sys.argv[2] == "--name-only":
            tree_sha = sys.argv[3]
            path = f".git/objects/{tree_sha[:2]}/{tree_sha[2:]}"
            with open(path, "rb") as f:
                compressed_contents = f.read()
            decompressed_contents = zlib.decompress(compressed_contents)

            content_start_index = decompressed_contents.find(b"\x00") + 1
            entries_data = decompressed_contents[content_start_index:]

            i = 0
            while i < len(entries_data):
                space_index = entries_data.find(b" ", i)
                null_index = entries_data.find(b"\x00", space_index)
                name = entries_data[space_index + 1 : null_index]
                print(name.decode())
                i = null_index + 21
    elif command == "write-tree":
        sha = write_tree()
        print(sha)
    elif command == "commit-tree":
        tree_sha = sys.argv[2]
        parent_sha = None
        message = None

        args = iter(sys.argv[3:])
        for arg in args:
            if arg == "-p":
                parent_sha = next(args)
            elif arg == "-m":
                message = next(args)

        if not message:
            raise ValueError("Commit message is required")

        timestamp = int(time.time())
        timezone = time.strftime("%z")

        lines = [f"tree {tree_sha}"]
        if parent_sha:
            lines.append(f"parent {parent_sha}")

        author = f"author Test User <test.user@example.com> {timestamp} {timezone}"
        committer = f"committer Test User <test.user@example.com> {timestamp} {timezone}"

        lines.append(author)
        lines.append(committer)
        lines.append("")
        lines.append(message)

        content = "\n".join(lines) + "\n"
        commit_object = b"commit %d\x00%s" % (len(content), content.encode("utf-8"))
        hex_sha = hashlib.sha1(commit_object).hexdigest()

        object_dir = f".git/objects/{hex_sha[:2]}"
        os.makedirs(object_dir, exist_ok=True)
        object_path = f"{object_dir}/{hex_sha[2:]}"
        with open(object_path, "wb") as f:
            f.write(zlib.compress(commit_object))

        print(hex_sha)
    elif command == "clone":
        repo_url = sys.argv[2]
        directory = sys.argv[3] if len(sys.argv) > 3 else repo_url.split('/')[-1].replace('.git', '')
        clone_repository(repo_url, directory)
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
