#!/usr/bin/env python
"""
Compare ssdeep and ppdeep libraries to ensure they produce identical results.
Tests context triggered piecewise hashes (CTPH) / fuzzy hashes on both string and bytes objects.
"""

import argparse
import os
import sys


def generate_test_data():
    """Generate 70 test objects: 35 strings and 35 bytes."""
    test_objects = []

    # 35 string test cases (25 regular + 5 hex escape + 5 unicode escape)
    string_tests = [
        "Hello, World!",
        "The quick brown fox jumps over the lazy dog",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit",
        "a" * 100,
        "b" * 500,
        "Test with special chars: !@#$%^&*()_+-={}[]|:;<>?,./",
        "Multiline\nstring\nwith\nnewlines",
        "Tab\tseparated\tvalues",
        "Unicode test: café, naïve, 日本語",
        "Email: test@example.com, URL: https://example.com",
        'JSON-like: {"key": "value", "number": 123}',
        'XML-like: <tag attribute="value">content</tag>',
        "Base64-like: SGVsbG8gV29ybGQh",
        "Hex-like: 48656c6c6f20576f726c6421",
        "Long repeated pattern: " + "pattern" * 100,
        "Mixed case: AbCdEfGhIjKlMnOpQrStUvWxYz",
        "Numbers only: 1234567890" * 10,
        "Whitespace variations:   spaces   tabs\ttabs   ",
        "Path-like: /usr/local/bin/python3.13",
        "Windows path: C:\\Users\\Admin\\Documents\\file.txt",
        "SQL-like: SELECT * FROM users WHERE id = 1",
        "HTML: <html><body><h1>Title</h1></body></html>",
        "Empty string",
        "Single char: x",
        "Very long string: " + "x" * 10000,
        # Hex escape sequences
        "\x48\x65\x6c\x6c\x6f",  # "Hello" in hex
        "\x00\x01\x02\x03\x04",  # Control characters
        "Null byte test: \x00 middle",
        "\xff\xfe\xfd",  # High byte values
        "Mixed: \x41\x42\x43 ABC",  # Hex + regular
        # Unicode escape sequences
        "\u00e9\u00e0\u00fc",  # é à ü
        "\u4e2d\u6587",  # 中文 (Chinese)
        "Emoji: \U0001f600\U0001f44d",  # 😀👍
        "\u03b1\u03b2\u03b3",  # αβγ (Greek)
        "Mixed: \u2665 hearts \u2660 spades",  # ♥ ♠
    ]

    for i, s in enumerate(string_tests):
        test_objects.append(
            {
                "type": "string",
                "id": f"str_{i + 1}",
                "data": s,
            }
        )

    # Bytes test cases. Some are byte literals, some are UTF-8 encoded strings, and some are binary data.
    bytes_tests = [
        b"Hello, World!",
        b"The quick brown fox jumps over the lazy dog",
        b"Lorem ipsum dolor sit amet, consectetur adipiscing elit",
        b"a" * 100,
        b"b" * 500,
        b"Test with special chars: !@#$%^&*()_+-={}[]|:;<>?,./",
        b"Multiline\nstring\nwith\nnewlines",
        b"Tab\tseparated\tvalues",
        b"Email: test@example.com, URL: https://example.com",
        b'JSON-like: {"key": "value", "number": 123}',
        b'XML-like: <tag attribute="value">content</tag>',
        b"Base64-like: SGVsbG8gV29ybGQh",
        b"Hex-like: 48656c6c6f20576f726c6421",
        b"Long repeated pattern: " + b"pattern" * 100,
        b"Mixed case: AbCdEfGhIjKlMnOpQrStUvWxYz",
        b"Numbers only: 1234567890" * 10,
        b"Whitespace variations:   spaces   tabs\ttabs   ",
        b"Path-like: /usr/local/bin/python3.13",
        b"Windows path: C:\\Users\\Admin\\Documents\\file.txt",
        b"SQL-like: SELECT * FROM users WHERE id = 1",
        b"HTML: <html><body><h1>Title</h1></body></html>",
        b"Empty bytes",
        b"Single char: x",
        b"Very long bytes: " + b"x" * 10000,
        bytes(range(256)),  # All possible byte values
        # Hex escape sequences
        b"\x48\x65\x6c\x6c\x6f",  # b"Hello" in hex
        b"\x00\x01\x02\x03\x04",  # Control characters
        b"Null byte test: \x00 middle",
        b"\xff\xfe\xfd",  # High byte values
        b"Mixed: \x41\x42\x43 ABC",  # Hex + regular
        # Unicode escape sequences (as UTF-8 encoded bytes)
        "\u00e9\u00e0\u00fc".encode("utf-8"),  # é à ü
        "\u4e2d\u6587".encode("utf-8"),  # 中文 (Chinese)
        "Emoji: \U0001f600\U0001f44d".encode("utf-8"),  # 😀👍
        "\u03b1\u03b2\u03b3".encode("utf-8"),  # αβγ (Greek)
        "Mixed: \u2665 hearts \u2660 spades".encode("utf-8"),  # ♥ ♠
        # 32
        b"\xc1C*\xa3 \xb3D@\xe4\x08\xab\xbc\x94\xc0W\x8d\x9e\xbc}\\{\x8d*\x07\x9f\xf9\xc8\x04\t\xba2\xa9",
        b"\xa6`\x02\xda\x9aB\xf1Up\x1f\x876Ay\x07\xf7}\x10\xd7\xb7\xfa\x8fWs\x9d\\}X\xff\xe2\x9c\x8e",
        b"\xa3\xcf\x99\xdd[\x9a?e\x0f\xbf]\xdd\x9e\xcb.\x17V`3\xbf\xed&T\xa6\xecN\x10\xfd\xc5\xda8\x1d",
        b'\\\x07\xc4O\xf05\xb9\x19Z\xb9\xdb\x9a\xd5\xed\x93\x9d\xc7`\xab\xb6\xa8\x99\xc4\x98"\xde\xde9\xfdb<\x9b',
        b"\x98\x11\x8d]\x93\x82\xaaEx~<}\\\x1a\xf9!\xae\xcc\x8cn-E\xe9\xa8\xe3\x0f\x0f\xa6\xa1\xdc\xd2\xe9\xa1",
        # 33
        b"\x98\x11\x8d]\x93\x82\xaaEx~<}\\\x1a\xf9!\xae\xcc\x8cn-E\xe9\xa8\xe3\x0f\x0f\xa6\xa1\xdc\xd2\xe9\xa1",
        # 64
        b"z\x06vf\xbb\xf9J*|4\\\xdd\x17\xd7\x8f9\xb3\x9a\r\xd2\xa2\xf0\xe3\x0f\xe4\xb5\\|\x7f\x1cq\xd0\x01\xaf\x86\x8b\xd1~\xf8*-\xf7\x12\xb5):Q\xa5z\xdc\xcb\x0bv|\x06c\xf0\xd2s\x18\rb\xd8\xed"
        # 65
        b"\x14\xbc\x91V2K\x8a\xce>\xdb\xf1\xe8\x1e\xef\xc0F\xaf\xb6\xd6(\xd2\xda\xd4#\xf6\x7fl\n\x7fT`-m\xd7\x1c;\x90X\x91\x80\x88\x99\xb6-h-\xd9\xdcx\xfb\xa6Tn\x87Pw\xfa\x9e:\x00*\\g\x1f\x80"
        b"\x00\x7f\xc5@\xc7\x18\x04\x995\x03\x9a\x0e\x8e\xb39\x13\x17\xb1SQ\xe2\xab\xb9\xe0D\x86,\x11\x9d7\xb1\xa2<\x95\x8b\x9e\xb8\xfe;\x9c\xca\xd3\x82'\x91\xe8\xd8f\xe6+\x9f\x12w\x16S\xbah\xa9\xee\xbd!\xc4+\xa9\xfe",
        # 127
        b'\xfa\xe8p\x08\x8b)T[\xc0\xeaS\x05-\xea\xa1\xed\x85V\xe0\xee\xab\xef\x17\x16(k\x14\rZB)\xbe\xf5!"\xa3R\xb2\x9a\x0c\xd0\xbb\xa5\x81\xcbq\x9eP_L\xc4\x9aP\xdf\x1a\xbcz\xb9\xb1\xa1\x07\x9eC\x12\xb1\xe6{\xf8\x18\x02\xf0B\xe1s\xbf\xb7\x9c\xf8e\\\x11_-\xef2o\xea\x8c<\x05\t\x10\xbdI=(\xf8\n\xffa\x8d\xc4\xd7\x11N\xe3\xf2\xd5\x9bQ#\x94\xe5\xf9\xc7\x1a\xda\xbeR{\xe9\xcf@\xf8\tZM'
        # 128
        b"cal\xbc\xaa\xfb\xc3@\x9a\x9euCi\xaf\xc5\xd8$\x8a\xe5\xabE\x85D\xd3\x161i)\xe5\xd4Uj\xdd\xf6\xe6\x08\x1e\xeb\xa8\x8eLd\x12\x81\xdd\xbbF\xc4\xc1\x17\xfd\xda\xb4W\xad_\x90\xadB\x140\xbdFI\xbeL\x9e\xc2\xc6\x03z-t\xbf\x84\xf33\xcd\xaa\x1ds0L\x1c\xaa\x16o\x1d\x078\xa8\x9ez\xa4\xb2\xe3on\xd5*\xbb\x9e?\x1dvf\xc8\xa0\xceHl\xd1\x1b_{\xe7\xdc\x19\x0c2)\r\xed\xa3\xf3\x13aw",
    ]

    for i, b in enumerate(bytes_tests):
        test_objects.append(
            {
                "type": "bytes",
                "id": f"bytes_{i + 1}",
                "data": b,
            }
        )

    # Add file tests
    file_paths = [
        "/usr/bin/setsid",
        "/usr/bin/locale",
        "/usr/bin/last",
        "/usr/bin/perl",
        # Add more file paths here as needed
    ]

    for idx, file_path in enumerate(file_paths, start=1):
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            test_objects.append(
                {
                    "type": "file",
                    "id": f"file_{idx}",
                    "data": file_data,
                }
            )
            print(f"Added file test {idx}: {file_path} ({len(file_data)} bytes)")
        except FileNotFoundError:
            print(f"Warning: File '{file_path}' not found, skipping")
        except Exception as e:
            print(f"Warning: Could not read file '{file_path}': {e}")

    return test_objects


def compare_libraries():
    """Compare ssdeep and ppdeep hash results."""

    # Try importing both libraries
    try:
        import ssdeep

        has_ssdeep = True
    except ImportError as e:
        print(f"Warning: ssdeep not available: {e}")
        has_ssdeep = False

    try:
        import ppdeep

        has_ppdeep = True
    except ImportError as e:
        print(f"Warning: ppdeep not available: {e}")
        has_ppdeep = False

    if not has_ssdeep and not has_ppdeep:
        print("Error: Neither ssdeep nor ppdeep is installed!")
        sys.exit(1)

    if not has_ssdeep:
        print("Warning: Only ppdeep is available. Cannot compare.")
        return

    if not has_ppdeep:
        print("Warning: Only ssdeep is available. Cannot compare.")
        return

    print("=" * 80)
    print("SSDEEP vs PPDEEP COMPARISON")
    print("=" * 80)
    print(f"ssdeep version: {ssdeep.__version__ if hasattr(ssdeep, '__version__') else 'unknown'}")
    print(f"ppdeep version: {ppdeep.__version__ if hasattr(ppdeep, '__version__') else 'unknown'}")
    print()

    # Generate test data
    test_objects = generate_test_data()
    string_count = len([t for t in test_objects if t["type"] == "string"])
    bytes_count = len([t for t in test_objects if t["type"] == "bytes"])
    file_count = len([t for t in test_objects if t["type"] == "file"])
    print(f"Testing {len(test_objects)} objects ({string_count} strings, {bytes_count} bytes, {file_count} files)\n")

    # Track results
    total_tests = 0
    matching = 0
    mismatches = []
    ssdeep_errors = []
    ppdeep_errors = []

    # Test each object
    for obj in test_objects:
        total_tests += 1
        obj_id = obj["id"]
        obj_type = obj["type"]
        data = obj["data"]

        # Get ssdeep hash
        try:
            if obj_type == "string":
                ssdeep_hash = ssdeep.hash(data)
            else:
                ssdeep_hash = ssdeep.hash(data)
        except Exception as e:
            ssdeep_hash = None
            ssdeep_errors.append({"id": obj_id, "error": str(e)})

        # Get ppdeep hash
        try:
            if obj_type == "string":
                ppdeep_hash = ppdeep.hash(data)
            else:
                ppdeep_hash = ppdeep.hash(data)
        except Exception as e:
            ppdeep_hash = None
            ppdeep_errors.append({"id": obj_id, "error": str(e)})

        # Compare results
        if ssdeep_hash is not None and ppdeep_hash is not None:
            if ssdeep_hash == ppdeep_hash:
                matching += 1
                print(f"✓ {obj_id:15} MATCH")
            else:
                mismatches.append(
                    {
                        "id": obj_id,
                        "type": obj_type,
                        "ssdeep": ssdeep_hash,
                        "ppdeep": ppdeep_hash,
                    }
                )
                print(f"✗ {obj_id:15} MISMATCH")
        elif ssdeep_hash is None and ppdeep_hash is None:
            print(f"⚠ {obj_id:15} BOTH FAILED")
        elif ssdeep_hash is None:
            print(f"⚠ {obj_id:15} SSDEEP FAILED")
        else:
            print(f"⚠ {obj_id:15} PPDEEP FAILED")

    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total tests:        {total_tests}")
    print(f"Matching hashes:    {matching} ({matching / total_tests * 100:.1f}%)")
    print(f"Mismatches:         {len(mismatches)}")
    print(f"ssdeep errors:      {len(ssdeep_errors)}")
    print(f"ppdeep errors:      {len(ppdeep_errors)}")

    # Print detailed mismatch information
    if mismatches:
        print("\n" + "=" * 80)
        print("MISMATCHES DETAIL")
        print("=" * 80)
        for mismatch in mismatches:
            print(f"\nID: {mismatch['id']} ({mismatch['type']})")
            print(f"  ssdeep: {mismatch['ssdeep']}")
            print(f"  ppdeep: {mismatch['ppdeep']}")

    # Print error details
    if ssdeep_errors:
        print("\n" + "=" * 80)
        print("SSDEEP ERRORS")
        print("=" * 80)
        for error in ssdeep_errors:
            print(f"{error['id']}: {error['error']}")

    if ppdeep_errors:
        print("\n" + "=" * 80)
        print("PPDEEP ERRORS")
        print("=" * 80)
        for error in ppdeep_errors:
            print(f"{error['id']}: {error['error']}")

    # Final verdict
    print("\n" + "=" * 80)
    if matching == total_tests:
        print("✓ RESULT: All hashes match! Libraries are compatible.")
        print("=" * 80)
        sys.exit(0)
    else:
        print("✗ RESULT: Differences detected! Review mismatches before swapping libraries.")
        print("=" * 80)
        sys.exit(1)


def find_mismatch_file(start_path="/"):
    """
    Recursively search filesystem for a file where ssdeep and ppdeep produce different hashes.

    Args:
        start_path: Directory to start searching from (default: "/")
    """
    try:
        import ssdeep
    except ImportError:
        print("Error: ssdeep not installed")
        sys.exit(1)

    try:
        import ppdeep
    except ImportError:
        print("Error: ppdeep not installed")
        sys.exit(1)

    print(f"Searching for hash mismatch starting from: {start_path}")
    print("Press Ctrl+C to stop\n")

    files_checked = 0
    errors_skipped = 0

    for root, dirs, files in os.walk(start_path):
        # Skip common system/virtual directories
        dirs[:] = [
            d
            for d in dirs
            if d
            not in [
                ".git",
                "node_modules",
                "__pycache__",
                ".venv",
                "venv",
                "Library",
                "Applications",
                "System",
                "Volumes",
                "dev",
                "proc",
                "sys",
            ]
        ]

        for filename in files:
            filepath = os.path.join(root, filename)

            # Skip symlinks and non-regular files
            try:
                if not os.path.isfile(filepath) or os.path.islink(filepath):
                    continue
            except (OSError, PermissionError):
                continue

            files_checked += 1
            if files_checked % 100 == 0:
                print(f"Checked {files_checked} files...", end="\r")

            try:
                ssdeep_hash = ssdeep.hash_from_file(filepath)
                ppdeep_hash = ppdeep.hash_from_file(filepath)

                if ssdeep_hash != ppdeep_hash:
                    print(f"\n\n{'=' * 80}")
                    print("MISMATCH FOUND!")
                    print(f"{'=' * 80}")
                    print(f"File: {filepath}")
                    print(f"Size: {os.path.getsize(filepath)} bytes")
                    print(f"ssdeep: {ssdeep_hash}")
                    print(f"ppdeep: {ppdeep_hash}")
                    print(f"{'=' * 80}")
                    print(f"Total files checked: {files_checked}")
                    # return filepath

            except (PermissionError, OSError, IOError, Exception):
                errors_skipped += 1
                continue

    print("\n\nSearch complete. No mismatches found.")
    print(f"Files checked: {files_checked}")
    print(f"Errors skipped: {errors_skipped}")
    return None


def find_random_mismatch(num_tests=10000, length=32):
    """
    Generate random byte strings and test for hash mismatches.

    Args:
        num_tests: Number of random strings to generate (default: 10000)
        length: Length of each random byte string (default: 32)
    """
    import random

    try:
        import ssdeep
    except ImportError:
        print("Error: ssdeep not installed")
        sys.exit(1)

    try:
        import ppdeep
    except ImportError:
        print("Error: ppdeep not installed")
        sys.exit(1)

    print(f"Generating {num_tests} random byte strings of length {length}")
    print("Press Ctrl+C to stop\n")

    tests_run = 0
    matches = 0
    mismatches_found = []

    for i in range(num_tests):
        tests_run += 1
        if tests_run % 100 == 0:
            print(f"Tested {tests_run}/{num_tests} random strings...", end="\r")

        # Generate random bytes
        random_bytes = bytes(random.randint(0, 255) for _ in range(length))

        try:
            ssdeep_hash = ssdeep.hash(random_bytes)
            ppdeep_hash = ppdeep.hash(random_bytes)

            if ssdeep_hash == ppdeep_hash:
                matches += 1
            else:
                mismatches_found.append(
                    {
                        "test_num": tests_run,
                        "data": random_bytes,
                        "ssdeep": ssdeep_hash,
                        "ppdeep": ppdeep_hash,
                    }
                )
                print(f"\n\n{'=' * 80}")
                print("MISMATCH FOUND!")
                print(f"{'=' * 80}")
                print(f"Test number: {tests_run}")
                print(f"Random bytes (hex): {random_bytes.hex()}")
                print(f"Random bytes (repr): {random_bytes!r}")
                print(f"Length: {len(random_bytes)}")
                print(f"ssdeep: {ssdeep_hash}")
                print(f"ppdeep: {ppdeep_hash}")
                print(f"{'=' * 80}")
                # Don't return immediately, continue testing to find all mismatches

        except Exception as e:
            print(f"\nError testing random bytes at iteration {tests_run}: {e}")
            continue

    # Print summary
    print("\n\nRandom testing complete.")
    print(f"Tests run: {tests_run}")
    print(f"Matches: {matches}")
    print(f"Mismatches: {len(mismatches_found)}")

    if len(mismatches_found) == 0:
        print("\n✓ No mismatches found! Libraries appear compatible.")
    else:
        print(f"\n✗ Found {len(mismatches_found)} mismatch(es)!")
        print("\nAll mismatches:")
        for idx, mismatch in enumerate(mismatches_found, 1):
            print(f"\n  {idx}. Test #{mismatch['test_num']}: {mismatch['data'].hex()[:60]}...")

    return mismatches_found


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare ssdeep and ppdeep library hash outputs")
    parser.add_argument(
        "--find-mismatch",
        action="store_true",
        help="Recursively search filesystem for a file with mismatched hashes",
    )
    parser.add_argument(
        "--start-path",
        type=str,
        default="/",
        help="Starting directory for mismatch search (default: /)",
    )
    parser.add_argument(
        "--random-test",
        action="store_true",
        help="Generate random byte strings to find hash mismatches",
    )
    parser.add_argument(
        "--num-tests",
        type=int,
        default=10000,
        help="Number of random tests to run (default: 10000)",
    )
    parser.add_argument(
        "--length",
        type=int,
        default=32,
        help="Length of random byte strings (default: 32)",
    )

    args = parser.parse_args()

    if args.find_mismatch:
        find_mismatch_file(args.start_path)
    elif args.random_test:
        find_random_mismatch(args.num_tests, args.length)
    else:
        compare_libraries()
