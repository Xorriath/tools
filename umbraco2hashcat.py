#!/usr/bin/env python3
# umbraco2hashcat - Converts ASP.NET Identity V3 hashes to hashcat format
# Works with Umbraco 7.7+ which uses PBKDF2 (HMAC-SHA1/SHA256/SHA512)
# To confirm hash type, check web.config for <membership> settings:
#   - useLegacyEncoding="false" (default 7.6+) = ASP.NET Identity V3 (this script)
#   - useLegacyEncoding="true" = older HMACSHA256 format (different tool needed)
# Also check machineKey validation algorithm in web.config for PRF type
import base64
import sys

def convert_hash(hash_b64):
    try:
        hash_bytes = base64.b64decode(hash_b64)
    except Exception:
        print(f"[!] Error: Invalid base64 string", file=sys.stderr)
        sys.exit(1)

    if len(hash_bytes) < 13:
        print(f"[!] Error: Hash too short to be ASP.NET Identity format", file=sys.stderr)
        sys.exit(1)

    # Parse V3 format structure
    format_marker = hash_bytes[0]
    prf = int.from_bytes(hash_bytes[1:5], 'big')
    iterations = int.from_bytes(hash_bytes[5:9], 'big')
    salt_len = int.from_bytes(hash_bytes[9:13], 'big')
    salt = hash_bytes[13:13+salt_len]
    subkey = hash_bytes[13+salt_len:]

    # Determine algorithm and hashcat mode
    algo_map = {0: ("sha1", 12000), 1: ("sha256", 10900), 2: ("sha512", 12100)}
    algo, mode = algo_map.get(prf, ("sha256", 10900))

    salt_b64 = base64.b64encode(salt).decode()
    subkey_b64 = base64.b64encode(subkey).decode()

    hashcat_format = f"{algo}:{iterations}:{salt_b64}:{subkey_b64}"

    print(f"[+] ASP.NET Identity V3 Hash")
    print(f"[+] Algorithm: PBKDF2-HMAC-{algo.upper()}")
    print(f"[+] Iterations: {iterations}")
    print(f"[+] Salt length: {salt_len} bytes")
    print(f"[+] Subkey length: {len(subkey)} bytes")
    print()
    print(f"[*] Hashcat mode: {mode}")
    print(f"[*] Hashcat format:")
    print(hashcat_format)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} '<base64_hash>'")
        print(f"Example: {sys.argv[0]} 'AQAAAAEAACcQAAAAEIhgGQjC5nEIdTaVpq+Y2b6A5ZdPsV91mIlU06FftmQrmAh5PntIXU7WqSBuOKOm3Q=='")
        sys.exit(1)
    
    convert_hash(sys.argv[1])
