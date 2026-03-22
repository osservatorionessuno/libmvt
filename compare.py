import json

from cryptography import x509 as cx509
from cryptography.x509.oid import NameOID

oid_map = {
    "E": NameOID.EMAIL_ADDRESS,
}

def dn_equal(a: str, b: str) -> bool:
    """Compare X.500 DNs (e.g. Java RFC2253 strings). asn1crypto's Name.parse() is not a DN string parser."""
    if a is None or b is None:
        return False
    if a == b:
        return True
    a = a.replace(", ", ",")
    b = b.replace(", ", ",")
    try:
        ax = cx509.Name.from_rfc4514_string(a, oid_map)
        print(f"ax: {ax}")
    except ValueError as e:
        print(f"ValueError: {a} - {e}")
        return False
    try:
        bx = cx509.Name.from_rfc4514_string(b, oid_map)
        print(f"bx: {bx}")
    except ValueError as e:
        print(f"ValueError: {b} - {e}")
        return False
    # Check if they are the same
    return ax == bx


with open("out2.txt", "r") as f:
    out = json.load(f)

with open("out_androguard.txt", "r") as f:
    out_androguard = json.load(f)

for key, value in out.items():
    if key not in out_androguard:
        print(f"{key} not in out_androguard")
    else:
        if (value['packageName'] != out_androguard[key][0]):
            print(f"{key} packageName is different")
        if (value['versionCode'] != out_androguard[key][1]):
            print(f"{key} versionName is different")
        if (value['versionName'] != out_androguard[key][2]):
            print(f"{key} versionCode is different")
        if not dn_equal(value["certificateSubject"], out_androguard[key][3]):
            print(f"{key} certificateSubject is different")
        del out_androguard[key]

if len(out_androguard) > 0:
    print("out_androguard is not empty")
    for key, value in out_androguard.items():
        print(f"{key} not in out")
else:
    print("elaborated all the APKs")