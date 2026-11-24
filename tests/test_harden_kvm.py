import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "harden-kvm.py"
_SPEC = importlib.util.spec_from_file_location("harden_kvm", _SCRIPT)
harden_kvm = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(harden_kvm)


def test_patch_edid_hex_sets_pnp_name_and_valid_checksum():
    # Minimal 128-byte EDID with GLKVM (0x1d89) and name descriptor at offset 90
    raw = bytearray(128)
    raw[0:8] = bytes.fromhex("00ffffffffffff00")
    raw[8:10] = bytes.fromhex("1d89")
    raw[90:95] = bytes.fromhex("000000fc00")
    raw[95:108] = b"GLKVM\n       "
    patched = harden_kvm.patch_edid_hex(raw.hex(), "DELL U2723QE")
    b = bytes.fromhex(patched)
    assert len(b) == 128
    assert b[8:10] == b"\x10\xac"  # DEL PNP ID
    assert b[95:108] == b"DELL U2723QE\n"
    assert sum(b) % 256 == 0  # Valid EDID base-block checksum


def test_render_override_yaml_disables_msd_and_spoofs_usb():
    yml = harden_kvm.render_override_yaml(harden_kvm.USB_PRESETS["logitech-receiver"])
    assert "type: disabled" in yml
    assert "vendor_id: 0x046d" in yml
    assert "product_id: 0xc52b" in yml
    assert 'manufacturer: "Logitech"' in yml
    assert "enabled: false" in yml
