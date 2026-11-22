import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPORTER_PATH = ROOT / "deploy" / "import-wifi.py"


def _load_importer():
    spec = importlib.util.spec_from_file_location("import_wifi", IMPORTER_PATH)
    assert spec and spec.loader, f"Missing {IMPORTER_PATH}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_parse_wifi_qr_handles_wpa_escaped_chars_and_open():
    mod = _load_importer()
    wpa = mod.parse_wifi_qr(r"WIFI:T:WPA;S:Camp\;Site\:One;P:p\;w\\1\:2\"x;;")
    assert wpa == {
        "ssid": "Camp;Site:One",
        "security": "wpa2",
        "psk": r'p;w\1:2"x',
    }

    sae = mod.parse_wifi_qr("WIFI:T:SAE;S:ModernNet;P:strongpass123;;")
    assert sae == {"ssid": "ModernNet", "security": "wpa2", "psk": "strongpass123"}

    open_net = mod.parse_wifi_qr("WIFI:T:nopass;S:FreeCafe;;")
    assert open_net == {"ssid": "FreeCafe", "security": "open", "psk": ""}


def test_parse_nmconnection_text_handles_wpa_open_and_skips_enterprise_or_ethernet():
    mod = _load_importer()

    wpa_text = """\
[connection]
id=Campground
type=wifi

[wifi]
mode=infrastructure
ssid=Campground North

[wifi-security]
key-mgmt=wpa-psk
psk=secretcamp99
"""
    assert mod.parse_nmconnection_text(wpa_text) == {
        "ssid": "Campground North",
        "security": "wpa2",
        "psk": "secretcamp99",
    }

    open_text = """\
[connection]
id=xfinitywifi
type=wifi

[wifi]
ssid=xfinitywifi
"""
    assert mod.parse_nmconnection_text(open_text) == {
        "ssid": "xfinitywifi",
        "security": "open",
        "psk": "",
    }

    ent_text = """\
[connection]
id=CorpWiFi
type=wifi

[wifi]
ssid=CorpWiFi

[wifi-security]
key-mgmt=wpa-eap
"""
    assert mod.parse_nmconnection_text(ent_text) is None

    eth_text = """\
[connection]
id=Wired
type=ethernet
"""
    assert mod.parse_nmconnection_text(eth_text) is None


def test_parse_android_wifi_xml_extracts_wpa_and_open_profiles():
    mod = _load_importer()
    xml_sample = """\
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<WifiConfigStoreData>
  <NetworkList>
    <Network>
      <WifiConfiguration>
        <string name="SSID">&quot;Home Cabin&quot;</string>
        <string name="PreSharedKey">&quot;cabin-pass-42&quot;</string>
      </WifiConfiguration>
    </Network>
    <Network>
      <WifiConfiguration>
        <string name="SSID">&quot;xfinitywifi&quot;</string>
        <null name="PreSharedKey" />
      </WifiConfiguration>
    </Network>
    <Network>
      <WifiConfiguration>
        <string name="SSID">&quot;&quot;</string>
      </WifiConfiguration>
    </Network>
    <Network>
      <WifiConfiguration>
        <string name="SSID">&quot;Eduroam&quot;</string>
        <null name="PreSharedKey" />
      </WifiConfiguration>
      <WifiEnterpriseConfiguration />
    </Network>
  </NetworkList>
</WifiConfigStoreData>
"""
    items = mod.parse_android_wifi_xml(xml_sample)
    assert items == [
        {"ssid": "Home Cabin", "security": "wpa2", "psk": "cabin-pass-42"},
        {"ssid": "xfinitywifi", "security": "open", "psk": ""},
    ]
