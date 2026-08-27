"""Offline unit tests — deterministic module behaviour, no network required.

These run by default (`pytest`) and are what CI executes. The parsers, detectors and
validators here are the parts that must never regress silently, so each pins a concrete
input -> expected output.
"""
from silentpivot.ai_engine import SilentAI
from silentpivot.bypass403 import Bypass403
from silentpivot.contentdisco import BUILTIN_WORDLIST, ContentDiscovery
from silentpivot.leakfinder import _COMPILED, _PLACEHOLDER
from silentpivot.nuclei import NucleiScanner
from silentpivot.pathtraversal import PathTraversal
from silentpivot.ssrf import SSRFScanner


# ---------------- parsers ----------------
def test_nuclei_jsonl_parse():
    sample = ('{"template-id":"x","info":{"name":"n","severity":"high"},'
              '"matched-at":"https://t/a"}')
    parsed = NucleiScanner.parse_jsonl(sample)
    assert len(parsed) == 1 and parsed[0]["severity"] == "HIGH"


def test_nuclei_jsonl_skips_garbage():
    parsed = NucleiScanner.parse_jsonl("not json\n\n{bad}\n")
    assert parsed == []


def test_ffuf_parser_decodes_base64_and_skips_bad_rows():
    ffuf = ('{"input":{"FUZZ":"admin"},"url":"http://t/admin","status":200,"length":12}\n'
            '{"input":{"FUZZ":"cGhwTXlBZG1pbg=="},"status":301,"length":9}\n'
            '{"input":{"FUZZ":"a"},"status":"abc"}\n'
            'not json')
    out = ContentDiscovery.parse_ffuf(ffuf)
    assert [x["path"] for x in out] == ["/admin", "/phpMyAdmin"]
    assert out[0]["status"] == 200


def test_gobuster_parser():
    gob = "/admin  (Status: 301) [Size: 234] [--> /admin/]\nnoise"
    out = ContentDiscovery.parse_gobuster(gob)
    assert len(out) == 1 and out[0]["status"] == 301 and out[0]["redirect"] == "/admin/"


def test_builtin_wordlist_populated():
    assert len(BUILTIN_WORDLIST) > 100


# ---------------- detectors ----------------
def test_bypass403_generates_techniques():
    attempts = Bypass403()._build_attempts("https://host/admin")
    techniques = {a[0].split()[0] for a in attempts}
    assert len(attempts) > 20 and {"header", "path", "method"} <= techniques


def test_leakfinder_catches_real_secrets_skips_placeholder():
    sample = ('a="AKIAIOSFODNN7EXAMPLE" b="AKIA1234567890ABCDEF" '
              'c="ghp_' + "z" * 36 + '"')
    hits = []
    for name, (pat, _c) in _COMPILED.items():
        for m in pat.finditer(sample):
            if not _PLACEHOLDER.search(m.group(0)):
                hits.append(name)
    # catches the real AWS + GitHub token, skips the EXAMPLE placeholder
    assert "AWS Access Key" in hits and "GitHub Token" in hits and len(hits) == 2


def test_pathtraversal_signature_and_clean():
    pt = PathTraversal()
    hit = pt._check("root:x:0:0:root:/root:/bin/bash", "x")
    clean = pt._check("<html>welcome</html>", "x")
    assert hit and hit[0] == "Linux /etc/passwd" and clean is None


def test_ssrf_confirms_real_rejects_reflection():
    real = SSRFScanner._check('{"AccessKeyId":"AKIA...","SecretAccessKey":"x"}',
                              "http://169.254.169.254/")
    reflected = SSRFScanner._check(
        "Warning: include(http://169.254.169.254/latest/meta-data/iam/)",
        "http://169.254.169.254/latest/meta-data/iam/")
    clean = SSRFScanner._check("<html>welcome</html>", "x")
    assert real and real[0] == "AWS metadata" and reflected is None and clean is None


def test_ai_payload_parse_valid_and_garbage():
    got = SilentAI._parse_payload_list('text ["http://127.0.0.1/","gopher://x"] tail', 12)
    assert got == ["http://127.0.0.1/", "gopher://x"]
    assert SilentAI._parse_payload_list("none", 12) == []
