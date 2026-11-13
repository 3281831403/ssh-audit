import os
import pytest

from ssh_audit.hostkeytest import HostKeyTest
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.policy import Policy
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexparty import SSH2_KexParty


@pytest.fixture
def kex(ssh_audit):
    kex_algs, key_algs = [], []
    enc, mac, compression, languages = [], [], ['none'], []
    cli = SSH2_KexParty(enc, mac, compression, languages)
    enc, mac, compression, languages = [], [], ['none'], []
    srv = SSH2_KexParty(enc, mac, compression, languages)
    cookie = os.urandom(16)
    kex = SSH2_Kex(OutputBuffer, cookie, kex_algs, key_algs, cli, srv, 0)
    return kex


def _make_kex(kex_algs, key_algs, enc=None, mac=None):
    '''Builds a fixed, synthetic SSH2_Kex object from plain algorithm lists.'''
    enc = ['aes128-ctr'] if enc is None else enc
    mac = ['hmac-sha2-256'] if mac is None else mac
    cli = SSH2_KexParty([], [], ['none'], [])
    srv = SSH2_KexParty(enc, mac, ['none'], [])
    cookie = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
    return SSH2_Kex(OutputBuffer, cookie, kex_algs, key_algs, cli, srv, 0)


def test_prevent_runtime_error_regression(ssh_audit, kex):
    """Prevent a regression of https://github.com/jtesta/ssh-audit/issues/41

    The following test setup does not contain any sensible data.
    It was made up to reproduce a situation when there are several host
    keys, and an error occurred when iterating and modifying them at the
    same time.
    """
    kex.set_host_key("ssh-rsa", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa1", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa2", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa3", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa4", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa5", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa6", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa7", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa8", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)

    rv = ssh_audit.build_struct('localhost', None, kex=kex)

    assert len(rv["fingerprints"]) == (9 * 2)  # Each host key generates two hash fingerprints: one using SHA256, and one using MD5.

    for key in ['banner', 'compression', 'enc', 'fingerprints', 'kex', 'key', 'mac']:
        assert key in rv


def test_gss_kex_recognized_in_json(ssh_audit):
    '''A GSS kex name with a random suffix is treated as a known algorithm in JSON, not as unknown.'''

    gss_name = 'gss-gex-sha1-vz8J1E9PzLr8b1K+0remTg=='
    kex = _make_kex([gss_name], ['ssh-ed25519'])
    rv = ssh_audit.build_struct('localhost', None, kex=kex)

    # The original, unmodified name is reported.
    assert rv['kex'][0]['algorithm'] == gss_name
    notes = rv['kex'][0]['notes']
    # It carries its real database notes (a SHA-1 failure), never the "using unknown algorithm" marker.
    assert 'fail' in notes
    assert 'using unknown algorithm' not in notes['fail']
    assert notes['fail'] == ['using broken SHA-1 hash algorithm']
    # Recognized GSS names must not appear in the top-level unknown list.
    assert rv['unknown_algorithms'] == []


def test_unknown_algorithms_are_warnings_in_json(ssh_audit):
    '''Unknown algorithms in a scan are classified as warnings in JSON (matching text output), not failures.'''

    kex = _make_kex(['totally-bogus-kex-xyz'], ['totally-bogus-key-xyz'],
                    enc=['totally-bogus-enc-xyz'], mac=['totally-bogus-mac-xyz'])
    rv = ssh_audit.build_struct('localhost', None, kex=kex)

    for section in ('kex', 'key', 'enc', 'mac'):
        assert rv[section][0]['notes'] == {'warn': ['using unknown algorithm']}


def test_unknown_algorithms_top_level_dedup_and_order(ssh_audit):
    '''The top-level unknown_algorithms list is deduplicated while preserving discovery order.'''

    kex = _make_kex(
        # bogus-kex-A appears twice within the kex list.
        ['gss-gex-sha1-vz8J1E9PzLr8b1K+0remTg==', 'bogus-kex-A', 'curve25519-sha256', 'bogus-kex-A'],
        ['ssh-ed25519', 'bogus-key-B'],
        enc=['aes128-ctr', 'bogus-enc-C'],
        # bogus-kex-A repeats in a different list, but must still be reported only once.
        mac=['hmac-sha2-256', 'bogus-mac-D', 'bogus-kex-A'],
    )
    rv = ssh_audit.build_struct('localhost', None, kex=kex)

    # kex list first, then key, enc, mac; duplicates collapsed; known GSS/regular names excluded.
    assert rv['unknown_algorithms'] == ['bogus-kex-A', 'bogus-key-B', 'bogus-enc-C', 'bogus-mac-D']


def test_unknown_algorithms_empty_when_all_known(ssh_audit):
    '''The unknown_algorithms field is present and empty when every name is recognized.'''

    kex = _make_kex(['curve25519-sha256'], ['ssh-ed25519'])
    rv = ssh_audit.build_struct('localhost', None, kex=kex)
    assert 'unknown_algorithms' in rv
    assert rv['unknown_algorithms'] == []


def test_known_algorithm_notes_unchanged(ssh_audit):
    '''Descriptors of correctly recognized algorithms remain unchanged.'''

    kex = _make_kex(['curve25519-sha256'], ['ssh-ed25519'])
    rv = ssh_audit.build_struct('localhost', None, kex=kex)

    assert rv['kex'][0]['notes'] == {
        'warn': ['does not provide protection against post-quantum attacks'],
        'info': ['default key exchange from OpenSSH 7.4 to 8.9',
                 'available since OpenSSH 7.4, Dropbear SSH 2018.76'],
    }
    assert rv['key'][0]['notes'] == {'info': ['available since OpenSSH 6.5, Dropbear SSH 2020.79']}

    # Running the report repeatedly must not change the output (the shared database is not mutated).
    rv_again = ssh_audit.build_struct('localhost', None, kex=kex)
    assert rv_again['kex'][0]['notes'] == rv['kex'][0]['notes']
    assert rv_again['key'][0]['notes'] == rv['key'][0]['notes']


def test_build_struct_does_not_mutate_kex_host_keys(ssh_audit):
    '''Building the JSON report must never modify the kex (RSA host key types must survive).'''

    kex = _make_kex(['curve25519-sha256'],
                    ['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519'])
    for rsa_type in HostKeyTest.RSA_FAMILY:
        kex.set_host_key(rsa_type, b'\x00' * 32, 1024, '', 0)
    kex.set_host_key('ssh-ed25519', b'\x00' * 32, 256, '', 0)

    host_keys_before = sorted(kex.host_keys().keys())
    ssh_audit.build_struct('localhost', None, kex=kex)
    host_keys_after = sorted(kex.host_keys().keys())

    assert host_keys_after == host_keys_before
    assert host_keys_after == ['rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519', 'ssh-rsa']


def test_policy_host_key_length_check_after_build_struct(ssh_audit):
    '''A host key length mismatch is still caught by a policy run after the JSON report is built.'''

    kex = _make_kex(['curve25519-sha256'],
                    ['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519'])
    # The server presents 1024-bit RSA keys (all RSA family members share the same key).
    for rsa_type in HostKeyTest.RSA_FAMILY:
        kex.set_host_key(rsa_type, b'\x00' * 32, 1024, '', 0)

    # The policy mandates 3072-bit RSA keys under the rsa-sha2-* names used by built-in policies.
    policy_data = '''name = "Test Policy"
version = 1
host keys = ssh-rsa, rsa-sha2-256, rsa-sha2-512
host_key_sizes = {"rsa-sha2-256": {"hostkey_size": 3072}, "rsa-sha2-512": {"hostkey_size": 3072}}
key exchanges = curve25519-sha256
ciphers = aes128-ctr
macs = hmac-sha2-256'''
    policy = Policy(policy_data=policy_data)

    # Internal-tool flow: generate the JSON report first, then run the policy against the same kex.
    ssh_audit.build_struct('localhost', None, kex=kex)
    passed, errors, _ = policy.evaluate(None, kex)

    assert passed is False
    mismatched_fields = [e['mismatched_field'] for e in errors]
    assert 'Host key (rsa-sha2-256) sizes' in mismatched_fields
    assert 'Host key (rsa-sha2-512) sizes' in mismatched_fields
