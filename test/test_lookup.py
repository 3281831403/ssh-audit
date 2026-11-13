import pytest

from ssh_audit import exitcodes
from ssh_audit.outputbuffer import OutputBuffer


# pylint: disable=attribute-defined-outside-init
class TestLookup:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.algorithm_lookup = ssh_audit.algorithm_lookup

    def _lookup(self, names):
        out = OutputBuffer()
        retval = self.algorithm_lookup(out, names)
        return retval, out.get_buffer()

    def test_gss_name_is_known(self):
        '''A GSS kex name with a random suffix is resolved through the shared lookup and not treated as unknown.'''

        retval, output = self._lookup('gss-gex-sha1-vz8J1E9PzLr8b1K+0remTg==')
        # It has a real failure note (SHA-1), so the exit code is FAILURE, but it must never be listed as unknown.
        assert retval == exitcodes.FAILURE
        assert 'unknown algorithms' not in output
        assert 'gss-gex-sha1-vz8J1E9PzLr8b1K+0remTg==' in output
        assert 'using broken SHA-1 hash algorithm' in output

    def test_gss_name_with_dashed_suffix_is_known(self):
        '''GSS suffixes containing dashes still match the database wildcard.'''

        retval, output = self._lookup('gss-group16-sha512-RAND-OM==')
        assert 'unknown algorithms' not in output
        assert 'gss-group16-sha512-RAND-OM==' in output

    def test_gss_warn_only_returns_warning(self):
        '''A recognized GSS name whose only notes are warnings yields the WARNING code, not the unknown FAILURE code.'''

        retval, output = self._lookup('gss-gex-sha256-ABCDEFG-suffix')
        assert retval == exitcodes.WARNING
        assert 'unknown algorithms' not in output

    def test_unknown_name_still_fails(self):
        '''Unrecognized names keep their historical failure behavior under --lookup.'''

        retval, output = self._lookup('totally-bogus-kex-xyz')
        assert retval == exitcodes.FAILURE
        assert 'unknown algorithms' in output
        assert 'totally-bogus-kex-xyz' in output

    def test_mixed_known_gss_and_unknown(self):
        '''A known GSS name is recognized while an unknown companion still fails the lookup.'''

        retval, output = self._lookup('gss-group16-sha512-RANDOM==,totally-bogus-kex-xyz')
        assert retval == exitcodes.FAILURE
        assert 'gss-group16-sha512-RANDOM==' in output
        assert 'totally-bogus-kex-xyz' in output
        assert 'unknown algorithms' in output

    def test_known_regular_algorithm(self):
        '''Regular known algorithms are looked up exactly as before.'''

        retval, output = self._lookup('curve25519-sha256')
        assert retval == exitcodes.WARNING  # It carries the non-PQ-safe warning.
        assert 'unknown algorithms' not in output
        assert 'curve25519-sha256' in output
