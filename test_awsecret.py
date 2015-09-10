from collections import namedtuple
from io import BytesIO
import pytest

from Crypto.PublicKey import RSA
from awsecret.database import PasswordDatabase, Recipient


@pytest.fixture
def rsa_pair():
    key = RSA.generate(1024)
    public_key = key.publickey()

    return namedtuple('RSAPair', 'private public')._make((key, public_key))


@pytest.fixture
def empty_db_file(rsa_pair):
    db = PasswordDatabase()
    db.recipients.append(Recipient(rsa_pair.public, ''))
    f = BytesIO()
    db.encrypt(f)
    f.seek(0)

    return namedtuple('EmptyDBFile', 'f rsa_pair')._make((f, rsa_pair))


class TestDatabase(object):
    def test_constructor(self, empty_db_file):
        new_database = PasswordDatabase()
        assert new_database.recipients == []
        assert new_database._password_store == {}

        database_from_file = PasswordDatabase(empty_db_file.f, empty_db_file.rsa_pair.private)
        assert len(database_from_file.recipients) == 1
        assert database_from_file._password_store == {}

        with pytest.raises(ValueError) as e:
            empty_db_file.f.seek(0)
            wrong_key = RSA.generate(1024)
            PasswordDatabase(empty_db_file.f, wrong_key)
        assert 'invalid RSA key!' in str(e)

    def test_get(self):
        """Tests getting passwords using bracket notation and .get() method"""

        database = PasswordDatabase()
        database['my_password'] = 'secret'

        assert database['my_password'] == 'secret'

        with pytest.raises(KeyError):
            database['foo']

        assert database.get('my_password') == 'secret'
        assert database.get('not_there') is None
        assert database.get('not_there', 'secret') == 'secret'

    def test_set(self):
        """Tests setting passwords using bracket notation and .set() method"""

        database = PasswordDatabase()

        database['my_password'] = 'secret'
        assert database._password_store['my_password'] == 'secret'

        database.set('more_password', 'more_secret')
        assert database._password_store['more_password'] == 'more_secret'

    def test_delete(self):
        """Tests deleting password entries"""

        database = PasswordDatabase()
        database['my_password'] = 'secret'

        del database['my_password']

        assert 'my_password' not in database._password_store

    def test_contains(self):
        """Tests the in keyword"""

        database = PasswordDatabase()

        assert 'my_password' not in database
        database['my_password'] = 'secret'
        assert 'my_password' in database

    def test_symmerty(self, rsa_pair):
        """Ensures that encrypt/decrypt is symmentrical"""

        database = PasswordDatabase()
        database['my_password'] = 'secret'
        database.recipients.append(Recipient(rsa_pair.public, 'Test'))

        f = BytesIO()
        database.encrypt(f)

        f.seek(0)
        database2 = PasswordDatabase(f, rsa_pair.private)
        assert database._password_store == database2._password_store
        assert len(database2.recipients) == 1 and database2.recipients[0].comment == 'Test'
