import json
import uuid
from boto.exception import S3ResponseError
from boto.s3.connection import S3Connection
from boto.s3.key import Key
import time
from io import BytesIO
from awsecret.database import PasswordDatabase

LOCK_TTL = 60  # 1 minute
LOCK_KEY = '{key}.LOCK'


class PasswordStore(object):
    """Manages storage of the password database on S3"""

    def __init__(self, bucket_name, key, aws_access_key, aws_secret_key):
        conn = S3Connection(aws_access_key, aws_secret_key)
        self.bucket = conn.get_bucket(bucket_name)
        self.key = key
        self.lock_id = None
        self.lock_depth = 0

    def _get_lock_info(self):
        s3_key = self.bucket.get_key(LOCK_KEY.format(key=self.key))

        if not s3_key:
            return None
        else:
            try:
                text = s3_key.get_contents_as_string().decode()
                if text:
                    return json.loads(text)
            except S3ResponseError:
                return None

    def _set_lock_info(self, info):
        s3_key = Key(bucket=self.bucket, name=LOCK_KEY.format(key=self.key))
        s3_key.set_contents_from_string(json.dumps(info).encode())

    def _remove_lock(self):
        self.bucket.delete_key(LOCK_KEY.format(key=self.key))

    def lock(self):
        """Acquires an exclusive lock for the password database."""

        lock_info = self._get_lock_info()

        if self.lock_id:
            if lock_info and lock_info.get('id') == self.lock_id:
                self.lock_depth += 1
                return
            else:
                self.lock_id = None
                self.lock_depth = 0
                return self.lock()

        elif lock_info:
            while lock_info and lock_info['timestamp'] + LOCK_TTL > time.time():
                time.sleep(1)
                lock_info = self._get_lock_info()
            if lock_info:
                self._remove_lock()

            return self.lock()

        else:
            self.lock_id = str(uuid.uuid4())
            self.lock_depth = 1
            self._set_lock_info({'id': self.lock_id, 'timestamp': time.time()})

            # Wait a short time and then verify that we successfully won the lock
            time.sleep(0.25)
            lock_info = self._get_lock_info()
            if lock_info and lock_info['id'] == self.lock_id:
                return
            else:
                return self.lock()

    def release(self):
        """Releases the lock for the password database."""

        self.lock_depth -= 1
        if self.lock_depth < 1:
            lock_info = self._get_lock_info()
            if lock_info and lock_info['id'] == self.lock_id:
                self._remove_lock()
                self.lock_id = None
                self.lock_depth = 0

    def exists(self):
        self.lock()
        try:
            s3_key = self.bucket.get_key(self.key)
        except S3ResponseError as e:
            if e.error_code == 404:
                return False
            raise
        finally:
            self.release()

        return s3_key is not None

    def get_database(self, rsa_key):
        """Returns the database, decrypted, or None if the database doesn't exist."""

        self.lock()
        try:
            s3_key = self.bucket.get_key(self.key)
            f = BytesIO()
            s3_key.get_contents_to_file(f)
        except S3ResponseError as e:
            if e.error_code == 404:
                return None
        finally:
            self.release()

        f.seek(0)
        return PasswordDatabase(f, rsa_key)

    def set_database(self, database):
        """Encrypts and writes the database."""

        f = BytesIO()
        database.encrypt(f)
        f.seek(0)

        self.lock()
        try:
            s3_key = Key(bucket=self.bucket, name=self.key)
            s3_key.set_contents_from_file(f)
        finally:
            self.release()
