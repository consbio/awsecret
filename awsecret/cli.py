from base64 import b64encode, b64decode
import json
import os
import click

from Crypto.PublicKey import RSA
from awsecret.database import PasswordDatabase, Recipient
from awsecret.storage import PasswordStore

USERDATA_PATH = os.path.expanduser(os.path.join('~', '.awsec_userdata.json'))


def get_userdata(check_for_keys=False):
    if os.path.exists(USERDATA_PATH):
        with open(USERDATA_PATH, 'r') as f:
            userdata = json.loads(f.read(), strict=False)

            if check_for_keys and 'rsa' not in userdata:
                raise ValueError('No RSA keys found. Did you run awsec keygen?')

            return userdata
    else:
        return {}


def get_profile(name):
    userdata = get_userdata()
    profile = userdata.get('profiles', {}).get(name)
    if not profile:
        raise click.UsageError('No such profile: {0}'.format(name))

    return profile


def decode_key(encoded_key, password=None, tries=0):
    try:
        return RSA.importKey(b64decode(encoded_key.encode()), passphrase=password)
    except ValueError:
        if tries < 3:
            return decode_key(encoded_key, click.prompt('Password', hide_input=True), tries=tries+1)
        else:
            raise click.UsageError('Wrong password')


def write_userdata(profiles):
    with open(USERDATA_PATH, 'w') as f:
        f.write(json.dumps(profiles, indent=4))


def write_profile(name, profile):
    userdata = get_userdata()

    if 'profiles' not in userdata:
        userdata['profiles'] = {}

    userdata['profiles'][name] = profile
    write_userdata(userdata)


def get_password_store(profile):
    return PasswordStore(profile['s3_bucket'], profile['s3_key'], profile['aws_access_key'], profile['aws_secret_key'])


def get_database(profile, storage=None):
    userdata = get_userdata(check_for_keys=True)
    private_key = decode_key(userdata['rsa']['key'])

    if storage is None:
        storage = get_password_store(profile)

    if not storage.exists():
        raise click.UsageError('No database file found. Did you run awsec initdb?')

    return storage.get_database(private_key)


@click.group(help='awsecret command line interface')
def main():
    # Create empty profiles file if none exists
    if not get_userdata():
        write_userdata({})


@main.group('profile', help='Profile management')
def profile_group():
    pass


@profile_group.command('create')
@click.option('--name', prompt='New profile name')
@click.option('--aws-access-key', prompt='AWS Access Key')
@click.option('--aws-secret-key', prompt='AWS Secret Key', hide_input=True)
@click.option('--s3-bucket', prompt='S3 bucket')
@click.option('--s3-key', prompt='S3 key')
def profile_create(name, aws_access_key, aws_secret_key, s3_bucket, s3_key):
    profiles = get_userdata().get('profiles', {})

    if name in profiles:
        click.confirm('The profile {0} already exists. Overwrite?'.format(name), abort=True)

    profile = {
        'aws_access_key': aws_access_key,
        'aws_secret_key': aws_secret_key,
        's3_bucket': s3_bucket,
        's3_key': s3_key
    }

    write_profile(name, profile)

    click.echo('Created profile {0}.'.format(name))


@profile_group.command('list')
def profile_list():
    profiles = get_userdata().get('profiles', {})
    click.echo('\n'.join(profiles.keys()))


@profile_group.command('remove')
@click.option('--name', prompt='Profile name')
def profile_remove(name):
    userdata = get_userdata()
    get_profile(name)

    del userdata.get('profiles', {})[name]
    write_userdata(userdata)
    click.echo('Removed profile {0}'.format(name))


@main.command('keygen')
@click.option('--size', type=int, default=4096)
def profile_keygen(size):
    userdata = get_userdata()

    if 'rsa' in userdata:
        click.confirm('This profile already has an RSA key pair. Do you want to replace it?', abort=True)
        click.confirm(
            'Are you sure? This make make any existing password databases inaccessible and cannot be undone!',
            abort=True
        )

    password = click.prompt('Password (optional)', hide_input=True, default='')
    if password:
        confirm_password = click.prompt('Again', hide_input=True)
        if password != confirm_password:
            raise click.UsageError("Passwords don't match!")

    click.echo('Generating key pair. This may take a while...')
    key = RSA.generate(size)
    public_key = key.publickey()

    userdata['rsa'] = {
        'key': b64encode(key.exportKey('PEM', passphrase=password or None)).decode(),
        'public_key': b64encode(public_key.exportKey('PEM')).decode()
    }

    write_userdata(userdata)

    click.echo('Key pair created. Your public key is:\n\n{0}'.format(public_key.exportKey('OpenSSH').decode()))


@main.command('export-public-key')
@click.argument('output', type=click.File('w'))
def profile_export_public_key(output, name):
    userdata = get_userdata(check_for_keys=True)

    public_key = decode_key(userdata['rsa']['public_key'])
    output.write(public_key.exportKey('OpenSSH').decode())


@main.command('initdb', help='Create an empty password database.')
@click.option('--name', prompt='Profile name')
@click.option('--email', prompt='Your email address')
def init_database(name, email):
    userdata = get_userdata(check_for_keys=True)
    public_key = decode_key(userdata['rsa']['public_key'])
    profile = get_profile(name)
    storage = get_password_store(profile)

    storage.lock()
    try:
        if storage.exists():
            raise click.UsageError('Cannot create new database, one already exists!')

        database = PasswordDatabase()
        database.recipients.append(Recipient(public_key, email))
        storage.set_database(database)

        click.echo('Empty database created.')
    finally:
        storage.release()


@main.command('set', help='Set a value in the database')
@click.option('--name', prompt='Profile name')
@click.argument('key')
@click.argument('value')
def set_value(key, value, name):
    profile = get_profile(name)
    storage = get_password_store(profile)

    storage.lock()
    try:
        database = get_database(profile, storage)
        database[key] = value
        storage.set_database(database)
    finally:
        storage.release()

    click.echo('Successfully updated {0}'.format(key))


@main.command('get', help='Get a value in the database')
@click.option('--name', prompt='Profile name')
@click.argument('key')
def get_value(key, name):
    profile = get_profile(name)
    database = get_database(profile)

    click.echo(database.get(key))


@main.command('dump', help='Dump all values to a JSON file.')
@click.argument('output', type=click.File('w'))
@click.option('--name', prompt='Profile name')
def dump_values(output, name):
    profile = get_profile(name)
    database = get_database(profile)

    output.write(json.dumps(database._password_store, indent=4))


@main.command('load', help='Load values from a JSON file.')
@click.argument('input', type=click.File('r'))
@click.option('--name', prompt='Profile name')
@click.option(
    '--overwrite/--no-overwrite', default=False, help='Overwrite duplicate values with values from the input file.'
)
@click.option(
    '--truncate/--no-truncate', default=False,
    help='Erase all existing values in the database before loading from the input file.'
)
def load_values(input, name, overwrite, truncate):
    profile = get_profile(name)
    storage = get_password_store(profile)

    storage.lock()
    try:
        database = get_database(profile, storage)
        data = json.loads(input.read(), strict=False)

        if truncate:
            database._password_store = {}

        for key, value in data.items():
            if overwrite or key not in database:
                database[key] = value

        storage.set_database(database)
    finally:
        storage.release()


@main.group('keys', help='Manage keys in the database.')
def keys_group():
    pass


@keys_group.command('list', help='List keys in the database.')
@click.option('--name', prompt='Profile name')
def keys_list(name):
    profile = get_profile(name)
    database = get_database(profile)

    for recipient in database.recipients:
        key_str = recipient.public_key.exportKey('OpenSSH').decode()
        click.echo('{0}    {1} ...'.format(recipient.comment, key_str[-20:]))


@keys_group.command('add', help='Add a key to the database.')
@click.argument('input', type=click.File('r'))
@click.option('--name', prompt='Profile name')
@click.option('--comment', prompt='Key comment (e.g., user email)')
def keys_add(input, name, comment):
    profile = get_profile(name)
    storage = get_password_store(profile)

    storage.lock()
    try:
        database = get_database(profile, storage)
        public_key = RSA.importKey(input.read())
        database.recipients.append(Recipient(public_key, comment))

        storage.set_database(database)
    finally:
        storage.release()


@keys_group.command('remove', help='Remove a key from the database.')
@click.option('--name', prompt='Profile name')
def keys_remove(name):
    profile = get_profile(name)
    database = get_database(profile)

    for i, recipient in enumerate(database.recipients):
        key_str = recipient.public_key.exportKey('OpenSSH').decode()
        click.echo('{0}: {1}    {2}'.format(i+ 1, recipient.comment, key_str[-20:]))

    idx = click.prompt('Which key do you want to remove? (1 - {0})'.format(len(database.recipients)), type=int)
    if idx < 1 or idx > len(database.recipients):
        raise ValueError('Invalid selection: {0}'.format(idx))

    storage = get_password_store(profile)

    storage.lock()
    try:
        database = get_database(profile, storage)
        del database.recipients[idx-1]

        storage.set_database(database)
    finally:
        storage.release()


if __name__ == '__main__':
    main()
