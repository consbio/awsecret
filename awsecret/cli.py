from base64 import b64encode, b64decode
import json
import os
import click

from Crypto.PublicKey import RSA

PROFILES_PATH = os.path.expanduser(os.path.join('~', '.awsec_profiles.json'))


def get_profiles():
    if os.path.exists(PROFILES_PATH):
        with open(PROFILES_PATH, 'r') as f:
            return json.loads(f.read(), strict=False)
    else:
        return {}


def decode_key(encoded_key, password=None, tries=0):
    try:
        return RSA.importKey(b64decode(encoded_key.encode()), passphrase=password)
    except ValueError:
        if tries < 3:
            return decode_key(encoded_key, click.prompt('Password', hide_input=True), tries=tries+1)
        else:
            raise click.UsageError('Wrong password')


def write_profiles(profiles):
    with open(PROFILES_PATH, 'w') as f:
        f.write(json.dumps(profiles, indent=4))


@click.group(help='awsecret command line interface')
def main():
    # Create empty profiles file if none exists
    if not get_profiles():
        write_profiles({})


@main.group(help='Profile management')
def profile():
    pass


@profile.command('create')
@click.option('--name', prompt='New profile name')
@click.option('--aws-access-key', prompt='AWS Access Key')
@click.option('--aws-secret-key', prompt='AWS Secret Key', hide_input=True)
@click.option('--s3-bucket', prompt='S3 bucket')
@click.option('--s3-key', prompt='S3 key')
def profile_create(name, aws_access_key, aws_secret_key, s3_bucket, s3_key):
    profiles = get_profiles()

    if name in profiles:
        click.confirm('The profile {0} already exists. Overwrite?'.format(name), abort=True)

    profiles[name] = {
        'aws_access_key': aws_access_key,
        'aws_secret_key': aws_secret_key,
        's3_bucket': s3_bucket,
        's3_key': s3_key
    }

    write_profiles(profiles)

    click.echo('Created profile {0}.'.format(name))


@profile.command('list')
def profile_list():
    profiles = get_profiles()
    click.echo('\n'.join(profiles.keys()))


@profile.command('remove')
@click.option('--name', prompt='Profile name')
def profile_remove(name):
    profiles = get_profiles()

    if name not in profiles:
        raise click.UsageError('No such profile: {0}'.format(name))

    del profiles[name]
    write_profiles(profiles)
    click.echo('Removed profile {0}'.format(name))


@profile.command('keygen')
@click.option('--name', prompt='Profile name')
@click.option('--size', type=int, default=4096)
def profile_keygen(name, size):
    profiles = get_profiles()

    if name not in profiles:
        raise click.UsageError('No such profile: {0}'.format(name))

    if 'rsa' in profiles[name]:
        click.confirm('This profile already has an RSA key pair. Do you want to replace it?', abort=True)
        click.confirm(
            'Are you sure? This will make the existing password database inaccessible and cannot be undone!',
            abort=True
        )

    password = click.prompt('Password (optional)', hide_input=True, default='')
    if password:
        confirm_password = click.prompt('Again', hide_input=True)
        if password != confirm_password:
            raise click.UsageError("Passwords don't match!")

    key = RSA.generate(size)
    public_key = key.publickey()

    profiles[name]['rsa'] = {
        'key': b64encode(key.exportKey('PEM', passphrase=password or None)).decode(),
        'public_key': b64encode(public_key.exportKey('PEM')).decode()
    }

    write_profiles(profiles)

    click.echo('Key pair created. Your public key is:\n\n{0}'.format(public_key.exportKey('OpenSSH').decode()))


@profile.command('export-public-key')
@click.option('--name', prompt='Profile name')
def profile_export_public_key(name):
    profiles = get_profiles()

    if name not in profiles:
        raise click.UsageError('No such profile: {0}'.format(name))

    if 'rsa' not in profiles[name]:
        raise click.UsageError('Profile {0} does not have a key pair.'.format(name))

    public_key = decode_key(profiles[name]['rsa']['public_key'])
    click.echo(public_key.exportKey('OpenSSH').decode())


if __name__ == '__main__':
    main()
