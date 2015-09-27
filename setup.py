from setuptools import setup
from awsecret import VERSION

setup(
    name='awsecret',
    description='Secure credential storage in S3.',
    keywords='password,aws,s3,credentials,encryption',
    version=VERSION,
    packages=['awsecret'],
    install_requires=['pycrypto', 'boto', 'click'],
    url='https://github.com/consbio/awsecret',
    license='BSD',
    entry_points={
        'console_scripts': ['awsec=awsecret.cli:main']
    }
)
