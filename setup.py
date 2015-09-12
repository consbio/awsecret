from setuptools import setup

setup(
    name='awsecret',
    description='Secure credential storage in S3.',
    keywords='password,aws,s3,credentials,encryption',
    version='0.1.0',
    packages=['awsecret'],
    requires=['pycrypto', 'boto', 'click'],
    url='https://github.com/consbio/awsecret',
    license='BSD',
    entry_points={
        'console_scripts': ['awsec=awsecret.cli:main']
    }
)
