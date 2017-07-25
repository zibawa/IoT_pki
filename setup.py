import os
from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django_IoT_pki',
    version='1.4',
    packages=find_packages(),
    include_package_data=True,
    license='GNU license',  # example license
    description='A simple public key infrastructure to allow issuing and automatic renewal of X509 certificates',
    long_description=README,
    url='https://www.zibawa.com/',
    author='Matt Field',
    author_email='matt.field@zibawa.com',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.11',  # replace "X.Y" as appropriate
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        # Replace these appropriately if you are stuck on Python 2.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Security :: Cryptography',
    ],
    install_requires=[
        'cryptography',
        'djangorestframework',
        'markdown',
        'pyOpenSSL',
        'coreapi',
        
        
        
        ],  
)