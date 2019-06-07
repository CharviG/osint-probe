from setuptools import setup


with open('VERSION') as f:
    __version__ = f.read()


setup(
    name='osint_probe',
    version=__version__,
    author='Ajoy Oommen',
    description='An OSINT tool made using Spiderfoot',
    license='MIT',
    packages=['sfp_modules'],
    py_modules=['sflib', 'osint_probe'],
    install_requires=[
        'beautifulsoup4',
        'lxml',
        'netaddr',
        'requests'
    ]
)
