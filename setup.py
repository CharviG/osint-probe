from setuptools import setup

setup(
    name='osint_probe',
    version='1.0.0',
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
