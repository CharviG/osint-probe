from setuptools import setup

setup(
    name='osint_probe',
    author='Ajoy Oommen',
    description='An OSINT tool made using Spiderfoot',
    license='MIT',
    packages=['modules'],
    py_modules=['sflib', 'osint_probe'],
    install_requires=[
        'beautifulsoup4',
        'lxml',
        'netaddr',
        'requests'
    ]
)
