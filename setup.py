from distutils.core import setup

setup(
    name='foorep',
    version='0.1.0',
    author='Johan Berggren',
    author_email='jbn@klutt.se',
    packages=['foorep', 'foorep.test'],
    url='http://foorensics.blogspot.com',
    license='LICENSE.txt',
    description='Malware Repository for humans',
    long_description=open('README.txt').read(),
    install_requires=[
        "pymongo==2.4",
        "CherryPy==3.2.2",
        "Jinja2==2.6",
        "pefile==1.2.10-123",
    ],
    include_package_data=True,
    package_data = {
        'foorep': [
            'plugins/*',
            'site/static/js/*',
            'site/static/css/*',
            'site/static/img/*',
            'site/templates/*',
            'site/static/bootstrap/js/*',
            'site/static/bootstrap/css/*',
            'site/static/bootstrap/img/*']
        },
        entry_points={
            'console_scripts':
                ['foorep=foorep.cli:main', 'foorepd=foorep.web:main']
        },
)
