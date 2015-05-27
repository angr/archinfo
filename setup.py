from distutils.core import setup
setup(
    name='archinfo',
    version='0.01',
    packages=['archinfo'],
    install_requires=[i.strip() for i in open('requirements.txt').readlines() if 'git' not in i]
)
