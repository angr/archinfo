from distutils.core import setup
setup(
    name='archinfo',
    version='4.5.9.9b',
    packages=['archinfo'],
    install_requires=[ 'capstone', 'pyelftools', 'pyvex' ]
)
