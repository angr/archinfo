from distutils.core import setup
setup(
    name='archinfo',
    version='4.5.9.14',
    packages=['archinfo'],
    install_requires=[ 'capstone', 'pyelftools', 'pyvex' ]
)
