from distutils.core import setup
setup(
    name='archinfo',
    version='0.02',
    packages=['archinfo'],
    install_requires=[ 'capstone', 'pyelftools', 'pyvex' ]
)
