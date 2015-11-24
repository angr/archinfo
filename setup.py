from distutils.core import setup
setup(
    name='archinfo',
    version='4.5.11.23',
    packages=['archinfo'],
    install_requires=[ 'capstone', 'pyelftools' ]
)
