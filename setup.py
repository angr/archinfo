from distutils.core import setup
setup(
    name='archinfo',
    version='4.5.10.15',
    packages=['archinfo'],
    install_requires=[ 'capstone', 'pyelftools' ]
)
