from distutils.core import setup
setup(
    name='archinfo',
    version='5.6.10.5',
    packages=['archinfo'],
    install_requires=[ 'capstone', 'pyelftools' ]
)
