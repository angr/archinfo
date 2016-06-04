from distutils.core import setup
setup(
    name='archinfo',
    version='4.6.6.4',
    packages=['archinfo'],
    install_requires=[ 'capstone', 'pyelftools' ]
)
