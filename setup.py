from distutils.core import setup
setup(
    name='archinfo',
    version='4.6.3.15',
    packages=['archinfo'],
    install_requires=[ 'capstone', 'pyelftools' ]
)
