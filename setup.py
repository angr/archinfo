from distutils.core import setup
setup(
    name='archinfo',
    version='4.6.2.25',
    packages=['archinfo'],
    install_requires=[ 'capstone', 'pyelftools' ]
)
