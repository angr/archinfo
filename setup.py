from distutils.core import setup
setup(
    name='archinfo',
    version='5.6.12.3',
    packages=['archinfo'],
    install_requires=[ 'capstone', 'pyelftools' ]
)
