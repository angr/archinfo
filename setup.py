from distutils.core import setup
setup(
    name='archinfo',
    version='5.6.8.22',
    packages=['archinfo'],
    install_requires=[ 'capstone', 'pyelftools' ]
)
