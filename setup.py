from setuptools import setup, find_packages

setup(
    name='archinfo',
    version='9.1.gitrolling',
    python_requires='>=3.6',
    packages=find_packages(),
    package_data={'archinfo': ['py.typed']},
    url="https://github.com/angr/archinfo",
)
