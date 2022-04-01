from setuptools import find_packages, setup

with open("README.md", "r") as f:
    long_desciption = f.read()

with open("requirements.txt", "r") as f:
    install_requires = f.read().splitlines()

setup(
    name="bota",
    version="0.1.0",
    author="Daniel Uhříček",
    author_email="daniel.uhricek@gypri.cz",
    url="https://github.com/danieluhricek/bota",
    description="BOTnet Analysis",
    long_desciption=long_desciption,
    long_description_content_type="text/markdown",
    install_requires=install_requires,
    packages=find_packages(),
)
