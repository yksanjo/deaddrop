from setuptools import setup, find_packages

setup(
    name="deaddrop-client",
    version="1.0.0",
    description="Zero-knowledge agent mailbox client SDK",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.25.0",
        "pynacl>=1.5.0",
    ],
    python_requires=">=3.8",
)
