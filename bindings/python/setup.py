from setuptools import setup, find_packages

setup(
    name="secure-protocol",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        # No heavy dependencies, handled by ctypes
    ],
    python_requires=">=3.8",
)
