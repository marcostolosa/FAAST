#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f.readlines() if not line.startswith("#")]

setup(
    name="faast",
    version="0.1.0",
    author="FAAST Project Contributors",
    author_email="marcos.tolosa@owasp.org",
    description="Full Agentic Application Security Testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/marcostolosa/faast",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.3.0",
            "isort>=5.10.1",
            "mypy>=0.950",
            "flake8>=4.0.1",
        ],
        "pdf": [
            "weasyprint>=59.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "faast=faast_agent.main:main",
        ],
    },
)