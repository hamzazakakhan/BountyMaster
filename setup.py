from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bug-bounty-cli",
    version="1.0.0",
    author="Bug Bounty CLI Team",
    description="AI-powered bug bounty CLI tool leveraging Kali Linux tools and OWASP Top 10",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/bug-bounty-cli",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=[
        "click>=8.1.7",
        "rich>=13.7.0",
        "typer>=0.9.0",
        "requests>=2.31.0",
        "aiohttp>=3.9.1",
        "openai>=1.6.0",
        "beautifulsoup4>=4.12.2",
        "lxml>=4.9.3",
        "selenium>=4.16.0",
        "python-nmap>=0.7.1",
        "scapy>=2.5.0",
        "pandas>=2.1.4",
        "pydantic>=2.5.3",
        "pyyaml>=6.0.1",
        "sqlalchemy>=2.0.23",
        "loguru>=0.7.2",
        "python-dotenv>=1.0.0",
        "jinja2>=3.1.2",
        "markdown>=3.5.1",
        "reportlab>=4.0.7",
        "scikit-learn>=1.3.2",
        "numpy>=1.26.2",
        "colorama>=0.4.6",
        "tqdm>=4.66.1",
        "python-dateutil>=2.8.2",
        "validators>=0.22.0",
    ],
    entry_points={
        "console_scripts": [
            "bugbounty=src.main:app",
        ],
    },
)
