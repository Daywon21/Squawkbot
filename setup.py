from setuptools import setup, find_packages

setup(
    name="squawkbot",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "aiohttp==3.9.5",
        "PyQt6==6.7.0",
        "requests==2.31.0",
        "twitchio==2.8.0",
        "obsws-python>=1.0.3",
        "pywin32==306; platform_system=='Windows'",
        "watchdog==4.0.1"
    ],
    entry_points={
        "console_scripts": [
            "squawkbot = squawkbot.squawkbot:main"
        ]
    },
    author="Javier",
    author_email="daywon1@gmail.com",
    description="A Twitch bot for managin' raids, clips, and OBS integration, arrgh!",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Daywon21/SquawkBot",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
)
