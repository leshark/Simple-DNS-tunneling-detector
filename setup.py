import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="dns_tunneling_detector",
    version="1.0",
    author="leshark",
    author_email="al.pyrko@yandex.ru",
    description="Simple DNS tunneling detector",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/leshark/Simple-DNS-tunneling-detector",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_data={
        "": ["pcap_examples", "example_output", "*.ini", "*.txt"],
    },
    python_requires='>=3.7',
    install_requires=["dpkt", "jsonschema"]
)
