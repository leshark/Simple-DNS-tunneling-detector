# Simple-DNS-tunneling-detector
[![Python 3.6](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-370/)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/leshark/Simple-DNS-tunneling-detector/Python%20application)
![GitHub repo size](https://img.shields.io/github/repo-size/leshark/Simple-DNS-tunneling-detector)
![GitHub](https://img.shields.io/github/license/leshark/Simple-DNS-tunneling-detector)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat)](http://makeapullrequest.com)

This is a simple DNS tunneling detector written at [Fintech & Security Superhero hackathon](https://dshkazan.ru/finsec)
<br>
This code works on pure Python 3.7 and uses some simple metrics to detect DNS tunnels (only HTTP traffic supported)

### Installation
* Clone this repository into your local directory
* Optionally set path to your directories or enable whitelist in config.ini
* Go to `your_directory/dns_tunneling_detector`
* Run `python3 -m pip install -r requirements.txt`

Now you can run the code with just `python3 __main__.py`

### Installation with Docker
complete the first 3 steps of installation and then run the following:
```
docker build -t dns-detector .
docker run -v $(pwd):/app dns-detector
```
> Remember to mount necessary directories (if you have changed them in config)

### Installation with pip
* Complete first 2 steps of installation
* Run `pip install -e .`
* Go to `your_directory/dns_tunneling_detector`
* Now you can simply do `python3 -m dns_tunneling_detector`

### Working scheme
The script consists of these simple steps:
1. Traffic dumps are read from the input directory
2. Every file is processed in parallel with dpkt library
3. Each packet in the dump is checked according to the filtration algorithm
4. Results are written in the output directory (CSV) alongside with log file and stats (JSON)

> Note that to benefit the most from Python multiprocessing, traffic dumps 
> should be approximately one size 
<br>

![](https://storage.geekclass.ru/images/21abe9fb-aaf0-4523-882f-4dd06c803da2.png)

### Filtration algorithm
The filtration algorithm uses simple criteria which are presented in the picture below:

![](https://storage.geekclass.ru/images/b6e0eea7-5a92-431d-bfa9-4ca1e451b71e.png)
Note that the result CSV will have such headers:
`pcap_name | packet_number | probability(100%, high, medium, low(?)) | reason`

### TODO
Current improvement steps are available [here](https://github.com/leshark/Simple-DNS-tunneling-detector/projects/1)
* Add some statistical analysis
* Apply machine learning to find the most suitable detection criteria
* Rewrite in C++ for better speed

> My humble attempt to rewrite it in C++ is [here](https://gitlab.com/leshark/dns_tunneling_detector/-/tree/master?ref_type=heads)

### Acknowledgments
Special thanks to my hackathon teammates:
* [archercreat](https://github.com/archercreat) - helped with code, whitelist implementation
* [RussianCatYakov](https://github.com/RussianCatYakov) - theoretical support, checkers selection

### Things to read 
* H. (n.d.). IPoverDNS. Retrieved August 07, 2020, from https://sarwiki.informatik.hu-berlin.de/IPoverDNS
* Yu, B., Smith, L., Threefoot, M., & Olumofin, F. (1970, January 01). [PDF] Behavior Analysis based DNS Tunneling Detection and Classification with Big Data Technologies: Semantic Scholar. Retrieved August 07, 2020, from https://www.semanticscholar.org/paper/Behavior-Analysis-based-DNS-Tunneling-Detection-and-Yu-Smith/b7bc7d2eb9c0f18b5e0e5da3cc6903acfe7c29fe
* Aiello, M., Mongelli, M., Muselli, M., & Verda, D. (2018, December 10). Unsupervised learning and rule extraction for Domain Name Server tunneling detection. Retrieved August 07, 2020, from https://onlinelibrary.wiley.com/doi/10.1002/itl2.85
* Koza, R. (2017). Real-time Detection of Network Tunnels (Master's thesis, Masaryk University Faculty of Informatics, 2017). Brno. Retrieved August 07, 2020, from https://is.muni.cz/th/p7gwp/text_prace.pdf
* Farnham, G. (2013). Detecting DNS Tunneling. Retrieved August 7, 2020, from https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152
