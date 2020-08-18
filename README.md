# Simple-DNS-tunneling-detector
This is a simple DNS tunneling detector written at [Fintech & Security Superhero hackathon](https://dshkazan.ru/finsec)
<br>
This code works on pure python 3.7 and uses some simple metrics to detect DNS tunnels (only HTTP traffic supported)

### Working scheme
<br>

![](https://storage.geekclass.ru/images/21abe9fb-aaf0-4523-882f-4dd06c803da2.png)

### Filtration algorithm
![](https://storage.geekclass.ru/images/b6e0eea7-5a92-431d-bfa9-4ca1e451b71e.png)

### TODO
* Add some statistical analysis
* Apply machine learning to find most suitable detection criteria
* Rewrite in C++ for better speed

### Things to read 
* H. (n.d.). IPoverDNS. Retrieved August 07, 2020, from https://sarwiki.informatik.hu-berlin.de/IPoverDNS
* Yu, B., Smith, L., Threefoot, M., & Olumofin, F. (1970, January 01). [PDF] Behavior Analysis based DNS Tunneling Detection and Classification with Big Data Technologies: Semantic Scholar. Retrieved August 07, 2020, from https://www.semanticscholar.org/paper/Behavior-Analysis-based-DNS-Tunneling-Detection-and-Yu-Smith/b7bc7d2eb9c0f18b5e0e5da3cc6903acfe7c29fe
* Aiello, M., Mongelli, M., Muselli, M., & Verda, D. (2018, December 10). Unsupervised learning and rule extraction for Domain Name Server tunneling detection. Retrieved August 07, 2020, from https://onlinelibrary.wiley.com/doi/10.1002/itl2.85
* Koza, R. (2017). Real-time Detection of Network Tunnels (Master's thesis, Masaryk University Faculty of Informatics, 2017). Brno. Retrieved August 07, 2020, from https://is.muni.cz/th/p7gwp/text_prace.pdf
* Farnham, G. (2013). Detecting DNS Tunneling. Retrieved August 7, 2020, from https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152
