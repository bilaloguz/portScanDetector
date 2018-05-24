TCP Port Scan Detector

As the name indicates, the programme tries to detect TCP port scans and reveals the 'attacker' IP. For the moment, it can only 
detect full (a.k.a. Vanilla) and half (a.k.a. SYN scan) scans.

While running the script, time parameter should also be given with -t switch which will define the working duration. 0 is
continuous run.

Example: python portScanDetector.py -t 5

which indicates program will run for 5 minutes and then stop. 
