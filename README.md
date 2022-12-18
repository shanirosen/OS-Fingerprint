# Welcome to OS Fingerprint!

This project intends to re-create nmap's tool for OS detection, 
using the methods described here: https://nmap.org/book/osdetect.html,
and the scapy library.

**© Shani Rosen 2022**

# Usage

First, clone the project and make sure to have all the requirements with:

```python
pip install -r requirements.txt
```
Then you can run the program by running:
```python
python main.py [host]
```
For example:
```python
sudo python main.py nmap.scanme.org
```
```python
sudo python main.py 45.33.32.156
```
> **Note:** The program has to run in root privileges! 

## Extra Parameters

|Param|Extended Version|Purpose|
|--|--|--|
| -h|- - help | General help 
| -f|- - fast  |  Shortening the amount of ports the program scans, so the result is faster|
|-t | - - timeout |Defining the timeout for receiving an answer to a packet. By default 5 seconds.| 
|-r |- - results |Define the number of top results to show. The default is 10.
|-p |- - ports |Show the result of the port scan. 
|-d |- - debug |Debug mode - logs every main function that runs, along with cpu usage, memory and duration.  
