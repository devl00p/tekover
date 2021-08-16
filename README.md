# Tekover

A subdomain takeover scanner using Python asyncio framework.

## Installation

`pip install tekover`

## Usage

```
        ▄▄▄█████▓▓█████  ██ ▄█▀ ▒█████   ██▒   █▓▓█████  ██▀███  
        ▓  ██▒ ▓▒▓█   ▀  ██▄█▒ ▒██▒  ██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
        ▒ ▓██░ ▒░▒███   ▓███▄░ ▒██░  ██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
        ░ ▓██▓ ░ ▒▓█  ▄ ▓██ █▄ ▒██   ██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄  
          ▒██▒ ░ ░▒████▒▒██▒ █▄░ ████▓▒░   ▒▀█░  ░▒████▒░██▓ ▒██▒
          ▒ ░░   ░░ ▒░ ░▒ ▒▒ ▓▒░ ▒░▒░▒░    ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
            ░     ░ ░  ░░ ░▒ ▒░  ░ ▒ ▒░    ░ ░░   ░ ░  ░  ░▒ ░ ▒░
          ░         ░   ░ ░░ ░ ░ ░ ░ ▒       ░░     ░     ░░   ░ 
                    ░  ░░  ░       ░ ░        ░     ░  ░   ░     
                                             ░                   
usage: tekover [-h] [--tasks TASKS] [-w WORDLIST] [-v] [--skip-check] [-o OUTPUT] domain [domain ...]

Tekover: Subdomain takeover scanner

positional arguments:
  domain                Domain name to scan for subdomain takeovers. May be either domain name of filename containing domains.

optional arguments:
  -h, --help            show this help message and exit
  --tasks TASKS         Number of concurrent tasks to use. Default is 100.
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist file containing the subdomains, one per line
  -v, --verbose         Print every existing CNAME found
  --skip-check          Skip checking resolvers status before using them (will be slower unless you filtered them yourself)
  -o OUTPUT, --output OUTPUT
                        Output file where to write vulnerable domains. Append mode.
```
