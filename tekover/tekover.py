import asyncio
import signal
import socket
import re
from typing import Tuple, List, Iterator, Set
from itertools import cycle
from functools import lru_cache
import logging
import json
import argparse
import os
from random import shuffle

from tld import get_fld
from tld.exceptions import TldDomainNotFound, TldBadUrl
import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver
import httpx
from rich.logging import RichHandler
from rich.progress import Progress

DEFAULT_TASKS_COUNT = 100
FORMAT = "%(message)s"
logging.basicConfig(
    level="INFO", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(show_path=False)]
)

log = logging.getLogger("rich")

IPV4_REGEX = re.compile(r"(\d+)\.(\d+)\.(\d+)\.(\d+)$")
GITHUB_IO_REGEX = re.compile(r"([a-z0-9]+)\.github\.io$")
MY_SHOPIFY_REGEX = re.compile(r"([a-z0-9-]+)\.myshopify\.com$")

current_dir = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
FINGERPRINTS_FILENAME = os.path.join(current_dir, "data", "fingerprints.json")
RESOLVERS_FILENAME = os.path.join(current_dir, "data", "resolvers.txt")
SUBDOMAINS_FILENAME = os.path.join(current_dir, "data", "subdomain-wordlist.txt")


class Takeover:
    def __init__(self):
        with open(FINGERPRINTS_FILENAME, errors="ignore") as fd:
            data = json.load(fd)
            self.ignore = []
            for ignore_regex in data["ignore"]:
                self.ignore.append(re.compile(r"(" + ignore_regex + r")"))
            self.services = data["services"]

    @staticmethod
    async def check_content(subdomain: str, fingerprints: List[str]) -> bool:
        if fingerprints:
            async with httpx.AsyncClient() as client:
                results = await asyncio.gather(
                    client.get(f"http://{subdomain}/", timeout=10),
                    client.get(f"https://{subdomain}/", timeout=10),
                    return_exceptions=True
                )
                for result in results:
                    if isinstance(result, BaseException):
                        continue
                    for pattern in fingerprints:
                        if pattern in result.text:
                            return True

        return False

    async def check(self, origin: str, domain: str) -> bool:
        if "." not in domain or domain.endswith((".local", ".internal")):
            # Stuff like "localhost": internal CNAMEs we can't control
            return False

        # Check for known false positives first
        for regex in self.ignore:
            if regex.search(domain):
                return False

        if IPV4_REGEX.match(domain):
            # Obviously we can't take control over any IP on the Internet
            return False

        # Is the pointed domain part of some particular takeover case?
        for service_entry in self.services:
            for cname_regex in service_entry["cname"]:
                if re.search(cname_regex, domain):
                    # The pointed domain match one of the rules, check the content on the website if necessary
                    result = await self.check_content(origin, service_entry["fingerprint"])
                    if result:
                        search = GITHUB_IO_REGEX.search(domain)
                        if search:
                            # This is a github.io website, we need to check is the username/organization exists
                            username = search.group(1)
                            try:
                                async with httpx.AsyncClient() as client:
                                    response = await client.head(f"https://github.com/{username}", timeout=10.)
                                    if response.status_code == 404:
                                        return True
                            except httpx.RequestError as exception:
                                log.warning(f"HTTP request to https://github.com/{username} failed")
                            return False

                        search = MY_SHOPIFY_REGEX.search(domain)
                        if search:
                            # Check for myshopify false positives
                            shop_name = search.group(1)
                            try:
                                async with httpx.AsyncClient() as client:
                                    # Tip from https://github.com/buckhacker/SubDomainTakeoverTools
                                    response = await client.get(
                                        (
                                            "https://app.shopify.com/services/signup/check_availability.json?"
                                            f"shop_name={shop_name}&email=test@example.com"
                                        ),
                                        timeout=10.
                                    )
                                    data = response.json()
                                    if data["status"] == "available":
                                        return True
                            except httpx.RequestError as exception:
                                log.warning(f"HTTP request to Shopify API failed")

                            return False

                        return True

                    # Otherwise if the pointed domain doesn't exists if may be enough
                    if service_entry["nxdomain"]:
                        try:
                            await dns.asyncresolver.resolve(domain)
                        except dns.asyncresolver.NXDOMAIN:
                            return True
                        except BaseException:
                            continue

        # What remains is potentially unregistered domain.
        # First: get root domain of the pointed domain
        try:
            root_domain = get_root_domain(domain)
        except (TldDomainNotFound, TldBadUrl):
            # We can't register the pointed domain as it is invalid
            log.warning(f"Pointed domain {domain} is not a valid domain name")
            return False

        try:
            # Second: using SOA on this root domain we check if it is available
            await dns.asyncresolver.resolve(root_domain, "SOA", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return True
        except BaseException as exception:
            log.warning(f"ANY request for {root_domain}: {exception}")

        return False


async def get_wildcard_responses(domain: str, resolvers: Iterator[str]) -> List[str]:
    # Ask for an improbable subdomain to see if there are any responses
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 10.
    resolver.nameservers = [next(resolvers) for __ in range(10)]

    try:
        results = await resolver.resolve(f"supercalifragilisticexpialidocious.{domain}", "CNAME")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
        return []
    return [record.to_text().strip(".") for record in results]


@lru_cache(maxsize=2000)
def get_root_domain(domain: str):
    # May raise tld.exceptions.TldDomainNotFound, tld.exceptions.TldBadUrl
    return get_fld(domain, fix_protocol=True)


def banner():
    print("""\t▄▄▄█████▓▓█████  ██ ▄█▀ ▒█████   ██▒   █▓▓█████  ██▀███  
\t▓  ██▒ ▓▒▓█   ▀  ██▄█▒ ▒██▒  ██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
\t▒ ▓██░ ▒░▒███   ▓███▄░ ▒██░  ██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
\t░ ▓██▓ ░ ▒▓█  ▄ ▓██ █▄ ▒██   ██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄  
\t  ▒██▒ ░ ░▒████▒▒██▒ █▄░ ████▓▒░   ▒▀█░  ░▒████▒░██▓ ▒██▒
\t  ▒ ░░   ░░ ▒░ ░▒ ▒▒ ▓▒░ ▒░▒░▒░    ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
\t    ░     ░ ░  ░░ ░▒ ▒░  ░ ▒ ▒░    ░ ░░   ░ ░  ░  ░▒ ░ ▒░
\t  ░         ░   ░ ░░ ░ ░ ░ ░ ▒       ░░     ░     ░░   ░ 
\t            ░  ░░  ░       ░ ░        ░     ░  ░   ░     
\t                                     ░                   """)


def key_func(ip_address: str) -> str:
    if "." in ip_address:
        return ".".join(num.rjust(3, "0") for num in ip_address.split("."))
    # 'z' is just to make sure IPv6 addresses appear after IVv4 ones
    return "z" + ":".join(num.rjust(4, "0") for num in ip_address.split(":"))


async def test_resolver(resolver_ip: str) -> Tuple[str, bool]:
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [resolver_ip]
    try:
        await resolver.resolve("google.fr")
    except (dns.asyncresolver.NXDOMAIN, dns.exception.Timeout, dns.name.EmptyLabel, dns.resolver.NoNameservers):
        return resolver_ip, False

    return resolver_ip, True


def get_lines_count(filename: str) -> int:
    count = 0
    with open(filename, errors="ignore") as fd:
        for __ in fd:
            count += 1
    return count


def iterate_domains(domains: List[str]) -> Iterator:
    # domains is a list of strings, either a filename (containing a list of domains) or directly a domain name
    for file_or_domain in domains:
        if os.path.isfile(file_or_domain):
            with open(file_or_domain) as fd:
                for line in fd:
                    domain = line.strip()
                    if domain:
                        yield domain
        else:
            yield file_or_domain


def count_iterable(iterator: Iterator) -> int:
    return sum(1 for __ in iterator)


async def feed_queue(
        queue: asyncio.Queue, domains: List[str], event: asyncio.Event, tasks_count: int, wordlist: str,
        domains_count: int):
    subs_count = get_lines_count(wordlist)
    domains_iterator = iterate_domains(domains)

    with Progress() as progress:
        task = progress.add_task(
            f"[green]Enumerating {subs_count} subdomains of {domains_count} domains...",
            total=(subs_count * domains_count) + tasks_count
        )
        for domain in domains_iterator:
            # 'domain' is a (presumably) valid domain name either read from a file or received as command line parameter
            try:
                root_domain = get_root_domain(domain)
            except (TldDomainNotFound, TldBadUrl):
                log.warning(f"{domain} is not a valid domain name")
                progress.update(task, advance=subs_count)  # Obviously we want to skip the wordlist
                continue

            with open(wordlist, errors="ignore") as fd:
                for line in fd:
                    sub = line.strip()

                    if not sub:
                        progress.update(task, advance=1)
                        continue

                    while True:
                        try:
                            queue.put_nowait((f"{sub}.{domain}", root_domain))
                        except asyncio.QueueFull:
                            await asyncio.sleep(.01)
                        else:
                            break

                    progress.update(task, advance=1)

                    if event.is_set():
                        break

            if event.is_set():
                break

        # send stop command to every worker
        for __ in range(tasks_count):
            while True:
                try:
                    queue.put_nowait(("__exit__", "whatever"))
                except asyncio.QueueFull:
                    await asyncio.sleep(.01)
                else:
                    break

            progress.update(task, advance=1)


takeover = Takeover()
flock = asyncio.Lock()


async def worker(queue: asyncio.Queue, resolvers: Iterator[str], verbose: bool, output_file: str,
                 bad_responses: Set[str]):
    global takeover
    global flock

    while True:
        try:
            domain, root_domain = queue.get_nowait()
        except asyncio.QueueEmpty:
            await asyncio.sleep(.05)
        else:
            queue.task_done()
            if domain == "__exit__":
                break

            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = 10.
                resolver.nameservers = [next(resolvers) for __ in range(10)]
                answers = await resolver.resolve(domain, 'CNAME', raise_on_no_answer=False)
            except (socket.gaierror, UnicodeError):
                continue
            except (dns.asyncresolver.NXDOMAIN, dns.exception.Timeout) as exception:
                # print(f"{domain}: {exception}")
                continue
            except (dns.name.EmptyLabel, dns.resolver.NoNameservers) as exception:
                log.warning(f"{domain}: {exception}")
                continue

            for answer in answers:
                cname = answer.to_text().strip(".")

                if cname in bad_responses:
                    # Those are wildcard responses and we don't care
                    continue

                if verbose:
                    log.info(f"Record {domain} points to {cname}")

                try:
                    if get_root_domain(cname) == root_domain:
                        # If it is an internal CNAME (like www.target.tld to target.tld) just ignore
                        continue
                except (TldDomainNotFound, TldBadUrl):
                    log.warning(f"{cname} is not a valid domain name")
                    continue

                if await takeover.check(domain, cname):
                    log.critical(f"{domain} to {cname} CNAME seems vulnerable to takeover")
                    if output_file:
                        async with flock:
                            with open(output_file, "a") as fd:
                                print(f"{domain} to {cname} CNAME seems vulnerable to takeover", file=fd)


def ctrl_c(event: asyncio.Event):
    log.info("Stopping. Please wait...")
    event.set()


def load_resolvers() -> List[str]:
    with open(RESOLVERS_FILENAME, errors="ignore") as fd:
        resolvers = [ip.strip() for ip in fd.readlines() if ip.strip()]
        shuffle(resolvers)
        return resolvers


async def test_resolvers(resolvers: List[str]) -> List[str]:
    valid_resolvers = []
    tasks = [test_resolver(ip) for ip in resolvers]
    with Progress() as progress:
        task = progress.add_task("[green]Testing resolvers...", total=len(tasks))
        for coro in asyncio.as_completed(tasks):
            ip, status = await coro
            if status:
                valid_resolvers.append(ip)
            else:
                log.debug(f"Resolver {ip} seems invalid")
            progress.update(task, advance=1)

    return valid_resolvers


async def get_all_wildcard_responses(
        domains: List[str], resolvers: Iterator[str], tasks_count: int, domains_count: int) -> Set[str]:
    tasks = set()
    wildcard_responses = set()
    domains_iterator = iterate_domains(domains)
    with Progress() as progress:
        progress_task = progress.add_task("[green]Looking for wildcard responses...", total=domains_count)

        for domain in domains_iterator:
            tasks.add(asyncio.create_task(get_wildcard_responses(domain, resolvers)))

            timeout = None if len(tasks) > tasks_count else 0.01
            done, __ = await asyncio.wait(tasks, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                wildcard_responses.update(await task)
                tasks.remove(task)
                progress.update(progress_task, advance=1)

        if tasks:
            wildcard_responses.update(* await asyncio.gather(*tasks))
            progress.update(progress_task, advance=len(tasks))

    return wildcard_responses


async def tekover_main():
    banner()
    parser = argparse.ArgumentParser(description="Tekover: Subdomain takeover scanner")

    parser.add_argument(
        "domains",
        metavar="domain",
        nargs='+',
        help="Domain name to scan for subdomain takeovers. May be either domain name of filename containing domains."
    )

    parser.add_argument(
        "--tasks", type=int,
        default=DEFAULT_TASKS_COUNT,
        help=f"Number of concurrent tasks to use. Default is {DEFAULT_TASKS_COUNT}."
    )

    parser.add_argument(
        "-w", "--wordlist",
        help="Wordlist file containing the subdomains, one per line",
        default=SUBDOMAINS_FILENAME,
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print every existing CNAME found"
    )

    parser.add_argument(
        "--skip-check",
        action="store_true",
        help="Skip checking resolvers status before using them (will be slower unless you filtered them yourself)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file where to write vulnerable domains. Append mode.",
        default=""
    )

    args = parser.parse_args()

    resolvers = load_resolvers()
    if not args.skip_check:
        log.info("Testing resolvers...")
        resolvers = await test_resolvers(resolvers)
        log.info(f"{len(resolvers)} resolvers seem valid")

    resolvers_cycle = cycle(resolvers)
    domains_count = count_iterable(iterate_domains(args.domains))

    log.info("Looking for wildcard responses...")
    wildcard_responses = await get_all_wildcard_responses(args.domains, resolvers_cycle, args.tasks, domains_count)

    if wildcard_responses:
        for wildcard in wildcard_responses:
            log.warning(f"Wildcard response '{wildcard}' will be ignored.")

    log.info(f"Enumerating subdomains of {domains_count} domains...")
    tasks = []
    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, ctrl_c, stop_event)
    sub_queue = asyncio.Queue(maxsize=args.tasks)
    tasks.append(
        asyncio.create_task(feed_queue(sub_queue, args.domains, stop_event, args.tasks, args.wordlist, domains_count))
    )

    for __ in range(args.tasks):
        tasks.append(
            asyncio.create_task(
                worker(sub_queue, resolvers_cycle, args.verbose, args.output, wildcard_responses)
            )
        )

    await asyncio.gather(*tasks)
    log.info("Done")


def tekover_main_wrapper():
    asyncio.run(tekover_main())
