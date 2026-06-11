from src import (
    info,
    ip_pattern,
    domain_pattern,
    replace_pattern
)

import tldextract

# Use bundled PSL; do not fetch from network
extractor = tldextract.TLDExtract(
    suffix_list_urls=None
)


def convert_to_domain_list(block_content: str, white_content: str) -> list[str]:
    white_domains = set()
    block_domains = set()

    extract_domains(white_content, white_domains)
    info(f"Number of whitelisted domains: {len(white_domains)}")

    extract_domains(block_content, block_domains)

    block_domains = remove_subdomains_if_higher(block_domains)
    info(f"Number of blocked domains: {len(block_domains)}")

    final_domains = sorted(block_domains - white_domains)
    info(f"Number of final domains: {len(final_domains)}")

    return final_domains


def extract_domains(content: str, domains: set[str]) -> None:
    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith(("#", "!", "/")):
            continue

        line = line.lower()

        if "#" in line:
            line = line.partition("#")[0]

        if "^" in line:
            line = line.partition("^")[0]

        domain = replace_pattern.sub("", line, count=1).strip()

        # Normalize common adblock syntaxes
        domain = domain.lstrip(".")
        if domain.startswith("*."):
            domain = domain[2:]

        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            continue

        # Reject obvious garbage
        if len(domain) > 253:
            continue

        if ".." in domain:
            continue

        if not domain_pattern.match(domain):
            continue

        if ip_pattern.match(domain):
            continue

        # Reject public suffixes (com, net, co.uk, etc.)
        ext = extractor(domain)

        if ext.domain == "":
            continue

        domains.add(domain)


def remove_subdomains_if_higher(domains: set[str]) -> set[str]:
    result = set()

    for domain in domains:
        keep = True

        pos = domain.find(".")

        while pos != -1:
            parent = domain[pos + 1:]

            if parent in domains:
                keep = False
                break

            pos = domain.find(".", pos + 1)

        if keep:
            result.add(domain)

    return result
