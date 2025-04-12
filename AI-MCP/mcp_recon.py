# mcp_recon_server.py
import asyncio
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel
import subprocess

mcp = FastMCP("recon-tools")


def execute(command: str) -> str:
    """Executes a shell command and returns output or error."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"[ERROR] {e.stderr.strip()}"


class DomainArgs(BaseModel):
    domain: str


@mcp.tool()
async def run_subfinder(req: DomainArgs) -> str:
    """
    Enumerate subdomains using subfinder.

    :param domain: Target domain to enumerate
    :type domain: str
    :return: Subdomains found
    :rtype: str
    """
    return execute(f"subfinder -d {req.domain} -silent")


@mcp.tool()
async def run_assetfinder(req: DomainArgs) -> str:
    """
    Enumerate subdomains using assetfinder.

    :param domain: Domain to scan for assets
    :type domain: str
    :return: Subdomains found
    :rtype: str
    """
    return execute(f"assetfinder --subs-only {req.domain}")


@mcp.tool()
async def run_dig(req: DomainArgs) -> str:
    """
    Perform DNS A record lookup using dig.

    :param domain: Domain to query
    :type domain: str
    :return: DNS A record response
    :rtype: str
    """
    return execute(f"dig {req.domain}")


@mcp.tool()
async def run_whois(req: DomainArgs) -> str:
    """
    Perform WHOIS lookup on the domain.

    :param domain: Domain or IP to query
    :type domain: str
    :return: WHOIS information
    :rtype: str
    """
    return execute(f"whois {req.domain}")


@mcp.tool()
async def run_sslscan(req: DomainArgs) -> str:
    """
    Run SSL scan on the target domain.

    :param domain: Domain to scan for SSL/TLS details
    :type domain: str
    :return: SSL scan results
    :rtype: str
    """
    return execute(f"sslscan {req.domain}")


@mcp.tool()
async def run_tlsx(req: DomainArgs) -> str:
    """
    Get TLS certificate data using tlsx.

    :param domain: Target domain for TLS info
    :type domain: str
    :return: TLS metadata
    :rtype: str
    """
    return execute(f"tlsx -host {req.domain}")


@mcp.tool()
async def run_dnsrecon(req: DomainArgs) -> str:
    """
    Run DNS reconnaissance using dnsrecon.

    :param domain: Domain to analyze
    :type domain: str
    :return: DNS records found by dnsrecon
    :rtype: str
    """
    return execute(f"dnsrecon -d {req.domain} -t std")


if __name__ == "__main__":
    asyncio.run(mcp.run_stdio())
