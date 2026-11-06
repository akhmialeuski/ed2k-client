# ed2k-client

A Python client for the eDonkey2000 (eD2k) network and its serverless Kad overlay, written as a library: one
`Client` object connects to a server and to Kad, searches for files by words and extension, downloads them from
many peers at once into a quarantine, verifies every part, inspects the content and only then releases the file.
It can also share files with other peers. The protocol details follow the C++ reference clients
[aMule](https://github.com/amule-project/amule) and [eMule](https://github.com/irwir/eMule).

The PoC was built to find and fetch books, so by default a search looks for PDF and DjVu files and a finished
download leaves quarantine only when its content really is a safe PDF or DjVu document.

## Installation

The package needs Python 3.14 and one runtime dependency, [pycryptodome](https://www.pycryptodome.org/), which
provides MD4 and RC4. OpenSSL 3 no longer offers MD4 through `hashlib`, and eD2k hashes are MD4.

```bash
uv sync
```

## Using the library

```python
import asyncio

from ed2k_client import Client, ClientConfig


async def main() -> None:
    async with Client(ClientConfig()) as client:
        await client.connect()  # log in to the busiest server of the eMule Security server.met
        await client.connect_kad()  # bootstrap Kad from the eMule Security nodes.dat
        results = await client.search('kademlia')  # PDF and DjVu files, most sources first
        for result in results[:10]:
            print(result.sources, result.size, result.name, result.link)
        finished = await client.download(results[0], progress=print)
        print(finished.path, finished.inspection)


asyncio.run(main())
```

The main entry points:

| Call                                                 | What it does                                                  |
| ---------------------------------------------------- | ------------------------------------------------------------- |
| `Client(ClientConfig(...))`                          | Loads or creates the identity, takes the state directory lock |
| `await client.connect(server=None)`                  | Logs in to a server and returns the assigned High or Low ID   |
| `await client.connect_kad()`                         | Bootstraps Kad and returns the number of live contacts        |
| `await client.search('words')`                       | Searches PDF and DjVu files on the server and in Kad          |
| `await client.search(SearchQuery(...))`              | Searches with explicit extensions, file type and size limits  |
| `await client.find_sources(file_hash=..., size=...)` | Asks the server and Kad which peers hold a file               |
| `await client.download(result_or_link)`              | Downloads, verifies, inspects and releases one file           |
| `await client.share(path)`                           | Shares a file or a directory and publishes it on the server   |
| `client.status`                                      | Server, ID, Kad contacts and shared files                     |
| `hash_file(path)`, `FileLink.parse(text)`            | Compute an eD2k hash, parse or build `ed2k://` links          |

Several downloads run concurrently with `asyncio.gather` on one client. One state directory serves one client at a
time, because a server keeps a single session per user hash.

## Command line

```bash
uv run ed2k-client search "springer 2025" --json
uv run ed2k-client download "ed2k://|file|Book.pdf|5648714|E737E3459E12C22118C48306FAE1D8EB|/"
uv run ed2k-client share ~/books --seconds 3600
uv run ed2k-client hash book.pdf
uv run ed2k-client servers
```

`--server ed2k://|server|ip|port|/` picks a server, `--no-kad` and `--no-server` skip a network, and `--udp-port 0`
lets Kad use any free port. `download` accepts several links and fetches them concurrently with one identity.

## Design

The package is layered so that each module owns one concern:

| Layer          | Modules                                                     | Responsibility                                  |
| -------------- | ----------------------------------------------------------- | ----------------------------------------------- |
| Facade         | `client.py`, `cli.py`                                       | One object and one command line over everything |
| Transfers      | `download.py`, `partfile.py`, `share.py`                    | Scheduling, verification, resume, serving       |
| Sessions       | `server.py`, `peer.py`, `kad/node.py`                       | The three protocol conversations                |
| Transport      | `transport.py`, `obfuscation.py`                            | Framed TCP packets, limits, timeouts, RC4       |
| Wire format    | `wire.py`, `tags.py`, `search.py`, `links.py`, `hashing.py` | Bytes in and out, parsed with hard limits       |
| Bootstrap data | `servermet.py`, `kad/contacts.py`, `fetch.py`               | `server.met`, `nodes.dat`, HTTPS download       |
| Defences       | `security.py`, `identity.py`                                | Names, paths, addresses, content, identity      |

A download keeps a part file in `<download_dir>/.incoming` with its progress in JSON next to it, both readable by
the owner only. Workers dial the sources the server and Kad report, request up to three 180 KiB blocks at a time,
accept raw or zlib-compressed blocks, and verify every 9,728,000-byte part against the hashset. A peer that queues
the client is asked again after 21.7 minutes at the earliest, as eMule's `FILEREASKTIME`, because eMule bans clients
that ask more often than every ten minutes. A part that fails its hash convicts its peer only when that peer alone
delivered it. A part with several contributors is fetched again from one peer, so the next failure is unambiguous.

## Defences

Everything that arrives from the network is untrusted, and these are the defences:

- Every length field is checked against a limit before anything is read or allocated, and zlib data is inflated
  with an output cap, so a malformed or hostile packet costs a bounded amount of memory and time.
- Addresses from servers, Kad and peers are dialled only when they are global unicast IPv4 addresses outside an
  optional eMule `ipfilter.dat`, so a hostile server cannot make the client probe the local network.
- File names from the network are sanitised to one path component and every write is proved to stay inside its
  directory, which defeats `../` and absolute-path tricks.
- Downloaded data stays in quarantine until its eD2k hash and every part hash match. The content is then classified
  by its magic bytes: executables, scripts and archives are refused, a PDF is refused when its dictionaries carry
  `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA` or `/SubmitForm` (hex-escaped names
  included), and only PDF and DjVu are released by default. Released files are mode 0600, never executable.
- Sharing is off until `share()` is called. Peers name files only by hash, symbolic links are not shared, and a
  file changed on disk after hashing is withdrawn instead of served.
- Kad answers are accepted only from a node the client is waiting on for that opcode, which drops forged answers.
- `server.met` and `nodes.dat` are fetched over HTTPS only.

The content inspection catches the common carriers of PDF malware, but it does not parse compressed object
streams, so it reports `/ObjStm` as notable. A file that passes is still untrusted data: open it in an up-to-date
viewer with JavaScript disabled.

## Tests

| Command                        | What runs                                                             |
| ------------------------------ | --------------------------------------------------------------------- |
| `uv run pytest`                | Unit tests in memory, including RHash vectors for the eD2k hash       |
| `uv run pytest -m integration` | Real clients over loopback, a fake eD2k server and a fake Kad network |
| `uv run pytest -m network`     | The live eD2k and Kad networks, on a host that may reach them         |

The integration suite downloads every size class of the part rules, raw and compressed blocks, obfuscated and plain,
from three seeders at once, through a seeder that vanishes, past a seeder that corrupts data, through an upload
queue, after an interruption, from a seeder that comes online late, through a server callback, and through server
and Kad search with sources from each network. The pre-commit gate runs ruff, ty, mypy, pyrefly and the unit tests:

```bash
uv run pre-commit run --all-files --config PoCs/ed2k-client/.pre-commit-config.yaml
```

## Limitations

The client is a Low ID client when its TCP port is not reachable from the internet. It can then download only from
High ID peers and be reached only through a server callback, because Kad buddies and NAT traversal are not
implemented. It does not implement AICH, source exchange, server UDP queries, Kad publishing, Secure User
Identification or the obfuscated server connection. Some servers accept a login and still ignore searches. On
2026-11-06 eMule Sunrise did so while ed2k-rust answered.
