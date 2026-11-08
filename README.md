# ed2k-client

A Python client for the eDonkey2000 (eD2k) network and its serverless Kad overlay, written as a library: one
`Client` object connects to a server and to Kad, searches for files by words and extension, downloads them from
many peers at once into a quarantine, verifies every part, inspects the content and only then releases the file.
It can also share files with other peers. The protocol details follow the C++ reference clients
[aMule](https://github.com/amule-project/amule) and [eMule](https://github.com/irwir/eMule).

A search looks for files of every type unless it names extensions, and a finished download leaves quarantine only
when its content carries nothing that runs when it is opened. The PoC was built to fetch books, which a search
for the extensions `pdf` and `djvu` and the `--documents-only` policy still serve.

## Installation

The package needs Python 3.14 and one runtime dependency, [pycryptodome](https://www.pycryptodome.org/), which
provides MD4 and RC4. OpenSSL 3 no longer offers MD4 through `hashlib`, and eD2k hashes are MD4. Until the first
release reaches PyPI, the `ed2k-client` command or the library installs from this repository:

```bash
uv tool install git+https://github.com/akhmialeuski/ed2k-client
pip install git+https://github.com/akhmialeuski/ed2k-client
```

A checkout for development gets the tools of the `dev` dependency group, which never reach the published package,
and the pre-commit hook that runs the gate described under [Tests](#tests). The examples below use `uv run` from
such a checkout, and an installed package runs the same commands without it:

```bash
uv sync
uv run pre-commit install --install-hooks
```

## Using the library

```python
import asyncio

from ed2k_client import Client, ClientConfig


async def main() -> None:
    async with Client(ClientConfig()) as client:
        await client.connect()  # log in to the four busiest servers of the eMule Security server.met
        await client.connect_kad()  # bootstrap Kad from the eMule Security nodes.dat
        results = await client.search('kademlia')  # files of every type, most sources first
        for result in results[:10]:
            print(result.sources, result.size, result.name, result.link)
        finished = await client.download(results[0], progress=print)
        print(finished.path, finished.inspection)


asyncio.run(main())
```

The main entry points:

| Call                                                 | What it does                                                  |
|------------------------------------------------------|---------------------------------------------------------------|
| `Client(ClientConfig(...))`                          | Loads or creates the identity, takes the state directory lock |
| `await client.connect(server=None)`                  | Logs in to up to four servers at once and returns their IDs   |
| `await client.connect_kad()`                         | Bootstraps Kad and returns the number of live contacts        |
| `await client.search('words')`                       | Searches files of every type on every server and in Kad       |
| `await client.search(SearchQuery(...))`              | Searches with explicit extensions, file type and size limits  |
| `await client.find_sources(file_hash=..., size=...)` | Asks every server and Kad which peers hold a file             |
| `await client.download(result_or_link)`              | Downloads, verifies, inspects and releases one file           |
| `await client.share(path)`                           | Shares a file or a directory and publishes it on every server |
| `client.status`                                      | Server sessions with their IDs, Kad contacts, shared files    |
| `hash_file(path)`, `FileLink.parse(text)`            | Compute an eD2k hash, parse or build `ed2k://` links          |

Several downloads run concurrently with `asyncio.gather` on one client. One state directory serves one client at a
time, because a server keeps a single session per user hash.

`connect()` logs in to `server_sessions` servers at once, four by default, because each server indexes its own users'
files: on 2026-11-07 seven servers answered one search with 1,808 distinct files, 1,575 of them known to one server
only. The candidates come from the configured `servers`, a local `server_met` file or the downloaded list, which is
cached as `server.met` in the state directory and read from there when the download fails. Servers that accepted a
login are kept in `servers.json` in the state directory and tried first next time, and one that refuses is dropped.
Peers learn the first live server from the hello, and shared files are published on every live server.

## Settings

Every value the client chose rather than the protocol is a field of `ClientConfig`, grouped by concern, with the
values the PoC was tested with as defaults:

| Group          | Holds                                                                              |
|----------------|------------------------------------------------------------------------------------|
| `ClientConfig` | Directories, ports, nickname, server lists and sessions, `nodes.dat`, IP filter    |
| `download`     | Peers at once, queue wait, reask interval, source refresh, deadline, content check |
| `timeouts`     | Connect, read, server login, search and sources, bootstrap download                |
| `limits`       | Caps on packet sizes, tags, strings, results, sources and bootstrap files          |
| `kad`          | Lookup parallelism and width, rounds, bootstrap and search fan-out, Kad timeout    |
| `peer`         | Blocks per request, send chunk, obfuscation padding                                |
| `share`        | Upload slots, incoming connections                                                 |
| `io`           | Read, scan and file-type buffer sizes                                              |

```python
from dataclasses import replace
from pathlib import Path

from ed2k_client import ClientConfig, DownloadSettings

config = replace(ClientConfig(), download=DownloadSettings(deadline=24 * 3600, max_peers=8))
config = ClientConfig.from_toml(Path('my-settings.toml'))
```

Each group refuses a value that cannot work when it is built. Values the protocol fixes, such as the part size,
the obfuscation magic numbers and the Kad search tolerance, stay constants, because changing them would break every
exchange with other clients. [config.example.toml](config.example.toml) lists every setting with its default and
description, and `scripts/render_config_example.py` regenerates it from the code.

## Command line

```bash
uv run ed2k-client search "springer 2025" --json
uv run ed2k-client search "springer 2025" --ext pdf djvu epub
uv run ed2k-client download "ed2k://|file|Book.pdf|5648714|E737E3459E12C22118C48306FAE1D8EB|/" --deadline-hours 24
uv run ed2k-client --config config.example.toml share ~/books --seconds 3600 --upload-slots 4
uv run ed2k-client hash book.pdf
uv run ed2k-client servers --save ~/server.met
uv run ed2k-client --config config.example.toml search "springer 2025" --server-met ~/server.met
```

`scripts/ed2k.py` runs the same command line from a checkout with `uv run scripts/ed2k.py ...`. `--config` reads a
TOML file shaped like [config.example.toml](config.example.toml), and a flag wins over the file. `--server
ed2k://|server|ip|port|/` picks a single server, `--server-met` reads the server list from a file that `servers
--save` wrote, `--no-kad` and `--no-server` skip a network, `--udp-port 0` lets Kad use any free port, `--port 0`
takes any free TCP port before the login and announces the port it got, and `--connect-timeout` and `--read-timeout`
set the connection timeouts. `download` accepts several
links and fetches them concurrently with one identity, `--documents-only` narrows what leaves quarantine to PDF
and DjVu and `--any-content` widens it to everything, `--allow-md4-only` accepts a part on its MD4 when no peer
serves the AICH hashes the link's root calls for, `--deadline-hours` and `--max-peers` bound each download, and
`share` takes `--upload-slots`.

## Design

The package is layered so that each module owns one concern:

| Layer          | Modules                                                     | Responsibility                              |
|----------------|-------------------------------------------------------------|---------------------------------------------|
| Facade         | `client.py`, `cli.py`, `settings.py`                        | One object, one command line, every setting |
| Transfers      | `download.py`, `partfile.py`, `share.py`                    | Scheduling, verification, resume, serving   |
| Sessions       | `server.py`, `peer.py`, `kad/node.py`                       | The three protocol conversations            |
| Transport      | `transport.py`, `obfuscation.py`                            | Framed TCP packets, limits, timeouts, RC4   |
| Wire format    | `wire.py`, `tags.py`, `search.py`, `links.py`, `hashing.py` | Bytes in and out, parsed with hard limits   |
| Bootstrap data | `servermet.py`, `kad/contacts.py`, `fetch.py`               | `server.met`, `nodes.dat`, HTTPS download   |
| Defences       | `security.py`, `identity.py`                                | Names, paths, addresses, content, identity  |

A download keeps a part file in `<download_dir>/.incoming` with its progress in JSON next to it, both readable by
the owner only. Workers dial the sources the server and Kad report, request up to three 180 KiB blocks at a time,
accept raw or zlib-compressed blocks, and verify every 9,728,000-byte part against the hashset. A peer that queues
the client is asked again after 21.7 minutes at the earliest, as eMule's `FILEREASKTIME`, because eMule bans clients
that ask more often than every ten minutes. A peer that ends an upload session, as aMule and eMule do after 10 MiB or
an hour while others wait, has queued the client again and is asked again the same way, never counted as a failure.
Without AICH, a part that fails its hash convicts its peer only when that peer alone delivered it, and a part with
several contributors is fetched again from one peer, so the next failure is unambiguous. With AICH, the failed 180 KiB
blocks are known, so only they are fetched again and only the peer that wrote one of them is banned.

## Defences

Everything that arrives from the network is untrusted, and these are the defences:

- Every length field is checked against a limit before anything is read or allocated, and zlib data is inflated
  with an output cap, so a malformed or hostile packet costs a bounded amount of memory and time.
- Addresses from servers, Kad and peers are dialled only when they are global unicast IPv4 addresses outside the IP
  filter, so a hostile server cannot make the client probe the local network. The filter is the `ipfilter.dat` that
  eMule Security keeps of ranges known to host fake servers and poisoned files, about 176,000 ranges, downloaded over
  HTTPS on entering the client, cached in the state directory and fetched again after `ip_filter_refresh`, seven
  days by default. A failed download keeps the old copy, and without one the client runs unfiltered after a warning.
  `ip_filter` names a local file instead, and an empty `ip_filter_url` turns the filter off.
- Search answers are checked against the query and against each other: a result whose name lacks a word of the
  query is dropped, since only a fake server or a poisoned index sends one, and a file reported by more servers and
  Kad ranks first, shown as `seen_on`, because a single fake server cannot plant it in independent indexes. A hash
  that answers give different sizes for is listed once per size, so a fake server echoing it with another size adds
  a row that ranks below the size the honest indexes agree on and cannot hide the file.
- File names from the network are sanitised to one path component and every write is proved to stay inside its
  directory, which defeats `../` and absolute-path tricks.
- Downloaded data stays in quarantine until its eD2k hash and every part hash match, and a part that matched is never
  written again: a peer sending data for it is banned. The content is then classified by its magic bytes, and
  `download.content_policy` decides what leaves quarantine. `safe`, the default, releases files of any kind except
  programs, scripts and Office documents that may carry macros. `documents` (`--documents-only`) releases only PDF and
  DjVu. `any` (`--any-content`) releases everything and only records the verdict. Under the first two, a PDF is refused
  when its dictionaries carry `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA` or `/SubmitForm`
  (hex-escaped names included), outside its strings, comments and stream bodies. An object header inside a stream body
  ends it for the scan, because a reader reaches an object by its xref offset wherever it lies. Under the first two, a
  file is also refused when the name it is released under has an extension on the list of [file types Outlook
  blocks](https://support.microsoft.com/en-us/office/blocked-attachments-in-outlook-434752e1-02d3-4e90-9124-8b81e49a8519),
  such as `.bat`, `.chm`, `.py` or `.hta`, or a macro-enabled Office extension such as `.docm`, and when it is named
  `.pdf` without a PDF header in its first kilobyte. A ZIP is refused when it holds an Office macro project or a Java
  manifest. Other archives pass `safe` as notable, because their other members are not inspected. Released files are
  mode 0600, never executable.
- A link that carries an AICH root (`h=`) adds a SHA-1 check of every 180 KiB block, which defeats a part forged to
  collide with the original MD4. Complete sources that announce AICH are asked for the block hashes of each part,
  and an answer counts only when it folds back to the root of the link, so a peer cannot forge it. Under
  `download.aich = 'require'`, the default, a part is not fetched until its block hashes are proven, and a file no
  complete AICH source serves runs into the deadline with the waiting parts named. `prefer` (`--allow-md4-only`)
  fetches every part and accepts one on its MD4 alone, with a warning, when no peer served its hashes. A part whose
  blocks all match the root but whose MD4 fails ends the download, because the link names two different files. Only
  the root of a link is used, never one a peer or a server reports.
- Sharing is off until `share()` is called. Peers name files only by hash, symbolic links are not shared, and a
  file changed or deleted on disk after hashing is withdrawn instead of served.
- Kad answers are accepted only from a node the client is waiting on for that opcode, which drops forged answers.
- `server.met` and `nodes.dat` are fetched over HTTPS only, and a redirect to plain HTTP is refused.

The content inspection catches the common carriers of PDF malware, but it does not parse compressed object
streams, so it reports `/ObjStm` as notable. A file that passes is still untrusted data: open it in an up-to-date
viewer with JavaScript disabled.

## Tests

| Command                        | What runs                                                             |
|--------------------------------|-----------------------------------------------------------------------|
| `uv run pytest`                | Unit tests in memory, including RHash vectors for the eD2k hash       |
| `uv run pytest -m integration` | Real clients over loopback, a fake eD2k server and a fake Kad network |
| `uv run pytest -m network`     | The live eD2k and Kad networks, on a host that may reach them         |

The integration suite downloads every size class of the part rules, raw and compressed blocks, obfuscated and plain,
from three seeders at once, through a seeder that vanishes, past a seeder that corrupts data, through an upload
queue, after an interruption, from a seeder that comes online late, through a server callback, and through server
and Kad search with sources from each network. The pre-commit gate runs ruff, ty, mypy, pyrefly and the unit tests:

```bash
uv run pre-commit run --all-files
```

## Limitations

The client is a Low ID client when its TCP port is not reachable from the internet. It can then download only from
High ID peers and be reached only through a server callback, because Kad buddies and NAT traversal are not
implemented. It does not serve AICH hashes to other peers, and does not implement source exchange, server UDP
queries, Kad publishing, Secure User Identification or the obfuscated server connection. Some servers accept a
login and still ignore searches. On 2026-11-06 eMule Sunrise did so while ed2k-rust answered.

## License and lawful use

ed2k-client is free software under the GNU General Public License, version 3 or later, whose text is in
[LICENSE](LICENSE). The client downloads and shares whatever the network offers. Before you fetch or share a file,
make sure you have the right to do so where you live.
