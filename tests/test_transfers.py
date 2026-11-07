"""Transfers between clients over loopback in many conditions.

Every test runs real clients in one process: sizes from one block to three parts, raw and compressed blocks,
obfuscation, several seeders at once, a seeder that disappears, a seeder that corrupts data, upload queues,
interruption and resume, a seeder that comes online late, and the quarantine refusing unsafe content.
"""

import asyncio
import json
import logging
from contextlib import AsyncExitStack
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from ed2k_client import (
    Client,
    ContentPolicy,
    DownloadError,
    FileLink,
    SecurityError,
    Source,
    StateInUseError,
    hash_file,
)
from ed2k_client.client import QUARANTINE_DIR
from ed2k_client.constants import BLOCK_SIZE, PART_SIZE
from ed2k_client.partfile import PartState
from ed2k_client.security import DocumentKind
from ed2k_client.settings import ShareSettings
from ed2k_client.sources import SourceOrigin, client_id_from_host
from tests.helpers import (
    DJVU_HEADER,
    FAST,
    LOOPBACK,
    ServeSpy,
    compressible,
    corrupting,
    failing_after,
    free_port,
    incompressible,
    make_config,
    source_of,
    write_file,
)

if TYPE_CHECKING:
    from pathlib import Path

    from ed2k_client import (
        DownloadProgress,
    )

pytestmark = pytest.mark.integration

LEECHER = 'leecher'
SEEDER = 'seeder'
HOSTILE = 'hostile'
SOURCE_DIR = 'src'
BATCH_FILE = 'setup.bat'
DOWNLOADS = 'downloads'
BOOK = 'book.pdf'
TRAP = 'trap.pdf'
PART_GLOB = '*.part'
METADATA_GLOB = '*.part.json'
BANNING = 'Banning'
DEADLINE = 'deadline'
SHORT = replace(FAST, deadline=6.0)


def source_file(root: Path, name: str, data: bytes) -> Path:
    """Write a file the seeders will share."""
    return write_file(root / SOURCE_DIR / name, data)


def download_dir(root: Path) -> Path:
    """Return the leecher's download directory."""
    return (root / LEECHER / DOWNLOADS).resolve()


def quarantine(root: Path) -> Path:
    """Return the leecher's quarantine directory."""
    return download_dir(root) / QUARANTINE_DIR


def link_for(path: Path, *, name: str | None = None) -> FileLink:
    """Build the ed2k link of a local file."""
    hashes = hash_file(path)
    return FileLink(name=name or path.name, size=hashes.size, file_hash=hashes.file_hash)


async def seed(
    stack: AsyncExitStack, root: Path, name: str, payload: Path, **overrides: object
) -> tuple[Client, ServeSpy]:
    """Start a client that shares ``payload`` and count what it serves."""
    seeder = await stack.enter_async_context(Client(make_config(root, name, **overrides)))
    await seeder.share(payload)
    spy = ServeSpy()
    spy.install(seeder.library)
    return seeder, spy


async def leech(stack: AsyncExitStack, root: Path, **overrides: object) -> Client:
    """Start the downloading client."""
    return await stack.enter_async_context(Client(make_config(root, LEECHER, **overrides)))


SIZES = [
    pytest.param(100, id='tiny'),
    pytest.param(BLOCK_SIZE - 1, id='block-minus-1'),
    pytest.param(BLOCK_SIZE, id='one-block'),
    pytest.param(BLOCK_SIZE + 1, id='block-plus-1'),
    pytest.param(PART_SIZE - 1, id='part-minus-1'),
    pytest.param(PART_SIZE, id='exact-part'),
    pytest.param(PART_SIZE + 1, id='part-plus-1'),
    pytest.param(2 * PART_SIZE + 12_345, id='three-parts'),
]


@pytest.mark.parametrize('size', SIZES)
async def test_every_size_class_downloads_intact(tmp_path: Path, size: int) -> None:
    """Every size class of the eD2k part rules arrives byte for byte and leaves quarantine."""
    payload = source_file(tmp_path, BOOK, compressible(size))
    async with AsyncExitStack() as stack:
        seeder, spy = await seed(stack, tmp_path, SEEDER, payload)
        leecher = await leech(stack, tmp_path)
        result = await leecher.download(link_for(payload), extra_sources=[source_of(seeder)])

    assert result.path == download_dir(tmp_path) / BOOK
    assert result.path.read_bytes() == payload.read_bytes()
    assert result.path.stat().st_mode & 0o777 == 0o600
    assert spy.served >= size
    assert not any(quarantine(tmp_path).glob(PART_GLOB))


@pytest.mark.parametrize('obfuscate', [False, True], ids=['plain', 'obfuscated'])
async def test_incompressible_blocks_travel_raw(tmp_path: Path, obfuscate: bool) -> None:
    """Random data is sent as raw SENDINGPART blocks, inside obfuscation or not."""
    payload = source_file(tmp_path, BOOK, incompressible(PART_SIZE + 77_777))
    async with AsyncExitStack() as stack:
        seeder, _ = await seed(stack, tmp_path, SEEDER, payload)
        leecher = await leech(stack, tmp_path)
        result = await leecher.download(link_for(payload), extra_sources=[source_of(seeder, obfuscate=obfuscate)])

    assert result.path.read_bytes() == payload.read_bytes()


async def test_djvu_and_non_document_content(tmp_path: Path) -> None:
    """A DjVu is released as a document, a binary file only under the ANY content policy."""
    djvu = source_file(tmp_path, 'atlas.djvu', compressible(300_000, header=DJVU_HEADER))
    binary = source_file(tmp_path, 'data.bin', incompressible(50_000, header=b'\x00\x01'))
    async with AsyncExitStack() as stack:
        seeder = await stack.enter_async_context(Client(make_config(tmp_path, SEEDER)))
        await seeder.share(tmp_path / SOURCE_DIR)
        leecher = await leech(stack, tmp_path, download=SHORT)
        result = await leecher.download(link_for(djvu), extra_sources=[source_of(seeder)])
        with pytest.raises(SecurityError, match='content is other'):
            await leecher.download(link_for(binary), extra_sources=[source_of(seeder)])
        anything = replace(SHORT, content_policy=ContentPolicy.ANY)
        released = await leecher.download(link_for(binary), extra_sources=[source_of(seeder)], settings=anything)

    assert result.inspection.kind == DocumentKind.DJVU
    assert released.path.read_bytes() == binary.read_bytes()


async def test_safe_policy_releases_data_and_keeps_a_script(tmp_path: Path) -> None:
    """Under the SAFE policy a data file leaves quarantine and a script stays in it."""
    binary = source_file(tmp_path, 'data.bin', incompressible(50_000, header=b'\x00\x01'))
    script = source_file(tmp_path, 'install.sh', b'#!/bin/sh\necho hostile\n' * 200)
    safe = replace(SHORT, content_policy=ContentPolicy.SAFE)
    async with AsyncExitStack() as stack:
        seeder = await stack.enter_async_context(Client(make_config(tmp_path, SEEDER)))
        await seeder.share(tmp_path / SOURCE_DIR)
        leecher = await leech(stack, tmp_path, download=safe)
        released = await leecher.download(link_for(binary), extra_sources=[source_of(seeder)])
        with pytest.raises(SecurityError, match='dangerous content'):
            await leecher.download(link_for(script), extra_sources=[source_of(seeder)])

    assert released.path.read_bytes() == binary.read_bytes()
    assert not (tmp_path / LEECHER / 'downloads' / 'install.sh').exists()


async def test_safe_policy_keeps_a_script_known_only_by_its_name(tmp_path: Path) -> None:
    """Under the SAFE policy a Windows batch file stays in quarantine, judged by the name it would be released as.

    The quarantined data is named by its hash, so only the final name tells the content check that it runs.

    :param tmp_path: the directory of the clients' files.
    :type tmp_path: Path
    """
    script = source_file(tmp_path, BATCH_FILE, b'@echo off\r\npowershell -enc AAAA\r\n' * 200)
    safe = replace(SHORT, content_policy=ContentPolicy.SAFE)
    async with AsyncExitStack() as stack:
        seeder, _ = await seed(stack, tmp_path, SEEDER, script)
        leecher = await leech(stack, tmp_path, download=safe)
        with pytest.raises(SecurityError, match=r'\.bat'):
            await leecher.download(link_for(script), extra_sources=[source_of(seeder)])

    assert not (download_dir(tmp_path) / BATCH_FILE).exists()


async def test_three_seeders_share_the_work(tmp_path: Path) -> None:
    """With three sources the blocks of one file come from more than one peer at the same time."""
    payload = source_file(tmp_path, BOOK, incompressible(3 * PART_SIZE))
    async with AsyncExitStack() as stack:
        seeders = [await seed(stack, tmp_path, f'{SEEDER}{index}', payload) for index in range(3)]
        leecher = await leech(stack, tmp_path)
        sources = [source_of(seeder) for seeder, _ in seeders]
        result = await leecher.download(link_for(payload), extra_sources=sources)

    served = [spy.served for _, spy in seeders]
    assert result.path.read_bytes() == payload.read_bytes()
    assert sum(1 for amount in served if amount > 0) >= 2
    assert sum(served) >= payload.stat().st_size


async def test_seeder_that_vanishes_is_replaced(tmp_path: Path) -> None:
    """A seeder whose file disappears mid-transfer drops out, and another seeder finishes the file."""
    payload = source_file(tmp_path, BOOK, incompressible(2 * PART_SIZE))
    async with AsyncExitStack() as stack:
        flaky, flaky_spy = await seed(stack, tmp_path, 'flaky', payload)
        flaky_spy.hook = failing_after(PART_SIZE // 2)
        steady, steady_spy = await seed(stack, tmp_path, 'steady', payload)
        leecher = await leech(stack, tmp_path)
        result = await leecher.download(link_for(payload), extra_sources=[source_of(flaky), source_of(steady)])

    assert result.path.read_bytes() == payload.read_bytes()
    assert steady_spy.served > 0


async def test_corrupting_seeder_is_outvoted(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Parts spoiled by a hostile seeder fail their hash and are fetched again until the file is right."""
    caplog.set_level(logging.INFO)
    payload = source_file(tmp_path, BOOK, incompressible(2 * PART_SIZE))
    async with AsyncExitStack() as stack:
        hostile, hostile_spy = await seed(stack, tmp_path, HOSTILE, payload)
        hostile_spy.hook = corrupting
        honest, _ = await seed(stack, tmp_path, 'honest', payload)
        leecher = await leech(stack, tmp_path)
        result = await leecher.download(link_for(payload), extra_sources=[source_of(hostile), source_of(honest)])

    assert result.path.read_bytes() == payload.read_bytes()
    assert hostile_spy.served > 0
    assert any('failed its hash' in message or BANNING in message for message in caplog.messages)


async def test_only_corrupting_seeder_fails_the_download(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A single hostile source is banned after its first part, and nothing leaves quarantine."""
    caplog.set_level(logging.INFO)
    payload = source_file(tmp_path, BOOK, incompressible(PART_SIZE + 10))
    async with AsyncExitStack() as stack:
        hostile, spy = await seed(stack, tmp_path, HOSTILE, payload)
        spy.hook = corrupting
        leecher = await leech(stack, tmp_path, download=SHORT)
        with pytest.raises(DownloadError, match=DEADLINE):
            await leecher.download(link_for(payload), extra_sources=[source_of(hostile)])

    assert any(BANNING in message for message in caplog.messages)
    assert not (download_dir(tmp_path) / BOOK).exists()


async def test_upload_queue_serves_the_second_leecher_later(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A seeder with one slot queues the second leecher and serves it when the slot frees."""
    caplog.set_level(logging.INFO)
    payload = source_file(tmp_path, BOOK, incompressible(PART_SIZE // 2))
    async with AsyncExitStack() as stack:
        seeder, _ = await seed(stack, tmp_path, SEEDER, payload, share=ShareSettings(upload_slots=1))
        first = await stack.enter_async_context(Client(make_config(tmp_path, 'first')))
        second = await stack.enter_async_context(Client(make_config(tmp_path, 'second')))
        link = link_for(payload)
        results = await asyncio.gather(
            first.download(link, extra_sources=[source_of(seeder)]),
            second.download(link, extra_sources=[source_of(seeder)]),
        )

    assert all(result.path.read_bytes() == payload.read_bytes() for result in results)
    assert any('Queued by' in message for message in caplog.messages)


async def test_interrupted_download_resumes_with_verified_parts(tmp_path: Path) -> None:
    """A download cancelled after its first verified part resumes in a new client without fetching that part."""
    payload = source_file(tmp_path, BOOK, incompressible(3 * PART_SIZE))
    link = link_for(payload)
    first_part = asyncio.Event()

    def on_progress(progress: DownloadProgress) -> None:
        if progress.verified_bytes >= PART_SIZE:
            first_part.set()

    async with AsyncExitStack() as stack:
        seeder, spy = await seed(stack, tmp_path, SEEDER, payload)
        async with Client(make_config(tmp_path, LEECHER, download=replace(FAST, max_peers=1))) as leecher:
            task = asyncio.create_task(leecher.download(link, extra_sources=[source_of(seeder)], progress=on_progress))
            await asyncio.wait_for(first_part.wait(), 30)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        metadata = next(quarantine(tmp_path).glob(METADATA_GLOB))
        verified_before = len(PartState(**json.loads(metadata.read_text())).verified_parts)
        served_before = spy.served

        async with Client(make_config(tmp_path, LEECHER)) as resumed:
            result = await resumed.download(link, extra_sources=[source_of(seeder)])

    assert verified_before >= 1
    assert result.path.read_bytes() == payload.read_bytes()
    assert spy.served - served_before <= payload.stat().st_size - verified_before * PART_SIZE + 6 * BLOCK_SIZE


async def test_seeder_coming_online_late_is_retried(tmp_path: Path) -> None:
    """A source that refuses connections at first is asked again and used once it is up."""
    payload = source_file(tmp_path, BOOK, compressible(400_000))
    port = free_port()
    late = Source(client_id=client_id_from_host(LOOPBACK), port=port, origin=SourceOrigin.LINK)
    async with Client(make_config(tmp_path, LEECHER)) as leecher:
        download = asyncio.create_task(leecher.download(link_for(payload), extra_sources=[late]))
        await asyncio.sleep(1.5)
        async with Client(make_config(tmp_path, SEEDER, tcp_port=port)) as seeder:
            await seeder.share(payload)
            result = await download

    assert result.path.read_bytes() == payload.read_bytes()


async def test_no_source_ends_at_the_deadline(tmp_path: Path) -> None:
    """Without any source the download gives up at its deadline and keeps the part file for later."""
    payload = source_file(tmp_path, BOOK, compressible(10_000))
    async with Client(make_config(tmp_path, LEECHER, download=replace(SHORT, deadline=2.0))) as leecher:
        with pytest.raises(DownloadError, match=DEADLINE):
            await leecher.download(link_for(payload))

    assert any(quarantine(tmp_path).glob(METADATA_GLOB))


async def test_pdf_with_javascript_stays_in_quarantine(tmp_path: Path) -> None:
    """A verified PDF that carries /JavaScript is refused and kept in quarantine."""
    script = b'%PDF-1.7\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>'
    payload = source_file(tmp_path, TRAP, script + compressible(50_000)[len(script) :])
    async with AsyncExitStack() as stack:
        seeder, _ = await seed(stack, tmp_path, SEEDER, payload)
        leecher = await leech(stack, tmp_path)
        with pytest.raises(SecurityError, match='JavaScript'):
            await leecher.download(link_for(payload), extra_sources=[source_of(seeder)])

    assert len(list(quarantine(tmp_path).glob(PART_GLOB))) == 1
    assert not (download_dir(tmp_path) / TRAP).exists()


async def test_executable_named_pdf_is_refused(tmp_path: Path) -> None:
    """A Windows executable published under a .pdf name never leaves quarantine."""
    payload = source_file(tmp_path, BOOK, b'MZ' + bytes(4096))
    async with AsyncExitStack() as stack:
        seeder, _ = await seed(stack, tmp_path, SEEDER, payload)
        leecher = await leech(stack, tmp_path)
        with pytest.raises(SecurityError, match='Windows executable'):
            await leecher.download(link_for(payload), extra_sources=[source_of(seeder)])


async def test_hostile_file_name_cannot_escape_download_dir(tmp_path: Path) -> None:
    """A link whose name climbs out of the download directory is saved inside it under a cleaned name."""
    payload = source_file(tmp_path, BOOK, compressible(10_000))
    async with AsyncExitStack() as stack:
        seeder, _ = await seed(stack, tmp_path, SEEDER, payload)
        leecher = await leech(stack, tmp_path)
        link = link_for(payload, name='../../evil/.bashrc.pdf')
        result = await leecher.download(link, extra_sources=[source_of(seeder)])

    assert result.path.parent == download_dir(tmp_path)
    assert not (tmp_path / 'evil').exists()


async def test_second_client_on_same_state_dir_is_refused(tmp_path: Path) -> None:
    """Two clients cannot share one state directory, because they would share one user hash."""
    config = make_config(tmp_path, LEECHER)
    async with Client(config):
        with pytest.raises(StateInUseError):
            async with Client(config):
                pass


async def test_private_source_is_refused_by_default(tmp_path: Path) -> None:
    """Without the test switch a loopback source is dropped, so a hostile server cannot aim the client inward."""
    async with Client(make_config(tmp_path, LEECHER, allow_private_peers=False)) as leecher:
        assert not leecher.policy.permits(LOOPBACK, 4662)
