# Changelog

Every notable change to ed2k-client is listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), so a minor release of 0.x may still break the API.

## [Unreleased]

### Added

- A `Client` library that logs in to several eD2k servers at once, joins Kad, searches both networks for files of
  every type and ranks the results by how many servers agree on them.
- Downloads from many peers into a quarantine, with every part checked against its MD4 hash and, when the link
  carries an AICH root, every block checked against it.
- A content policy that releases a finished file only when it carries nothing that runs when it is opened.
- Optional sharing of a chosen directory, off by default.
- The eMule Security IP filter, applied by default.
- The `ed2k-client` command line with `search`, `download`, `share`, `servers` and `hash`, configured by flags or
  a TOML file.
- The package metadata for PyPI under GPL-3.0-or-later.
