"""Verify files from the caf.generator module with corruption detection."""

import os
import hashlib
import struct
from binascii import hexlify
from typing import Optional, Any
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table
from rich.rule import Rule

from caf.constants import BLOCK_SIZE, HEADER_SIZE, ROOT_PARENT_HASH
from caf.content import ContentStream
from caf.utils import file_path_to_hash


BUFFER_READ_SIZE = BLOCK_SIZE


@dataclass
class HeaderInfo:
    """Parsed header information from a CAF file."""

    parent_hash: bytes
    master_seed: bytes
    file_length: int
    header_checksum: bytes
    reserved: bytes


@dataclass
class CorruptionRegion:
    """Information about a corrupted region in a file."""

    offset: int
    size: int
    pattern: str
    details: str


class FileVerifier(object):
    """Verify and analyze corruption in CAF files."""

    ROOTS_DIR = os.path.join('.metadata', 'roots')

    def __init__(self, rootdir: str, analysis_chunk_size: int = 4096) -> None:
        self._rootdir = rootdir
        self._verification_succeeded = True
        self._analysis_chunk_size = analysis_chunk_size
        self._corruption_reports: list[dict[str, Any]] = []
        self._console = Console()
        self._err_console = Console(stderr=True)

    def verify_files(self) -> bool:
        """Verify all files in the directory."""
        self._verification_succeeded = True
        self._corruption_reports = []
        referenced = set()

        roots_dir = os.path.join(self._rootdir, self.ROOTS_DIR)
        if not os.path.isdir(roots_dir):
            self._err_console.print(
                f"[red bold]ERROR:[/] {self._rootdir} is not a valid CAF "
                f"store (missing {self.ROOTS_DIR} directory)"
            )
            return False

        known_roots = os.listdir(roots_dir)
        files_validated = 0

        for root, _, filenames in os.walk(self._rootdir):
            if '.metadata' in root:
                # We validate the metadata directory separately.
                continue
            for filename in filenames:
                full_path = os.path.join(root, filename)
                parent_path = self._validate_and_analyze_file(full_path)
                files_validated += 1
                if parent_path:
                    referenced.add(parent_path)
                    if not os.path.isfile(parent_path):
                        self._err_console.print(
                            f"[red bold]CORRUPTION:[/] Parent hash not found: "
                            f"{parent_path}"
                        )
                        self._verification_succeeded = False

        self._verify_referenced_files(referenced, known_roots)
        self._verify_known_roots(known_roots)
        self._print_corruption_summary()
        return self._verification_succeeded

    def _validate_and_analyze_file(self, full_path: str) -> Optional[str]:
        """Validate a single file and analyze corruption if found."""
        actual_size = os.path.getsize(full_path)
        with open(full_path, 'rb') as f:
            header = f.read(HEADER_SIZE)

            # Validate header
            header_valid, header_info = self._validate_header(header)
            if not header_valid or header_info is None:
                self._err_console.print(
                    f"[red bold]CORRUPTION:[/] Header corrupted in "
                    f"{full_path} - cannot proceed with validation"
                )
                self._verification_succeeded = False
                return None

            # Check file size
            if actual_size != header_info.file_length:
                self._err_console.print(
                    f"[red bold]CORRUPTION:[/] File size mismatch in "
                    f"{full_path}: expected {header_info.file_length}, "
                    f"got {actual_size}"
                )
                self._verification_succeeded = False

            # Validate BLAKE2b hash
            expected_hash = file_path_to_hash(full_path)
            blake2b = hashlib.blake2b(digest_size=20)
            blake2b.update(header)
            while chunk := f.read(BUFFER_READ_SIZE):
                blake2b.update(chunk)
            actual_hash = blake2b.hexdigest()

        if actual_hash != expected_hash:
            # File is corrupted, perform detailed analysis
            self._err_console.print(
                f'[red bold]CORRUPTION:[/] Invalid checksum for file '
                f'"{full_path}": actual blake2b {actual_hash}'
            )
            self._verification_succeeded = False

            # Perform corruption analysis
            corrupted_regions = self._analyze_corruption(
                full_path, header_info, actual_size
            )

            # Generate corruption report
            self._generate_corruption_report(
                full_path,
                expected_hash,
                actual_hash,
                header_info,
                corrupted_regions,
                actual_size,
            )

        # Return parent file path
        if header_info.parent_hash == ROOT_PARENT_HASH:
            return None
        hex_parent = hexlify(header_info.parent_hash).decode('ascii')
        return os.path.join(
            self._rootdir,
            hex_parent[:2],
            hex_parent[2:4],
            hex_parent[4:6],
            hex_parent[6:8],
            hex_parent[8:],
        )

    def _validate_header(
        self, header: bytes
    ) -> tuple[bool, Optional[HeaderInfo]]:
        """Validate header integrity and parse header information."""
        if len(header) < HEADER_SIZE:
            return False, None

        stored_checksum = header[44:52]
        calculated_checksum = hashlib.sha3_256(header[:44]).digest()[:8]

        if stored_checksum != calculated_checksum:
            return False, None

        # Parse header
        header_info = HeaderInfo(
            parent_hash=header[0:20],
            master_seed=header[20:36],
            file_length=struct.unpack('>Q', header[36:44])[0],
            header_checksum=header[44:52],
            reserved=header[52:60],
        )

        return True, header_info

    def _analyze_corruption(
        self, file_path: str, header_info: HeaderInfo, actual_file_size: int
    ) -> list[CorruptionRegion]:
        """Analyze corruption patterns in the file in constant memory."""
        corrupted_regions: list[CorruptionRegion] = []

        expected_file_size = header_info.file_length
        compare_end = min(actual_file_size, expected_file_size)
        bytes_to_compare = max(0, compare_end - HEADER_SIZE)

        # ContentStream uses fixed block sizes internally, so content is
        # deterministic regardless of read() call pattern.
        expected_stream = ContentStream(header_info.master_seed)
        offset = HEADER_SIZE

        with open(file_path, 'rb') as f:
            f.seek(HEADER_SIZE)
            remaining = bytes_to_compare
            while remaining > 0:
                chunk_size = min(self._analysis_chunk_size, remaining)
                actual_chunk = f.read(chunk_size)
                if not actual_chunk:
                    break

                expected_chunk = expected_stream.read(len(actual_chunk))

                if actual_chunk != expected_chunk:
                    corruption_info = self._analyze_corruption_pattern(
                        actual_chunk, expected_chunk
                    )
                    region = CorruptionRegion(
                        offset=offset,
                        size=len(actual_chunk),
                        pattern=corruption_info['pattern'],
                        details=corruption_info['details'],
                    )
                    self._append_or_merge_corruption_region(
                        corrupted_regions, region
                    )

                offset += len(actual_chunk)
                remaining -= len(actual_chunk)

        if actual_file_size < expected_file_size:
            missing_bytes = expected_file_size - actual_file_size
            self._append_or_merge_corruption_region(
                corrupted_regions,
                CorruptionRegion(
                    offset=actual_file_size,
                    size=missing_bytes,
                    pattern='truncated',
                    details=f'Missing {missing_bytes:,} bytes at end of file',
                ),
            )
        elif actual_file_size > expected_file_size:
            extra_bytes = actual_file_size - expected_file_size
            self._append_or_merge_corruption_region(
                corrupted_regions,
                CorruptionRegion(
                    offset=expected_file_size,
                    size=extra_bytes,
                    pattern='extra-bytes',
                    details=f'Unexpected {extra_bytes:,} extra bytes',
                ),
            )

        return corrupted_regions

    def _append_or_merge_corruption_region(
        self, regions: list[CorruptionRegion], region: CorruptionRegion
    ) -> None:
        """Merge contiguous regions when pattern/details match."""
        if not regions:
            regions.append(region)
            return

        last = regions[-1]
        is_contiguous = last.offset + last.size == region.offset
        if (
            is_contiguous
            and last.pattern == region.pattern
            and last.details == region.details
        ):
            last.size += region.size
            return

        regions.append(region)

    def _analyze_corruption_pattern(
        self, actual: bytes, expected: bytes
    ) -> dict[str, str]:
        """Analyze the pattern of corruption in a chunk."""
        if all(b == 0 for b in actual):
            return {'pattern': 'zero-filled', 'details': 'All bytes are 0x00'}

        if len(set(actual)) == 1:
            return {
                'pattern': 'repeated-byte',
                'details': f'All bytes are 0x{actual[0]:02x}',
            }

        # Check for partial corruption
        min_len = min(len(actual), len(expected))
        diff_positions = [
            i for i in range(min_len) if actual[i] != expected[i]
        ]

        # Add positions for size differences
        if len(actual) != len(expected):
            diff_positions.extend(
                range(min_len, max(len(actual), len(expected)))
            )
        corruption_rate = len(diff_positions) / len(actual)

        if corruption_rate < 0.1:
            return {
                'pattern': 'sparse',
                'details': f'{len(diff_positions)} bytes corrupted',
            }

        # Check if corruption aligns with common boundaries
        if offset := self._check_alignment(diff_positions):
            return {
                'pattern': 'aligned',
                'details': f'Corruption aligned to {offset}-byte boundaries',
            }

        return {
            'pattern': 'random',
            'details': f'{corruption_rate:.1%} corruption rate',
        }

    def _check_alignment(self, positions: list[int]) -> Optional[int]:
        """Check if corrupted positions align to common boundaries."""
        common_boundaries = [512, 1024, 4096, 8192]
        for boundary in common_boundaries:
            if all(pos % boundary == 0 for pos in positions[:5]):
                return boundary
        return None

    def _generate_corruption_report(
        self,
        file_path: str,
        expected_hash: str,
        actual_hash: str,
        header_info: HeaderInfo,
        corrupted_regions: list[CorruptionRegion],
        actual_file_size: int,
    ) -> None:
        """Generate a detailed corruption report."""
        total_corrupted_bytes = sum(
            region.size for region in corrupted_regions
        )
        expected_file_size = header_info.file_length
        analysis_file_size = max(actual_file_size, expected_file_size)
        corruption_percentage = (
            (total_corrupted_bytes / analysis_file_size) * 100
            if analysis_file_size > 0
            else 0.0
        )

        # Distinguish path mismatch (content valid) vs actual corruption
        if (
            total_corrupted_bytes == 0
            and actual_file_size == expected_file_size
        ):
            corruption_type = "path_mismatch"
        else:
            corruption_type = "content"

        report = {
            'file': file_path,
            'expected_blake2b': expected_hash,
            'actual_blake2b': actual_hash,
            'file_size': actual_file_size,
            'expected_file_size': expected_file_size,
            'analysis_file_size': analysis_file_size,
            'header_valid': True,
            'master_seed': hexlify(header_info.master_seed).decode('ascii'),
            'total_corrupted_bytes': total_corrupted_bytes,
            'corruption_percentage': corruption_percentage,
            'corrupted_regions': corrupted_regions,
            'analysis_chunk_size': self._analysis_chunk_size,
            'corruption_type': corruption_type,
        }

        self._corruption_reports.append(report)

    def _print_corruption_summary(self) -> None:
        """Print summary of all corruption found."""
        if not self._corruption_reports:
            return

        self._console.print()
        self._console.print(Rule("Error Analysis", style="red"))

        for report in self._corruption_reports:
            self._console.print()
            self._console.print(f"[bold]File:[/] {report['file']}")

            if report['corruption_type'] == 'path_mismatch':
                # Path mismatch: content is valid but stored at wrong path
                self._console.print(
                    "[bold]Status:[/] [yellow]PATH MISMATCH[/] (content valid)"
                )

                table = Table(
                    show_header=False, box=None, padding=(0, 2, 0, 0)
                )
                table.add_column("Label", style="dim")
                table.add_column("Value")
                table.add_row("File Size", f"{report['file_size']:,} bytes")
                table.add_row(
                    "Path indicates", f"[cyan]{report['expected_blake2b']}[/]"
                )
                table.add_row(
                    "Actual checksum", f"[cyan]{report['actual_blake2b']}[/]"
                )
                self._console.print(table)

                self._console.print()
                self._console.print(
                    "[dim]The file content is valid but stored at an "
                    "incorrect path.[/]"
                )
            else:
                # Actual content corruption
                self._console.print(
                    "[bold]Status:[/] [red bold]CONTENT CORRUPTED[/]"
                )

                table = Table(
                    show_header=False, box=None, padding=(0, 2, 0, 0)
                )
                table.add_column("Label", style="dim")
                table.add_column("Value")
                table.add_row("Actual Size", f"{report['file_size']:,} bytes")
                table.add_row(
                    "Header Size",
                    f"{report['expected_file_size']:,} bytes",
                )
                table.add_row(
                    "Expected BLAKE2b",
                    f"[cyan]{report['expected_blake2b']}[/]",
                )
                table.add_row(
                    "Actual BLAKE2b", f"[cyan]{report['actual_blake2b']}[/]"
                )
                self._console.print(table)

                self._console.print()
                header_status = (
                    "[green]PASSED[/]"
                    if report['header_valid']
                    else "[red]FAILED[/]"
                )
                self._console.print(
                    f"[dim]Header Validation:[/] {header_status}"
                )
                self._console.print(
                    f"[dim]Master Seed:[/] [cyan]{report['master_seed']}[/]"
                )

                self._console.print()
                self._console.print("[bold]Corruption Analysis[/]")
                corrupted = report['total_corrupted_bytes']
                pct = report['corruption_percentage']
                size = report['analysis_file_size']
                self._console.print(f"  [dim]Analysis size:[/] {size:,}")
                self._console.print(
                    f"  [dim]Bytes corrupted:[/] [red]{corrupted:,}[/] "
                    f"({pct:.2f}%)"
                )
                self._console.print(
                    f"  [dim]Regions:[/] {len(report['corrupted_regions'])}"
                )

                for i, region in enumerate(report['corrupted_regions'], 1):
                    end_offset = region.offset + region.size
                    self._console.print()
                    self._console.print(
                        f"  [bold]Region {i}:[/] "
                        f"Offset {region.offset:,}–{end_offset:,} "
                        f"({region.size:,} bytes)"
                    )
                    self._console.print(
                        f"    [dim]Pattern:[/] {region.pattern}"
                    )
                    if region.details:
                        self._console.print(
                            f"    [dim]Details:[/] {region.details}"
                        )

                # Generate visualization
                self._console.print()
                self._print_corruption_visualization(
                    report['analysis_file_size'], report['corrupted_regions']
                )

        self._console.print()

    def _print_corruption_visualization(
        self, file_size: int, regions: list[CorruptionRegion]
    ) -> None:
        """Print a visual representation of corruption."""
        bar_length = 60
        if file_size <= 0:
            return

        # Build list of (is_corrupted, char) for each position
        corrupted = [False] * bar_length

        for region in regions:
            start_pos = int((region.offset / file_size) * bar_length)
            end_pos = int(
                ((region.offset + region.size) / file_size) * bar_length
            )
            for i in range(max(0, start_pos), min(end_pos + 1, bar_length)):
                corrupted[i] = True

        bar = ''.join('X' if is_bad else '=' for is_bad in corrupted)
        self._console.print("[bold]Visualization:[/]")
        self._console.print(f"[{bar}]", markup=False)
        self._console.print(" 0%".ljust(bar_length // 2) + "100%")

    def _verify_referenced_files(
        self, referenced: set[str], known_roots: list[str]
    ) -> None:
        """Verify that all files are referenced by some other file."""
        for root, _, filenames in os.walk(self._rootdir):
            if '.metadata' in root:
                continue
            for filename in filenames:
                full_path = os.path.join(root, filename)
                if (
                    full_path not in referenced
                    and file_path_to_hash(full_path) not in known_roots
                ):
                    self._err_console.print(
                        f"[yellow bold]ORPHAN:[/] File not referenced by "
                        f"any files: {full_path}"
                    )
                    self._verification_succeeded = False

    def _verify_known_roots(self, known_roots: list[str]) -> None:
        """Verify the integrity of root files."""
        verify_hash = hashlib.blake2b(digest_size=20)
        for root in sorted(known_roots):
            verify_hash.update(root.encode('ascii'))
        actual = verify_hash.hexdigest().encode('ascii')
        with open(os.path.join(self._rootdir, '.metadata', 'all'), 'rb') as f:
            expected = f.read()
        if actual != expected:
            self._err_console.print(
                "[red bold]CORRUPTION:[/] Root hash is not valid, "
                "roots are missing."
            )
            self._verification_succeeded = False
