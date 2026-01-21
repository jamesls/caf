"""Verify files from the caf.generator module with corruption detection."""

import os
import hashlib
import struct
from binascii import hexlify
from typing import Literal, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table
from rich.rule import Rule

from caf.constants import BLOCK_SIZE, HEADER_SIZE, ROOT_PARENT_HASH
from caf.content import ContentStream
from caf.paths import hash_to_path, parse_hash_from_path


BUFFER_READ_SIZE = BLOCK_SIZE


@dataclass
class HeaderInfo:
    """Parsed header information from a CAF file."""

    parent_hash: bytes
    content_seed: bytes
    file_length: int
    header_checksum: bytes
    reserved: bytes


# Corruption pattern types


@dataclass(frozen=True)
class ZeroFilled:
    """All bytes in the region are 0x00."""

    pass


@dataclass(frozen=True)
class RepeatedByte:
    """All bytes in the region are the same value."""

    byte_value: int


@dataclass(frozen=True)
class Sparse:
    """Less than 10% of bytes are corrupted."""

    corrupted_count: int


@dataclass(frozen=True)
class Aligned:
    """Corruption aligns to common I/O boundaries."""

    boundary: int


@dataclass(frozen=True)
class Random:
    """Unstructured corruption with high corruption rate."""

    corruption_rate: float


@dataclass(frozen=True)
class Truncated:
    """File is shorter than expected."""

    missing_bytes: int


@dataclass(frozen=True)
class ExtraBytes:
    """File has unexpected data beyond expected length."""

    extra_count: int


CorruptionPattern = (
    ZeroFilled
    | RepeatedByte
    | Sparse
    | Aligned
    | Random
    | Truncated
    | ExtraBytes
)


@dataclass
class CorruptionRegion:
    """Information about a corrupted region in a file."""

    offset: int
    size: int
    pattern: CorruptionPattern


@dataclass
class CorruptionReport:
    """Detailed report of corruption found in a single file."""

    file: str
    expected_blake2b: str
    actual_blake2b: str
    file_size: int
    expected_file_size: int
    header_valid: bool
    content_seed: str
    total_corrupted_bytes: int
    corruption_percentage: float
    corrupted_regions: list[CorruptionRegion]
    corruption_type: Literal['content', 'path_mismatch']


@dataclass
class VerificationResult:
    """Result of verifying files in a CAF store."""

    success: bool
    reports: list[CorruptionReport]


class FileVerifier(object):
    """Verify and analyze corruption in CAF files."""

    ROOTS_DIR = os.path.join('.metadata', 'roots')

    def __init__(self, rootdir: str, analysis_chunk_size: int = 4096) -> None:
        self._rootdir = rootdir
        self._verification_succeeded = True
        self._analysis_chunk_size = analysis_chunk_size
        self._corruption_reports: list[CorruptionReport] = []
        self._console = Console()
        self._err_console = Console(stderr=True)

    def verify_files(self) -> VerificationResult:
        """Verify all files in the directory."""
        self._verification_succeeded = True
        self._corruption_reports = []
        referenced: set[str] = set()

        roots_dir = os.path.join(self._rootdir, self.ROOTS_DIR)
        if not os.path.isdir(roots_dir):
            self._err_console.print(
                f"[red bold]ERROR:[/] {self._rootdir} is not a valid CAF "
                f"store (missing {self.ROOTS_DIR} directory)"
            )
            return VerificationResult(success=False, reports=[])

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
        return VerificationResult(
            success=self._verification_succeeded,
            reports=self._corruption_reports,
        )

    def _validate_and_analyze_file(self, full_path: str) -> Optional[str]:
        """Validate a single file and analyze corruption if found."""
        expected_hash = parse_hash_from_path(full_path)
        if not expected_hash:
            self._err_console.print(
                f"[red bold]ERROR:[/] Invalid CAF path layout: {full_path}"
            )
            self._verification_succeeded = False
            return None

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
        return hash_to_path(self._rootdir, hex_parent)

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
            content_seed=header[20:36],
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
        expected_stream = ContentStream(header_info.content_seed)
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
                    pattern = self._analyze_corruption_pattern(
                        actual_chunk, expected_chunk
                    )
                    region = CorruptionRegion(
                        offset=offset,
                        size=len(actual_chunk),
                        pattern=pattern,
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
                    pattern=Truncated(missing_bytes=missing_bytes),
                ),
            )
        elif actual_file_size > expected_file_size:
            extra_bytes = actual_file_size - expected_file_size
            self._append_or_merge_corruption_region(
                corrupted_regions,
                CorruptionRegion(
                    offset=expected_file_size,
                    size=extra_bytes,
                    pattern=ExtraBytes(extra_count=extra_bytes),
                ),
            )

        return corrupted_regions

    def _append_or_merge_corruption_region(
        self, regions: list[CorruptionRegion], region: CorruptionRegion
    ) -> None:
        """Merge contiguous regions when pattern matches."""
        if not regions:
            regions.append(region)
            return

        last = regions[-1]
        is_contiguous = last.offset + last.size == region.offset
        if is_contiguous and last.pattern == region.pattern:
            last.size += region.size
            return

        regions.append(region)

    def _analyze_corruption_pattern(
        self, actual: bytes, expected: bytes
    ) -> CorruptionPattern:
        """Analyze the pattern of corruption in a chunk."""
        if all(b == 0 for b in actual):
            return ZeroFilled()

        if len(set(actual)) == 1:
            return RepeatedByte(byte_value=actual[0])

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
            return Sparse(corrupted_count=len(diff_positions))

        # Check if corruption aligns with common boundaries
        if boundary := self._check_alignment(diff_positions):
            return Aligned(boundary=boundary)

        return Random(corruption_rate=corruption_rate)

    def _check_alignment(self, positions: list[int]) -> Optional[int]:
        """Check if corrupted positions align to common boundaries."""
        common_boundaries = [512, 1024, 4096, 8192]
        for boundary in common_boundaries:
            if all(pos % boundary == 0 for pos in positions[:5]):
                return boundary
        return None

    def _format_pattern(self, pattern: CorruptionPattern) -> tuple[str, str]:
        """Return (pattern_name, details) for display."""
        match pattern:
            case ZeroFilled():
                return ('zero-filled', 'All bytes are 0x00')
            case RepeatedByte(byte_value=v):
                return ('repeated-byte', f'All bytes are 0x{v:02x}')
            case Sparse(corrupted_count=n):
                return ('sparse', f'{n} bytes corrupted')
            case Aligned(boundary=b):
                return (
                    'aligned',
                    f'Corruption aligned to {b}-byte boundaries',
                )
            case Random(corruption_rate=r):
                return ('random', f'{r:.1%} corruption rate')
            case Truncated(missing_bytes=n):
                return ('truncated', f'Missing {n:,} bytes at end of file')
            case ExtraBytes(extra_count=n):
                return ('extra-bytes', f'Unexpected {n:,} extra bytes')

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
        corruption_type: Literal['content', 'path_mismatch']
        if (
            total_corrupted_bytes == 0
            and actual_file_size == expected_file_size
        ):
            corruption_type = 'path_mismatch'
        else:
            corruption_type = 'content'

        report = CorruptionReport(
            file=file_path,
            expected_blake2b=expected_hash,
            actual_blake2b=actual_hash,
            file_size=actual_file_size,
            expected_file_size=expected_file_size,
            header_valid=True,
            content_seed=hexlify(header_info.content_seed).decode('ascii'),
            total_corrupted_bytes=total_corrupted_bytes,
            corruption_percentage=corruption_percentage,
            corrupted_regions=corrupted_regions,
            corruption_type=corruption_type,
        )

        self._corruption_reports.append(report)

    def _print_corruption_summary(self) -> None:
        """Print summary of all corruption found."""
        if not self._corruption_reports:
            return

        self._console.print()
        self._console.print(Rule("Error Analysis", style="red"))

        for report in self._corruption_reports:
            self._console.print()
            self._console.print(f"[bold]File:[/] {report.file}")

            if report.corruption_type == 'path_mismatch':
                # Path mismatch: content is valid but stored at wrong path
                self._console.print(
                    "[bold]Status:[/] [yellow]PATH MISMATCH[/] (content valid)"
                )

                table = Table(
                    show_header=False, box=None, padding=(0, 2, 0, 0)
                )
                table.add_column("Label", style="dim")
                table.add_column("Value")
                table.add_row("File Size", f"{report.file_size:,} bytes")
                table.add_row(
                    "Path indicates", f"[cyan]{report.expected_blake2b}[/]"
                )
                table.add_row(
                    "Actual checksum", f"[cyan]{report.actual_blake2b}[/]"
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
                table.add_row("Actual Size", f"{report.file_size:,} bytes")
                table.add_row(
                    "Header Size",
                    f"{report.expected_file_size:,} bytes",
                )
                table.add_row(
                    "Expected BLAKE2b",
                    f"[cyan]{report.expected_blake2b}[/]",
                )
                table.add_row(
                    "Actual BLAKE2b", f"[cyan]{report.actual_blake2b}[/]"
                )
                self._console.print(table)

                self._console.print()
                header_status = (
                    "[green]PASSED[/]"
                    if report.header_valid
                    else "[red]FAILED[/]"
                )
                self._console.print(
                    f"[dim]Header Validation:[/] {header_status}"
                )
                self._console.print(
                    f"[dim]Content Seed:[/] [cyan]{report.content_seed}[/]"
                )

                self._console.print()
                self._console.print("[bold]Corruption Analysis[/]")
                corrupted = report.total_corrupted_bytes
                pct = report.corruption_percentage
                size = max(report.file_size, report.expected_file_size)
                self._console.print(f"  [dim]Analysis size:[/] {size:,}")
                self._console.print(
                    f"  [dim]Bytes corrupted:[/] [red]{corrupted:,}[/] "
                    f"({pct:.2f}%)"
                )
                self._console.print(
                    f"  [dim]Regions:[/] {len(report.corrupted_regions)}"
                )

                for i, region in enumerate(report.corrupted_regions, 1):
                    end_offset = region.offset + region.size
                    self._console.print()
                    self._console.print(
                        f"  [bold]Region {i}:[/] "
                        f"Offset {region.offset:,}–{end_offset:,} "
                        f"({region.size:,} bytes)"
                    )
                    pattern_name, details = self._format_pattern(
                        region.pattern
                    )
                    self._console.print(f"    [dim]Pattern:[/] {pattern_name}")
                    self._console.print(f"    [dim]Details:[/] {details}")

                # Generate visualization
                self._console.print()
                self._print_corruption_visualization(
                    size, report.corrupted_regions
                )

        self._console.print()

    def _print_corruption_visualization(
        self, file_size: int, regions: list[CorruptionRegion]
    ) -> None:
        """Print a visual representation of corruption."""
        bar_length = 60
        if file_size <= 0:
            return

        # Build corruption map
        corrupted = [False] * bar_length
        for region in regions:
            start_pos = int((region.offset / file_size) * bar_length)
            end_pos = int(
                ((region.offset + region.size) / file_size) * bar_length
            )
            for i in range(max(0, start_pos), min(end_pos + 1, bar_length)):
                corrupted[i] = True

        # Unicode characters for visualization
        CLEAN = "━"  # U+2501 box drawing heavy horizontal
        CORRUPT = "█"  # U+2588 full block

        # Build bar with simple block rendering
        bar_parts = []
        for is_bad in corrupted:
            if is_bad:
                bar_parts.append(f"[red]{CORRUPT}[/]")
            else:
                bar_parts.append(f"[dim]{CLEAN}[/]")

        bar = "".join(bar_parts)

        self._console.print("[bold]Visualization:[/]")
        self._console.print(bar)
        self._console.print(f"0%{' ' * (bar_length - 4)}100%")

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
                    and parse_hash_from_path(full_path) not in known_roots
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
