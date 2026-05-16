from dataclasses import dataclass, field
import re


@dataclass(slots=True)
class AddedLine:
    number: int
    content: str


@dataclass(slots=True)
class DiffFile:
    path: str
    additions: list[AddedLine] = field(default_factory=list)
    scan_lines: list[AddedLine] = field(default_factory=list)


HUNK_RE = re.compile(r"@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@")


def _clean_path(raw: str) -> str:
    path = raw.strip()
    if path.startswith("a/") or path.startswith("b/"):
        path = path[2:]
    if path == "/dev/null":
        return "unknown"
    return path.strip('"') or "unknown"


def parse_unified_diff(diff_text: str) -> list[DiffFile]:
    files: list[DiffFile] = []
    current: DiffFile | None = None
    new_line_number = 0
    saw_hunk = False

    def ensure_current() -> DiffFile:
        nonlocal current
        if current is None:
            current = DiffFile(path="unknown")
            files.append(current)
        return current

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff --git "):
            parts = raw_line.split()
            path = _clean_path(parts[-1]) if len(parts) >= 4 else "unknown"
            current = DiffFile(path=path)
            files.append(current)
            new_line_number = 0
            saw_hunk = False
            continue

        if raw_line.startswith("+++ "):
            current_file = ensure_current()
            current_file.path = _clean_path(raw_line[4:])
            continue

        if raw_line.startswith("@@"):
            match = HUNK_RE.search(raw_line)
            if match:
                new_line_number = int(match.group(1))
                saw_hunk = True
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_file = ensure_current()
            number = new_line_number if saw_hunk else len(current_file.additions) + 1
            added_line = AddedLine(number=number, content=raw_line[1:])
            current_file.additions.append(added_line)
            current_file.scan_lines.append(added_line)
            if saw_hunk:
                new_line_number += 1
            continue

        if raw_line.startswith("-") and not raw_line.startswith("---"):
            continue

        if current is not None and saw_hunk:
            content = raw_line[1:] if raw_line.startswith(" ") else raw_line
            current.scan_lines.append(AddedLine(number=new_line_number, content=content))
            new_line_number += 1

    return [file for file in files if file.additions]


def added_code(diff_text: str) -> str:
    lines: list[str] = []
    for file in parse_unified_diff(diff_text):
        lines.extend(line.content for line in file.additions)
    return "\n".join(lines)
