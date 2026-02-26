from pathlib import Path


def generate_project_context(
    root_dir: str,
    output_file: str,
    exclude_dirs: set[str],
    exclude_files: set[str],
    extensions: list[str] | None = None,
) -> None:
    """
    Concatenates project files with prioritization for architectural context.
    """
    if extensions is None:
        extensions = [".py", ".md", ".txt", ".yaml", ".json", ".toml", ".html", ".js"]
    root = Path(root_dir)
    # Define priority files for early token ingestion
    priority_files = ["README.md", "pyproject.toml", "agents.md", "todo.md"]
    priority_dirs = ["docs"]

    # Track processed files to avoid duplicates
    processed_files: set[Path] = set()

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"# Project Context: {root.name}\n\n")

        # 1. Directory Tree
        f.write("## Directory Structure\n```text\n")
        for path in sorted(root.rglob("*")):
            if any(part in exclude_dirs for part in path.parts):
                continue
            depth = len(path.relative_to(root).parts)
            spacer = "    " * (depth - 1)
            f.write(f"{spacer}{path.name}/\n" if path.is_dir() else f"{spacer}{path.name}\n")
            print(f"{spacer}{path.name}/" if path.is_dir() else f"{spacer}{path.name}")
        f.write("```\n\n---\n\n")

        def write_file_content(path: Path):
            if path in processed_files or not path.is_file():
                return
            if path.suffix not in extensions or path.name in exclude_files:
                return
            if any(part in exclude_dirs for part in path.parts):
                return

            relative_path = path.relative_to(root)
            f.write(f"### File: {relative_path}\n")
            f.write(f"```{path.suffix.lstrip('.')}\n")
            try:
                f.write(path.read_text(encoding="utf-8"))
            except Exception as e:
                f.write(f"// Error reading file: {e}")
            f.write("\n```\n\n")
            processed_files.add(path)

        # 2. Priority Phase: README, TOML, Agents
        f.write("## High-Level Architecture & Docs\n")
        for name in priority_files:
            target = root / name
            if target.exists():
                write_file_content(target)

        # 3. Priority Phase: Docs folder
        for p_dir in priority_dirs:
            dir_path = root / p_dir
            if dir_path.exists():
                for path in sorted(dir_path.rglob("*")):
                    write_file_content(path)

        # 4. General Phase: Everything else
        f.write("## Source Code and Configuration\n")
        for path in sorted(root.rglob("*")):
            write_file_content(path)


if __name__ == "__main__":
    output_file = "project_full_context.md"
    generate_project_context(
        root_dir=".",
        output_file=output_file,
        exclude_dirs={"__pycache__", ".git", ".venv", ".uv", "node_modules", ".ruff_cache", "data", "secrets"},
        exclude_files={".env", "uv.lock", ".gitignore", "generate_project_context.py", output_file},
    )
