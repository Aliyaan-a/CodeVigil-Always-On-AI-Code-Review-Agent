# Getting Started with CodeVigil

## Step 1: Download & Setup (2 minutes)

After downloading the `CodeVigil-Always-On-AI-Code-Review-Agent` folder:

```bash
# Navigate into the project
cd CodeVigil-Always-On-AI-Code-Review-Agent

# (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate    # Linux/Mac
# venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# For full development setup (testing, linting, etc.)
pip install -e ".[dev]"
```

### Minimum Requirements
- **Python 3.10+** (check with `python3 --version`)
- **PyYAML** and **Click** (installed via requirements.txt)
- No API keys needed for the core tool — LLM features are optional

---

## Step 2: Try It Instantly

### Quick Demo (no setup needed beyond Python + PyYAML + Click)
```bash
python3 demo.py
```
This reviews a built-in sample file full of bugs, security issues, and anti-patterns. You'll see a color-coded terminal report + an HTML report file.

### Review Your Own Code
```bash
# Single file
python3 demo.py path/to/your/file.py

# Entire directory
python3 demo.py --scan path/to/your/project/
```

---

## Step 3: Use the CLI

After installing (`pip install -e .`), you get the `codevigil` command:

```bash
# Review a single file (console output)
codevigil review myfile.py

# Review with Markdown output (great for PR comments)
codevigil review myfile.py --format md

# Save an HTML report
codevigil review myfile.py --format html --output report.html

# Only show warnings and above (hide info-level noise)
codevigil review myfile.py --severity warning

# Generate SARIF for GitHub Actions
codevigil review myfile.py --format sarif --output results.sarif

# Review Git diff (what changed since last commit)
codevigil diff HEAD~1

# Review only staged changes (pre-commit hook)
codevigil diff --staged

# Scan entire project
codevigil scan ./src
```

---

## Step 4: Use It in Python Code

```python
from src.agents.orchestrator import Orchestrator
from src.schemas.config import CodeVigilConfig

# Create config (LLM disabled by default)
config = CodeVigilConfig()
orch = Orchestrator(config)

# Review a file
report = orch.review_file("mycode.py")

# Check results
print(f"Grade: {report.score.grade}")
print(f"Score: {report.score.overall}/100")
print(f"Issues: {report.total_findings}")

for fa in report.files_analyzed:
    for finding in fa.findings:
        print(f"  [{finding.severity.value}] {finding.rule_id}: {finding.title}")
```

---

## Step 5: Run the Tests

```bash
# All 73 tests
python3 run_tests.py

# With pytest (if installed)
pytest tests/ -v
```

---

## Step 6: Upload to GitHub

```bash
cd CodeVigil-Always-On-AI-Code-Review-Agent

# Initialize Git
git init
git add .
git commit -m "feat: initial CodeVigil release — AI code review agent"

# Create a repo on GitHub (github.com/new), then:
git remote add origin https://github.com/Aliyaan-a/CodeVigil-Always-On-AI-Code-Review-Agent.git
git branch -M main
git push -u origin main
```

### Tips for a Great GitHub Repo:
1. **Update the README** — Replace `yourusername` with your actual GitHub username
2. **Add a profile photo** to your GitHub account
3. **Write good commit messages** as you iterate
4. **Enable GitHub Actions** — the CI workflow will auto-run on push
5. **Add topics/tags**: `python`, `code-review`, `static-analysis`, `ai`, `cli`, `security`

---

## Step 7: Enable LLM-Powered Reviews (Optional)

For AI-powered semantic analysis using GPT-4 or Claude:

```bash
# Set your API key
export OPENAI_API_KEY="sk-..."
# OR
export ANTHROPIC_API_KEY="sk-ant-..."

# Install the LLM dependencies
pip install openai
# OR
pip install anthropic
```

Then enable in config:
```yaml
# .codevigil.yaml
analyzers:
  llm:
    enabled: true
    provider: openai    # or "anthropic"
    model: gpt-4        # or "claude-sonnet-4-20250514"
```

---

## What Gets Checked?

| Analyzer | What It Detects | Rules |
|----------|----------------|-------|
| **AST Analyzer** | Mutable defaults, bare excepts, unreachable code, shadowed builtins, unused vars, star imports | AST-001 to AST-013 |
| **Security Scanner** | Hardcoded secrets, SQL/command injection, eval/exec, pickle, weak crypto, SSL bypass | SEC-001 to SEC-029 |
| **Complexity Engine** | Cyclomatic/cognitive complexity, function length, nesting depth, maintainability index | CX-001 to CX-006 |
| **Style Checker** | Naming conventions, docstrings, type hints, line length, import order, TODOs | STY-001 to STY-040 |
| **Performance Plugin** | String concat in loops, list comprehension opportunities, membership on lists | PERF-001 to PERF-006 |
| **Docstring Enforcer** | Missing parameter docs, return docs, exception docs | DOC-001 to DOC-003 |
| **LLM Reasoner** | Logical bugs, architecture issues, concurrency problems, API design | LLM-001+ |

---

## Project Structure Cheat Sheet

```
CodeVigil-Always-On-AI-Code-Review-Agent/
├── demo.py                 ← START HERE — run this first
├── run_tests.py            ← Run all 73 tests
├── src/
│   ├── cli/main.py         ← CLI entry point (codevigil command)
│   ├── agents/
│   │   └── orchestrator.py ← Main pipeline controller
│   ├── analyzers/          ← All analysis engines
│   ├── plugins/            ← Plugin system + built-in plugins
│   ├── reporters/          ← Output formatters (JSON/MD/HTML/SARIF)
│   └── schemas/            ← Data models & config
├── configs/                ← Preset configs (default/strict/minimal)
├── examples/               ← Usage examples & sample code
└── tests/                  ← Unit + integration tests
```
