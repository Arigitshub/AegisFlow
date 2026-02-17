# Installation

AegisFlow is available on PyPI and supports Python 3.9+.

## Basic Installation

To install the core package (CLI, regex detection, process wrapper):

```bash
pip install aegisflow
```

## ML-Powered Detection

If you want to use the HuggingFace transformer models for high-accuracy prompt injection detection, install the `ml` extra:

```bash
pip install "aegisflow[ml]"
```

This will pull in `torch` and `transformers`. Warning: The first time you run a scan, it will download the ~500MB model.

## Development Installation

To contribute to AegisFlow or run the test suite:

```bash
git clone https://github.com/Arigitshub/AegisFlow.git
cd AegisFlow
pip install -e ".[dev]"
```

## Verification

Verify the installation by running the help command:

```bash
aegis --help
```
