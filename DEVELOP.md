
The project utilizes [uv] https://docs.astral.sh/uv/.

# Running

You can run any of the application scripts using:

```
$ uv run <sript-name>
```

For example:

```
$ uv run trust-purl <name>
```

or

```
$ uv run trust-products <base purl>
```

# Linting

The linting tool in use in the CI environment (Github Actions) is `ruff`. You can run it in the development environment with:

```
$ uvx ruff check
```

and 

```
$ uvx ruff format --check
```

If that check fails, you can format the files with:

```
$ uvx ruff format
```

# Tests

```
$ uv run pytest
```