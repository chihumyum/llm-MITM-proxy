# LLMProxy Python Client

This directory contains the **Python client** for interacting with the
LLMProxy backend.\
It also includes example scripts for generating text, retrieving stored
content, uploading data, and inspecting model metadata.


------------------------------------------------------------------------

## Installation

From inside the `py/` directory:

``` bash
pip install .
```

This installs the `llmproxy` package into your environment.

------------------------------------------------------------------------

## Configuration & API Key

Before running any examples, create a `.env` file containing:

    LLMPROXY_API_KEY="your-api-key-here"
    LLMPROXY_ENDPOINT="https://a061igc186.execute-api.us-east-1.amazonaws.com/prod"


Place the `.env` file either:

-   in `py/examples/`
-   in your project folder

------------------------------------------------------------------------

## Core Operations

The Python client exposes five high-level functions:

### `generate(model, system, query, …)`

Send a generation request.

### `retrieve(document_id, …)`

Retrieve stored content

### `upload_text(text, …)`

Upload raw text to the backend.

### `upload_file(path, …)`

Upload a PDF for processing/storage.

Check `llmproxy/main.py` for full argument lists and defaults.

------------------------------------------------------------------------

## Example Usage

### Basic text generation

``` python
from llmproxy import LLMProxy

client = LLMProxy()

response = client.generate(
    model="4o-mini",
    system="Answer humorously.",
    query="Who are the Jumbos?",
    lastk=5
)

print(response)
```

------------------------------------------------------------------------

## Run an Example Script

``` bash
cd py/examples
python generate.py
```
