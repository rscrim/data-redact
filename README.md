# PII and SPII Detector and Redactor

This Go program is designed to detect and redact PII (Personally Identifiable Information) and SPII (Sensitive Personally Identifiable Information) data from files. It uses regular expressions to search for certain patterns that may indicate the presence of PII or SPII data.

## Requirements

- Go 1.16 or higher

## Installation

1. Clone or download the repository
2. Open the command prompt and navigate to the directory containing the program
3. Run `go build` to build the executable

## Usage

The program can be run using the command line interface. The following options are available:

- `-mode`: Specify the DLP mode: tokenize, detokenize, or redact (default: tokenize)
- `-file`: Specify the file or directory path (required)
- `-output`: Specify the output directory path (optional)
- `-token`: Specify the token used for tokenization (default: "[TOKEN]")

To run the program, enter the following command in the terminal:

```bash
./pii-detector -mode=<mode> -file=<file> -output=<output> -token=<token>
```

### Modes

- `tokenize`: Tokenize the input using the specified token
- `detokenize`: Detokenize the input using the specified token
- `redact`: Redact PII and SPII information from the input

### Examples

Tokenize a file:

```bash
./pii-detector -mode=tokenize -file=/path/to/file.txt -token=*** > /path/to/output.txt
```

Detokenize a file:

```bash
./pii-detector -mode=detokenize -file=/path/to/file.txt -token=*** > /path/to/output.txt
```

Redact PII and SPII information from a file:

```bash
./pii-detector -mode=redact -file=/path/to/file.txt > /path/to/output.txt
```

Process all files in a directory:

```bash
./pii-detector -mode=redact -file=/path/to/directory/
```

## License

This program is released under the MIT License.
