/*
DESCRIPTION:
This is a command-line tool for Data Loss Prevention (DLP). It offers three modes: tokenize, detokenize and redact, that can be used to mask sensitive information in a given file or directory. The tool is designed to handle text files and supports the detection and redaction of Personally Identifiable Information (PII) and Sensitive Personally Identifiable Information (SPII) data.

AUTHOR: @rscrim
Date: 21/03/2023
Version: 1.0
*/
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var piiRegex = regexp.MustCompile(`(?i)(\b(?:[a-z]+\s)?(?:SSN|social security number|driver's license|passport|credit card|debit card|bank account)\b|\b(?:[a-z]+\s)?(?:first|last|middle|maiden|previous|current)\s?(?:name|initials)\b|\b(?:[a-z]+\s)?(?:phone|fax|email|address|city|state|zip|postal)\s?(?:number|code)\b)`)

var spiiRegex = regexp.MustCompile(`(?i)(\b(?:[a-z]+\s)?(?:medical|health|insurance|benefits|prescription|treatment)\s?(?:information|record)\b|\b(?:[a-z]+\s)?(?:ethnicity|race|sexual|gender|religion)\s?(?:identity|orientation)\b)`)

func main() {
	// Define command line options
	modePtr := flag.String("mode", "tokenize", "Specify the DLP mode: tokenize, detokenize or redact")
	filePtr := flag.String("file", "", "Specify the file or directory path")
	outputPtr := flag.String("output", "", "Specify the output directory path")
	tokenPtr := flag.String("token", "[TOKEN]", "Specify the token used for tokenization")
	flag.Parse()

	// Check if file or directory is specified
	if *filePtr == "" {
		fmt.Println("Error: File or directory path is required")
		os.Exit(1)
	}

	// Check if file or directory exists
	fileInfo, err := os.Stat(*filePtr)
	if err != nil {
		fmt.Println("Error: Could not access file or directory")
		os.Exit(1)
	}

	// Check if directory is a known top-level folder or system directory
	if isIllegalDirectory(fileInfo) {
		fmt.Println("Error: Illegal directory selected")
		os.Exit(1)
	}

	// Process file or directory
	var files []string
	if fileInfo.IsDir() {
		files, err = listFiles(*filePtr)
		if err != nil {
			fmt.Println("Error: Could not access directory contents")
			os.Exit(1)
		}
		if len(files) > 20 {
			fmt.Printf("Found %d files in directory. Do you want to process all of them? (y/n): ", len(files))
			var input string
			fmt.Scanln(&input)
			if strings.ToLower(input) != "y" {
				for _, file := range files {
					processFile(file, modePtr, tokenPtr, outputPtr)
				}
				return
			}
		}
		for _, file := range files {
			if !approveFile(file) {
				continue
			}
			processFile(file, modePtr, tokenPtr, outputPtr)
		}
	} else {
		if approveFile(*filePtr) {
			processFile(*filePtr, modePtr, tokenPtr, outputPtr)
		}
	}
}

// Tokenize input using the specified token
func tokenize(input []byte, token string) []byte {
	regex := regexp.MustCompile(`\b(\w+)\b`)
	return regex.ReplaceAllFunc(input, func(match []byte) []byte {
		return []byte(token)
	})
}

// Detokenize input using the specified token
func detokenize(input []byte, token string) []byte {
	regex := regexp.MustCompile(fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(token)))
	return regex.ReplaceAllFunc(input, func(match []byte) []byte {
		return []byte(strings.TrimSpace(string(match)))
	})
}

// Redact PII and SPII information from input
func redact(input []byte) []byte {
	piiRegex := regexp.MustCompile(`(?i)\b(?:[a-z]+\s)?(?:SSN|social security number|driver's license|passport|credit card|debit card|bank account)\b`)
	spiiRegex := regexp.MustCompile(`(?i)\b(?:[a-z]+\s)?(?:medical|health|insurance|benefits|prescription|treatment)\s?(?:information|record)\b`)
	input = piiRegex.ReplaceAll(input, []byte("[redacted]"))
	input = spiiRegex.ReplaceAll(input, []byte("[redacted]"))
	return input
}

// Check if the directory is a known top-level folder or system directory
func isIllegalDirectory(fileInfo os.FileInfo) bool {
	if fileInfo.IsDir() {
		absPath, err := filepath.Abs(fileInfo.Name())
		if err == nil {
			illegalDirs := []string{
				"/etc",
				"/var",
				"C:/Program Files",
				"C:/Program Files (x86)",
				"C:/Windows",
				"C:/Windows/System32",
			}
			for _, dir := range illegalDirs {
				if strings.HasPrefix(absPath, dir) {
					return true
				}
			}
		}
	}
	return false
}

// List all files in the directory
func listFiles(directory string) ([]string, error) {
	var files []string
	fileInfos, err := ioutil.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	for _, fileInfo := range fileInfos {
		if !fileInfo.IsDir() {
			files = append(files, filepath.Join(directory, fileInfo.Name()))
		}
	}
	return files, nil
}

// Prompt the user to approve a file for processing
func approveFile(file string) bool {
	fmt.Printf("Process file %s? (y/n): ", file)
	var input string
	fmt.Scanln(&input)
	return strings.ToLower(input) == "y"
}

// Process a file based on the selected mode
func processFile(file string, modePtr *string, tokenPtr *string, outputPtr *string) {
	// Read input file
	inputFile, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("Error: Could not read input file %s\n", file)
		return
	}

	// Identify PII and SPII in the input
	piiMatches := piiRegex.FindAll(inputFile, -1)
	spiiMatches := spiiRegex.FindAll(inputFile, -1)
	fmt.Printf("Processing %s... Found %d PII matches and %d SPII matches\n", file, len(piiMatches), len(spiiMatches))

	// Perform DLP based on the selected mode
	var output []byte
	switch *modePtr {
	case "tokenize":
		output = tokenize(inputFile, *tokenPtr)
	case "detokenize":
		output = detokenize(inputFile, *tokenPtr)
	case "redact":
		output = redact(inputFile)
	default:
		fmt.Printf("Error: Unknown mode %s\n", *modePtr)
		return
	}

	// Write output file
	var outputFile string
	if *outputPtr != "" {
		if fileInfo, err := os.Stat(*outputPtr); err == nil && fileInfo.IsDir() {
			outputFile = filepath.Join(*outputPtr, fmt.Sprintf("%s_redacted.%s", filepath.Base(file), filepath.Ext(file)))
		}
	}
	if outputFile == "" {
		outputFile = filepath.Join(filepath.Dir(file), fmt.Sprintf("%s_redacted%s", filepath.Base(file[:len(file)-len(filepath.Ext(file))]), filepath.Ext(file)))
	}
	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		fmt.Printf("Error: Could not write output file %s\n", outputFile)
		return
	}

	fmt.Printf("Processed %s, output saved to %s\n", file, outputFile)
}
