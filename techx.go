package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/goflags"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/rix4uni/techx/banner"
)

// Result structure for JSON output
type Result struct {
	Host  string   `json:"host"`
	Count int      `json:"count"`
	Tech  []string `json:"tech"`
}

// Attempts to probe the domain to determine which protocol (http or https) to use
func probeDomain(domain string, timeout int, userAgent string, client *http.Client) (string, string) {
	// Attempt HTTPS first
	url := "https://" + domain
	if isReachable(url, timeout, userAgent, client) {
		return url, "https://"
	}

	// Fallback to HTTP
	url = "http://" + domain
	if isReachable(url, timeout, userAgent, client) {
		return url, "http://"
	}

	// Return empty values if both attempts fail
	return "", ""
}

// Checks if a URL is reachable
func isReachable(url string, timeout int, userAgent string, client *http.Client) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 100 && resp.StatusCode < 599 // Consider status codes 100-599 as reachable
}

type Options struct {
	Output         string
	JSONOutput     bool
	CSVOutput      bool
	Threads        int
	UserAgent      string
	SendToDiscord  bool
	DiscordId      string
	ProviderConfig string
	MatchTech      string
	Verbose        bool
	Version        bool
	Silent         bool
	Delay          time.Duration
	Retries        int
	Timeout        int
	RetriesDelay   int
	Insecure       bool
}

// Define the flags
func ParseOptions() *Options {
	// Get the user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error fetching home directory: %v\n", err)
		os.Exit(1)
	}

	// Define the default config path using the expanded home directory
	defaultConfigPath := filepath.Join(homeDir, ".config", "notify", "provider-config.yaml")
	defaultTechXConfigPath := filepath.Join(homeDir, ".config", "techx", "technologies.txt")

	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`A high-performance technology detection tool built with Go, leveraging the projectdiscovery wappalyzergo library to identify web technologies and frameworks.`)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "File to save output (default is stdout)"),
		flagSet.BoolVar(&options.JSONOutput, "json", false, "Output in JSON format"),
		flagSet.BoolVar(&options.CSVOutput, "csv", false, "Output in CSV format"),
	)

	createGroup(flagSet, "rate-limit", "RATE-LIMIT",
		flagSet.IntVarP(&options.Threads, "threads", "t", 50, "Number of threads to use"),
	)

	createGroup(flagSet, "configurations", "Configurations",
		flagSet.StringVarP(&options.UserAgent, "user-agent", "H", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36", "Custom User-Agent header for HTTP requests"),
		flagSet.BoolVar(&options.SendToDiscord, "discord", false, "Send Matched tech to Discord"),
		flagSet.StringVar(&options.DiscordId, "id", "alivesubdomain", "Discord id to send the notification"),
		flagSet.StringVarP(&options.ProviderConfig, "provider-config", "pc", defaultConfigPath, "provider config path"),
	)

	createGroup(flagSet, "matchers", "Matchers",
		flagSet.StringVarP(&options.MatchTech, "match-tech", "mt", defaultTechXConfigPath, "Send matched tech output to Discord (comma-separated, file)"),
	)

	createGroup(flagSet, "debug", "Debug",
		flagSet.BoolVar(&options.Verbose, "verbose", false, "Enable verbose output for debugging purposes"),
		flagSet.BoolVar(&options.Version, "version", false, "Print the version of the tool and exit"),
		flagSet.BoolVar(&options.Silent, "silent", false, "silent mode"),
	)

	createGroup(flagSet, "optimizations", "OPTIMIZATIONS",
		flagSet.IntVar(&options.Retries, "retries", 1, "Number of retry attempts for failed HTTP requests"),
		flagSet.IntVar(&options.Timeout, "timeout", 15, "HTTP request timeout in seconds"),
		flagSet.IntVarP(&options.RetriesDelay, "retriesDelay", "rd", 0, "Delay in seconds between retry attempts"),
		flagSet.BoolVarP(&options.Insecure, "insecure", "i", false, "Disable TLS verification"),
		flagSet.DurationVar(&options.Delay, "delay", -1, "duration between each http request (eg: 200ms, 1s)"),
	)

	_ = flagSet.Parse()

	return options
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}

// Config structure to hold the YAML data
type Config struct {
	Discord []DiscordConfig `yaml:"discord"`
}

// DiscordConfig holds individual Discord settings
type DiscordConfig struct {
	ID                string `yaml:"id"`
	DiscordChannel    string `yaml:"discord_channel"`
	DiscordUsername   string `yaml:"discord_username"`
	DiscordFormat     string `yaml:"discord_format"`
	DiscordWebhookURL string `yaml:"discord_webhook_url"`
}

// Function to load the configuration from a YAML file
func loadConfig(configFile string) (*Config, error) {
	config := &Config{}

	// Read the YAML file
	file, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	// Unmarshal the YAML data into the Config struct
	err = yaml.Unmarshal(file, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// Function to find the Discord configuration by ID
func getDiscordConfigByID(config *Config, id string) *DiscordConfig {
	for _, discordConfig := range config.Discord {
		if discordConfig.ID == id {
			return &discordConfig
		}
	}
	return nil
}

// Function to send a message to Discord
func discord(webhookURL, messageContent string) {
	// Create a map to hold the JSON payload
	payload := map[string]string{
		"content": messageContent,
	}

	// Marshal the payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error marshaling payload:", err)
		return
	}

	// Create a new POST request with the payload
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set the Content-Type header to application/json
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	options := ParseOptions()
	// Check if the request was successful
	if options.Verbose {
		if resp.StatusCode == http.StatusNoContent {
			fmt.Println("Matched tech Message sent to Discord successfully!")
		} else {
			fmt.Printf("Failed to send message. Status code: %d\n", resp.StatusCode)
		}
	}
}

// ensureTechnologiesFile checks if the technologies.txt file exists in the config directory
// If it doesn't exist, downloads it from the GitHub repository
func ensureTechnologiesFile(techFilePath string, verbose bool) error {
	// Check if file already exists
	if _, err := os.Stat(techFilePath); err == nil {
		if verbose {
			fmt.Printf("Technologies file already exists at: %s\n", techFilePath)
		}
		return nil
	}

	if verbose {
		fmt.Printf("Technologies file not found. Downloading to: %s\n", techFilePath)
	}

	// Create the directory if it doesn't exist
	techDir := filepath.Dir(techFilePath)
	if err := os.MkdirAll(techDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Download the file from GitHub
	url := "https://raw.githubusercontent.com/rix4uni/techx/main/technologies.txt"

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download technologies file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download technologies file: HTTP %d", resp.StatusCode)
	}

	// Create the file
	file, err := os.Create(techFilePath)
	if err != nil {
		return fmt.Errorf("failed to create technologies file: %v", err)
	}
	defer file.Close()

	// Write the downloaded content to the file
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write technologies file: %v", err)
	}

	if verbose {
		fmt.Printf("Successfully downloaded technologies file to: %s\n", techFilePath)
	}

	return nil
}

func readMatchesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var matches []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := strings.TrimSpace(scanner.Text())
		if match != "" {
			matches = append(matches, match)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return matches, nil
}

func parseMatches(matchesStr string) []string {
	var matches []string
	for _, match := range strings.Split(matchesStr, ",") {
		trimmed := strings.TrimSpace(match)
		if trimmed != "" {
			matches = append(matches, trimmed)
		}
	}
	return matches
}

func main() {
	options := ParseOptions()

	// Print version and exit if -version flag is provided
	if options.Version {
		banner.PrintBanner()
		banner.PrintVersion()
		return
	}

	if !options.Silent {
		banner.PrintBanner()
	}

	// Check if -discord flag is provided without -pc
	if options.SendToDiscord && options.ProviderConfig == "" {
		fmt.Println("Error: -pc flag is required when using -discord.")
		os.Exit(1)
	}
	var config *Config
	var err error // Declare err here
	// Only load the configuration if -discord and -pc is provided
	if options.SendToDiscord && options.ProviderConfig != "" {
		config, err = loadConfig(options.ProviderConfig)
		if err != nil {
			fmt.Println("Error loading config:", err)
			os.Exit(1)
		}
	}

	// Ensure technologies.txt file exists (download if needed)
	if strings.HasSuffix(options.MatchTech, ".txt") {
		if err := ensureTechnologiesFile(options.MatchTech, options.Verbose); err != nil {
			fmt.Printf("Error ensuring technologies file: %v\n", err)
			os.Exit(1)
		}
	}

	// Determine the match criteria
	var matches []string
	if strings.HasSuffix(options.MatchTech, ".txt") {
		// Treat as a file path
		var err error
		matches, err = readMatchesFromFile(options.MatchTech)
		if err != nil {
			fmt.Printf("Error reading match file: %v\n", err)
			return
		}
	} else {
		// Treat as a comma-separated list or single value
		matches = parseMatches(options.MatchTech)
	}

	// Initialize Wappalyzer client
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		if options.Verbose {
			fmt.Printf("Error initializing Wappalyzer client: %v\n", err)
		}
		os.Exit(1)
	}

	// Initialize Discord config only if SendToDiscord is enabled
	var discordConfig *DiscordConfig
	if options.SendToDiscord {
		// Use a hardcoded ID to find the corresponding webhook URL
		hardcodedID := options.DiscordId // replace with your desired hardcoded ID
		discordConfig = getDiscordConfigByID(config, hardcodedID)
		if discordConfig == nil {
			fmt.Printf("Discord config with ID '%s' not found in %s\n", hardcodedID, options.ProviderConfig)
			os.Exit(1)
		}
	}
	// Initialize HTTP client with improved TLS and transport settings
	tr := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		Proxy:                 http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	if options.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(options.Timeout) * time.Second,
	}

	// Initialize writers
	var writers []io.Writer
	if options.Output != "" {
		file, err := os.Create(options.Output)
		if err != nil {
			if options.Verbose {
				fmt.Printf("Failed to create file %s: %v\n", options.Output, err)
			}
			os.Exit(1)
		}
		defer file.Close()
		writers = append(writers, file)
	}
	// Always append stdout (terminal) to writers
	writers = append(writers, os.Stdout)

	// Use MultiWriter to write to multiple destinations
	writer := io.MultiWriter(writers...)

	// Create a CSV writer if the -csv flag is used
	var csvWriter *csv.Writer
	if options.CSVOutput {
		csvWriter = csv.NewWriter(writer)
		// Write CSV headers
		if err := csvWriter.Write([]string{"host", "count", "tech"}); err != nil {
			if options.Verbose {
				fmt.Printf("Error writing header to CSV: %v\n", err)
			}
			os.Exit(1)
		}
	}

	// Create a channel for URLs and a wait group
	urlChan := make(chan string)
	var wg sync.WaitGroup
	sem := make(chan struct{}, options.Threads) // Semaphore to limit the number of concurrent threads
	var mu sync.Mutex                           // Mutex for synchronized output

	// Worker function to process URLs
	worker := func() {
		for url := range urlChan {
			if options.Verbose {
				mu.Lock()
				fmt.Printf("Processing URL: %s\n", url)
				mu.Unlock()
			}

			var resp *http.Response
			var fetchErr error

			// Retry logic
			for i := 0; i < options.Retries; i++ {
				// Set up HTTP request with timeout
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(options.Timeout)*time.Second)
				defer cancel()

				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					if options.Verbose {
						mu.Lock()
						fmt.Printf("Failed to create request for %s: %v\n", url, err)
						mu.Unlock()
					}
					continue
				}

				// Set the custom User-Agent header
				req.Header.Set("User-Agent", options.UserAgent)

				resp, fetchErr = httpClient.Do(req)
				if fetchErr == nil {
					break // Exit retry loop if request is successful
				}

				if options.Verbose {
					mu.Lock()
					fmt.Printf("Retrying %s (%d/%d): %v\n", url, i+1, options.Retries, fetchErr)
					mu.Unlock()
				}

				if options.RetriesDelay > 0 {
					time.Sleep(time.Duration(options.RetriesDelay) * time.Second) // Delay before retry
				}
			}

			if fetchErr != nil {
				if options.Verbose {
					mu.Lock()
					fmt.Printf("Failed to fetch %s after %d retries: %v\n", url, options.Retries, fetchErr)
					mu.Unlock()
				}
				continue
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close() // Close the body after reading

			// Fingerprint the URL
			fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)

			// Matches
			var matched []string

			// Convert fingerprints to a slice of strings and sort
			var tech []string
			for name := range fingerprints {
				tech = append(tech, name)

				// match tech with case-sensitive
				lowerName := strings.ToLower(name)
				for _, match := range matches {
					if strings.Contains(lowerName, strings.ToLower(match)) {
						matched = append(matched, name)
					}
				}

			}
			sort.Strings(tech) // Sort the technologies alphabetically
			count := len(tech) // Count the number of detected technologies

			if options.Verbose {
				mu.Lock()
				fmt.Printf("Detected technologies for %s: [%s]\n", url, strings.Join(tech, ", "))
				mu.Unlock()
			}

			// Output the result based on the flags
			if options.JSONOutput {
				result := Result{
					Host:  url,
					Count: count,
					Tech:  tech,
				}
				jsonData, _ := json.MarshalIndent(result, "", "  ")
				mu.Lock()
				fmt.Fprintln(writer, string(jsonData))
				mu.Unlock()
			} else if options.CSVOutput {
				// Write CSV output
				record := []string{url, fmt.Sprintf("%d", count), strings.Join(tech, ", ")}
				mu.Lock()
				if err := csvWriter.Write(record); err != nil {
					fmt.Printf("Error writing record to CSV: %v\n", err)
					os.Exit(1)
				}
				csvWriter.Flush()
				mu.Unlock()
			} else {
				mu.Lock()
				fmt.Fprintf(writer, "URL: %s\nCount: %d\nTechnologies: [%s]\n\n", url, count, strings.Join(tech, ", "))
				mu.Unlock()
			}
			// Consolidate matched technologies into a single message
			if len(matched) > 0 {
				// Create a single message with all matched technologies
				matchedTechs := strings.Join(matched, ", ")
				messageContent := fmt.Sprintf("```URL: %s\nMatched Tech: %v```\n", url, matchedTechs)
				// Send consolidated message to Discord
				if options.SendToDiscord && config != nil && discordConfig != nil {
					discord(discordConfig.DiscordWebhookURL, messageContent)
				}
			}

			// Delay between requests if delay is set
			if options.Delay > 0 {
				time.Sleep(options.Delay)
			}

			// Release the semaphore
			<-sem
		}
	}

	// Start worker goroutines
	for i := 0; i < options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker()
		}()
	}

	// Reading URLs from stdin and sending them to the channel
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := scanner.Text()

		// Probe logic: Check if the domain needs probing
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			// Probe the domain to determine the correct scheme
			probedURL, scheme := probeDomain(url, options.Timeout, options.UserAgent, httpClient)

			// If probing fails (i.e., both https:// and http:// fail), skip this URL
			if probedURL == "" {
				if options.Verbose {
					mu.Lock()
					fmt.Printf("Skipping %s: both http:// and https:// failed\n", url)
					mu.Unlock()
				}
				continue // Move to the next URL
			}

			// Update the URL to the probed URL
			url = probedURL

			// Print the successfully probed scheme
			if options.Verbose {
				mu.Lock()
				fmt.Printf("Probed Scheme: %s\n", scheme)
				mu.Unlock()
			}
		}

		sem <- struct{}{} // Acquire a semaphore slot
		urlChan <- url
	}

	// Close the URL channel and wait for all workers to finish
	close(urlChan)
	wg.Wait()

	// Handle scanner errors
	if err := scanner.Err(); err != nil {
		if options.Verbose {
			mu.Lock()
			fmt.Printf("Error reading from stdin: %v\n", err)
			mu.Unlock()
		}
		os.Exit(1)
	}
}
