## techfinder

A high-performance technology detection tool built with Go, leveraging the projectdiscovery wappalyzergo library to identify web technologies and frameworks.

## 🚀 Features

- **Fast & Efficient**: Multi-threaded processing for high-speed detection
- **Multiple Output Formats**: Plain text, JSON, and CSV support
- **Flexible Input**: Process single URLs or bulk lists via stdin
- **Discord Integration**: Send detection results directly to Discord
- **Customizable**: Configurable timeouts, retries, and rate limiting
- ♻️ **Crash-Safe Resume**: Default-on resume with `resume.cfg`; use `--no-resume` to start fresh

## 📦 Installation

### Using Go Install
```
go install github.com/rix4uni/techfinder@latest
```

### Download Prebuilt Binaries
```
wget https://github.com/rix4uni/techfinder/releases/download/v0.0.6/techfinder-linux-amd64-0.0.6.tgz
tar -xvzf techfinder-linux-amd64-0.0.6.tgz
rm -rf techfinder-linux-amd64-0.0.6.tgz
mv techfinder ~/go/bin/techfinder
```

Or download [binary release](https://github.com/rix4uni/techfinder/releases) for your platform.

### Compile from Source
```
git clone --depth 1 https://github.com/rix4uni/techfinder.git
cd techfinder; go install
```

## 🔧 Usage
```yaml
A high-performance technology detection tool built with Go, leveraging the projectdiscovery wappalyzergo library to identify web technologies and frameworks.

Usage:
  techfinder [flags]

Flags:
OUTPUT:
   -o, -output string  File to save output (default is stdout)
   -json               Output in JSON format
   -csv                Output in CSV format

RATE-LIMIT:
   -t, -threads int  Number of threads to use (default 50)

CONFIGURATIONS:
   -H, -user-agent string        Custom User-Agent header for HTTP requests (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
   -discord                      Send Matched tech to Discord
   -id string                    Discord id to send the notification (default "alivesubdomain")
   -pc, -provider-config string  provider config path (default "/root/.config/notify/provider-config.yaml")

MATCHERS:
   -mt, -match-tech string  Send matched tech output to Discord (comma-separated, file) (default "/root/.config/techfinder/technologies.txt")

DEBUG:
   -verbose  Enable verbose output for debugging purposes
   -version  Print the version of the tool and exit
   -silent   silent mode

OPTIMIZATIONS:
   -retries int            Number of retry attempts for failed HTTP requests (default 1)
   -timeout int            HTTP request timeout in seconds (default 15)
   -rd, -retriesDelay int  Delay in seconds between retry attempts
   -i, -insecure           Disable TLS verification
   -delay value            duration between each http request (eg: 200ms, 1s) (default -1ns)
```

## 📊 Output Examples

Single URL:
```yaml
echo "https://hackerone.com" | techfinder
```

Multiple URLs:
```yaml
cat urls.txt | techfinder
```

# Start fresh without resuming
```yaml
cat urls.txt | techfinder --no-resume
```

## Plain text
```yaml
cat urls.txt | techfinder
URL: https://hackerone.com
Count: 14
Technologies: [Cloudflare, Drupal:10, Fastly, Google Tag Manager, HSTS, MariaDB, Marketo Forms:2, Nginx, Optimizely, PHP, Pantheon, TrustArc, Varnish, YouTube]

URL: https://bugcrowd.com
Count: 16
Technologies: [Bootstrap, Fastly, HSTS, MariaDB, Marketo Forms:2, MySQL, Nginx, OneTrust, PHP, Pantheon, Slick, Varnish, WordPress, Yoast SEO:22.8, jQuery, jQuery UI]

URL: https://www.intigriti.com
Count: 4
Technologies: [CookieYes, DatoCMS, HSTS, Vercel]
```

## JSON format
```yaml
cat urls.txt | techfinder -json
{
  "host": "https://hackerone.com",
  "count": 14,
  "tech": [
    "Cloudflare",
    "Drupal:10",
    "Fastly",
    "Google Tag Manager",
    "HSTS",
    "MariaDB",
    "Marketo Forms:2",
    "Nginx",
    "Optimizely",
    "PHP",
    "Pantheon",
    "TrustArc",
    "Varnish",
    "YouTube"
  ]
}
{
  "host": "https://www.intigriti.com",
  "count": 4,
  "tech": [
    "CookieYes",
    "DatoCMS",
    "HSTS",
    "Vercel"
  ]
}
{
  "host": "https://bugcrowd.com",
  "count": 16,
  "tech": [
    "Bootstrap",
    "Fastly",
    "HSTS",
    "MariaDB",
    "Marketo Forms:2",
    "MySQL",
    "Nginx",
    "OneTrust",
    "PHP",
    "Pantheon",
    "Slick",
    "Varnish",
    "WordPress",
    "Yoast SEO:22.8",
    "jQuery",
    "jQuery UI"
  ]
}
```

## CSV format
```yaml
cat urls.txt | techfinder -csv
host,count,tech
https://bugcrowd.com,16,"Bootstrap, Fastly, HSTS, MariaDB, Marketo Forms:2, MySQL, Nginx, OneTrust, PHP, Pantheon, Slick, Varnish, WordPress, Yoast SEO:22.8, jQuery, jQuery UI"
https://www.intigriti.com,4,"CookieYes, DatoCMS, HSTS, Vercel"
https://hackerone.com,14,"Cloudflare, Drupal:10, Fastly, Google Tag Manager, HSTS, MariaDB, Marketo Forms:2, Nginx, Optimizely, PHP, Pantheon, TrustArc, Varnish, YouTube"
```

## ⚙️ Configuration Flags

### Output Options
| Flag | Description | Default |
|------|-------------|---------|
| `-o, -output` | Save output to file | stdout |
| `-json` | Output in JSON format | false |
| `-csv` | Output in CSV format | false |

### Rate Limiting
| Flag | Description | Default |
|------|-------------|---------|
| `-t, -threads` | Number of concurrent threads | 50 |
| `-delay` | Delay between HTTP requests (e.g., 200ms, 1s) | -1ns |
| `-retries` | Retry attempts for failed requests | 1 |
| `-rd, -retriesDelay` | Delay between retries (seconds) | 0 |
| `-rate` | Maximum requests per second (0 = unlimited) | 0 |

### HTTP Configuration
| Flag | Description | Default |
|------|-------------|---------|
| `-H, -user-agent` | Custom User-Agent string | Mozilla/5.0 (Windows NT 10.0...) |
| `-timeout` | HTTP request timeout for fingerprinting and initial protocol probing (seconds) | 15 |
| `-i, -insecure` | Disable TLS verification | false |
| `--no-resume` | Disable resume; start fresh and ignore any existing `resume.cfg` | false |

### Matchers & Notifications
| Flag | Description | Default |
|------|-------------|---------|
| `-mt, -match-tech` | Match specific technologies (file or comma-separated) | - |
| `-discord` | Send results to Discord | false |
| `-id` | Discord channel ID for notifications | general |
| `-pc, -provider-config` | Notify provider config path | ~/.config/notify/provider-config.yaml |

### Debug & Info
| Flag | Description |
|------|-------------|
| `-verbose` | Enable verbose debugging output |
| `-silent` | Enable silent mode |
| `-version` | Show version information |

## 🔍 Advanced Usage

### Technology Matching
```yaml
# Match specific technologies
echo "https://example.com" | techfinder -mt "wordpress,php,nginx,iis,jenkins,java,grafana"

# Use match file
echo "https://example.com" | techfinder -mt technologies.txt
```

### Discord Integration
```yaml
# Send results to Discord
cat urls.txt | techfinder -discord -id "tech-scans"
```

### Save Results to File
```yaml
# JSON output to file
cat urls.txt | techfinder -json -o results.json

# CSV output to file  
cat urls.txt | techfinder -csv -o results.csv
```

## 🛠️ Performance Tuning

For large-scale scans:
```yaml
# Increase threads and adjust timeouts
# Note: Probing now happens concurrently in workers for much faster performance
cat large_targets.txt | techfinder -t 200 -timeout 10 -retries 2 -rate 500

# Rate limiting example (100 requests per second max)
cat targets.txt | techfinder -t 100 -rate 100

## ♻️ Resume & Interrupt Handling

- Default-on resume saves progress to a `resume.cfg` in the current directory in the form:

```
scanned=300000
```

- Re-run the same command in the same directory to resume; the scanner skips the first `scanned` items and continues.
- Use `--no-resume` to start from scratch.
- On successful completion, `resume.cfg` is deleted automatically.
- On CTRL+C, pending tasks are cancelled gracefully and progress is saved before exiting with a helpful resume hint.
```