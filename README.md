## techfinder

A high-performance technology detection tool built with Go, leveraging the [rix4uni/wappalyzergo](https://github.com/rix4uni/wappalyzergo) library to identify web technologies and frameworks — including dynamically loaded JS frameworks like **React, Next.js, Vue, Svelte, Framer Motion** and more via headless browser support.

## 🚀 Features

- **🧠 Headless Detection (default)**: Uses a real headless Chrome browser to detect technologies loaded dynamically via JavaScript (React, Next.js, Framer Motion, Swiper, etc.)
- **⚡ Fast Static Mode**: High-speed HTTP-only detection for large-scale scans without browser overhead
- **🔧 Multi-threaded**: Concurrent processing for maximum throughput
- **📄 Multiple Output Formats**: Plain text, JSON, and CSV support
- **🎯 Tech Matching**: Filter & alert on specific technologies
- **💬 Discord Integration**: Send detections directly to Discord
- **♻️ Crash-Safe Resume**: Default-on resume with `resume.cfg`; use `--no-resume` to start fresh

## 📦 Installation

### Using Go Install
```
go install github.com/rix4uni/techfinder@latest
```

### Download Prebuilt Binaries
```
wget https://github.com/rix4uni/techfinder/releases/download/v0.0.7/techfinder-linux-amd64-0.0.7.tgz
tar -xvzf techfinder-linux-amd64-0.0.7.tgz
rm -rf techfinder-linux-amd64-0.0.7.tgz
mv techfinder ~/go/bin/techfinder
```

Or download [binary release](https://github.com/rix4uni/techfinder/releases) for your platform.

### Compile from Source
```
git clone --depth 1 https://github.com/rix4uni/techfinder.git
cd techfinder; go install
```

## 🔧 Usage
```
A high-performance technology detection tool built with Go, leveraging the rix4uni wappalyzergo library to identify web technologies and frameworks.

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
   -H, -user-agent string        Custom User-Agent header for HTTP requests (default "Mozilla/5.0 ...")
   -discord                      Send Matched tech to Discord
   -id string                    Discord id to send the notification (default "alivesubdomain")
   -pc, -provider-config string  provider config path (default "/root/.config/notify/provider-config.yaml")
   -no-resume                    Disable resume functionality and start scanning fresh

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
   -rate int               Maximum requests per second (0 = unlimited)
   -mode string            Detection mode: 'best' uses headless browser for JS/DOM fingerprinting (default), 'fast' uses static HTTP only (default "best")
```

## 🧠 Detection Modes

techfinder supports two detection modes controlled by the `-mode` flag:

### `-mode best` (Default — Headless Browser)

Launches a real headless Chrome browser for every target, executes page JavaScript, and evaluates:
- **JS globals** (e.g. `window.React.version`, `window.__NEXT_DATA__`)
- **DOM selectors** (e.g. `.swiper`, `[data-framer]`)
- Fully rendered HTML after JS hydration

This catches technologies invisible to static HTTP requests.

```bash
echo "https://www.cetus.zone" | techfinder -mode best -silent
```
```
URL: https://www.cetus.zone
Count: 17
Technologies: [Amazon CloudFront, Amazon Web Services, Framer Motion, HSTS, LottieFiles, Netlify, Next.js App Router, Next.js:14.2.16, Node.js, Open Graph, Priority Hints, React, Svelte, SvelteKit, Swiper, Vite, Webpack]
```

### `-mode fast` (Static HTTP Only)

Uses plain HTTP GET requests only — no browser, no JS execution. Best for large-scale scanning where speed matters more than completeness.

```bash
echo "https://www.cetus.zone" | techfinder -mode fast -silent
```
```
URL: https://www.cetus.zone
Count: 4
Technologies: [Amazon CloudFront, Amazon Web Services, HSTS, Netlify]
```

> **Note:** In `best` mode, if headless Chrome fails for a URL (e.g. network timeout), techfinder automatically falls back to static detection for that target.

## 📊 Output Examples

Single URL:
```bash
echo "https://hackerone.com" | techfinder
```

Multiple URLs:
```bash
cat urls.txt | techfinder
```

Start fresh without resuming:
```bash
cat urls.txt | techfinder --no-resume
```

## Plain text
```bash
cat urls.txt | techfinder -mode fast
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
```bash
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
```

## CSV format
```bash
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
| `-timeout` | HTTP request timeout in seconds | 15 |
| `-i, -insecure` | Disable TLS verification | false |
| `--no-resume` | Disable resume; start fresh | false |

### Detection Mode
| Flag | Description | Default |
|------|-------------|---------|
| `-mode` | `best` = headless browser (JS/DOM), `fast` = static HTTP only | `best` |

### Matchers & Notifications
| Flag | Description | Default |
|------|-------------|---------|
| `-mt, -match-tech` | Match specific technologies (file or comma-separated) | - |
| `-discord` | Send results to Discord | false |
| `-id` | Discord channel ID for notifications | alivesubdomain |
| `-pc, -provider-config` | Notify provider config path | ~/.config/notify/provider-config.yaml |

### Debug & Info
| Flag | Description |
|------|-------------|
| `-verbose` | Enable verbose debugging output |
| `-silent` | Enable silent mode |
| `-version` | Show version information |

## 🔍 Advanced Usage

### Technology Matching
```bash
# Match specific technologies
echo "https://example.com" | techfinder -mt "wordpress,php,nginx,react,nextjs"

# Use match file
echo "https://example.com" | techfinder -mt technologies.txt
```

### Discord Integration
```bash
# Send results to Discord
cat urls.txt | techfinder -discord -id "tech-scans"
```

### Save Results to File
```bash
# JSON output to file
cat urls.txt | techfinder -json -o results.json

# CSV output to file
cat urls.txt | techfinder -csv -o results.csv
```

## 🛠️ Performance Tuning

For large-scale scans where speed is critical, use `-mode fast` to skip headless Chrome:
```bash
# Fast static mode — no browser overhead
cat large_targets.txt | techfinder -mode fast -t 200 -timeout 10 -retries 2 -rate 500
```

For accuracy-focused scans on a smaller set of targets, use the default headless mode:
```bash
# Best accuracy — headless browser per URL
cat targets.txt | techfinder -mode best -t 20 -timeout 20
```

## ♻️ Resume & Interrupt Handling

- Default-on resume saves progress to a `resume.cfg` in the current directory:

```
scanned=300000
```

- Re-run the same command in the same directory to resume; the scanner skips the first `scanned` items and continues.
- Use `--no-resume` to start from scratch.
- On successful completion, `resume.cfg` is deleted automatically.
- On CTRL+C, pending tasks are cancelled gracefully and progress is saved before exiting with a helpful resume hint.
