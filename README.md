#  Scanner 
*Inspects and maps multiple attack surfaces of a website of CVEs and CWEs*
***

## Usage

1. `# Scan a target url`<br>
   `$ cargo run --release -- scan <url>` 
2. `# List modules` <br>
   `$ cargo run -- modules`
   
***
### Modules
1. `subdomain module`: <br>
   Find all subdomains for a given domain and source
2. `http module`: <br>
For a given endpoint (`host:port`), check for vulnerabilities
***

