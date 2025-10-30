
# DNS Proxy

**DNS Proxy** acts as an intermediate layer between clients and a DNS server, applying user-defined rules such as domain blocking and redirection.
  
## Requirements

- **[Python 3.13+](https://python.org/)**
- [dnspython](https://pypi.org/project/dnspython/)
- [fastapi](https://pypi.org/project/fastapi/)
- [uvicorn](https://pypi.org/project/uvicorn/)
- [loguru](https://pypi.org/project/loguru/)
- [pydantic](https://pypi.org/project/pydantic/)
- [pydantic-settings](https://pypi.org/project/pydantic-settings/)

## Installation

### Clone the repository
```bash
git clone https://github.com/ximbio/dns-proxy.git
cd dns-proxy
```

### Install dependencies

#### Using uv (Recommended)
 `uv` automatically creates and manages a virtual environment for the project.
 
```
uv sync
```

#### Using pip + venv

```
python -m venv venv
source venv/bin/activate # or on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

### Environment variables

Set the following environment variables to configure the proxy behavior:

| Variable | Description | Default |
|-----------|--------------|----------|
| `USE_DOT` | Enable DNS-over-TLS (1 = enabled, 0 = disabled) | `0` |
| `USE_DOH` | Enable DNS-over-HTTPS (1 = enabled, 0 = disabled) | `1` |
| `DOH_HOST` | DoH server host | `127.0.0.1` |
| `DOH_PORT` | DoH server port | `8000` |
| `DOT_HOST` | DoT server host |  |
| `DOT_PORT` | DoT server port | |
| `DOT_CERT_FILE` | Path to TLS certificate file | |
| `DOT_KEY_FILE` | Path to TLS key file |  |
| `LOG_LEVEL` | Logging level (`DEBUG`, `INFO`, `WARNING`, etc.) | `INFO` |
| `UPSTREAM_DNS` | List of upstream DNS resolvers | [`1.1.1.1`, `8.8.8.8`] |

>**Note**: you may need special permissions to bind port 853 directly.

### Rules
All rules are configured in `rules.json` at the root of the project.
> **Note**
> `rules.json` will be automatically created at the first launch.


`rules.json` structure:
```json
{
	"blocklist_file": "",
	"redirect_map": {
	
	},
	"blocklist": [
	
	]
}
```
1. `blocklist_file` specifies a path to a **JSON file** containing a list of blocked domain patterns.
	`blocklist_file` example:
	```
	[
		"ads.google.com",
		...
		"ads.amazon.com"
	]
	```
	You can leave this field empty if you don’t want to use an external blocklist file.
	
2. `redirect_map` defines custom IP overrides for specific domain patterns.
	For example:
	```json
	"redirect_map": {
		"*.google.com": "123.123.123.123",
		"sub.amazon.com": "123.123.123.132",
		"example.com": "123.123.123.123"
	}
	```

3. `blocklist` lists domain patterns that should be blocked. When a request matches a blocked domain, the server returns an `NXDOMAIN` response code.

>**Note**
>A domain pattern can be written in the following forms:
> - `google.com` -  matches only the `google.com` domain
>- `sub.google.com` - matches only the `sub.google.com` domain
>- `*.google.com` - matches all subdomains of `google.com`, but **not** `google.com` itself.

## Running

### Using uv (recommended)
```bash
uv run python main.py
```
### Using python
```bash
python main.py
```
