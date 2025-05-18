# Knock

Knock is a secure web-based firewall management tool that allows you to manage your firewall rules through a simple web interface. It uses predefined shell scripts, making it flexible for different Linux firewall configurations.

## Features

- Web-based interface for managing firewall rules
- IPv4 and IPv6 support
- Secure token-based authentication
- Configurable script execution
- CSRF protection
- Background script execution capability

## Installation

1. Download the latest release from the releases page
2. Make the binary executable:
   ```bash
   chmod +x knock
   ```
3. Create a configuration file (see Configuration section)
4. Run the server:
   ```bash
   export TOKEN=<auth-token>
   ./knock -c your_config.conf
   ```

## Configuration

Knock uses a simple configuration file format that compatiable with bash grammer. 
Here's an example:

```conf
[ /path/to/endpoint#title=Title#desc=Description#background=false ]

# Your shell script here
command1
command2

[ /path/to/endpoint2#title=Title#desc=Description#background=false ]

# Your shell script here
command1
command2
```

### Configuration Options

- `path`: The URL path for the endpoint
- `title`: Display title for the endpoint
- `desc`: Description of what the endpoint does
- `background`: Whether to run the script in the background (true/false)

## Usage

1. Start the server with your configuration file:
   ```bash
   ./knock -c your_config.conf
   ```

2. Access the web interface at `http://localhost:8080` (default port)

3. Use the web interface to:
   - Allow IP addresses through the firewall
   - Deny IP addresses
   - Manage both IPv4 and IPv6 rules

## Security

- The server uses token-based authentication
- CSRF protection is implemented
- All scripts are executed with proper security measures
- IP validation is performed before any actions

## Example Configuration

See `example.conf` for sample configurations for both nftables and iptables.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.