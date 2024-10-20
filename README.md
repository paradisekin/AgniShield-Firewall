
# Agnishield Web Firewall

Agnishield Web Firewall is a Chrome extension that fetches firewall rules from a backend API and dynamically blocks specified domains. The firewall is designed to enhance web browsing security by preventing access to malicious or restricted domains as defined in the backend API.

## Features

- Dynamically fetches firewall rules from a backend API.
- Blocks specified domains in real-time.
- Easy-to-use Chrome extension interface.
- Supports custom rules and domain lists from a centralized backend.
- Provides real-time protection for web browsing.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/agnishield-web-firewall.git
   ```

2. Navigate to the project directory:

   ```bash
   cd agnishield-web-firewall
   ```

3. Install dependencies (if any):

   ```bash
   npm install
   ```

4. Load the Chrome extension:
   - Open Chrome and navigate to `chrome://extensions/`.
   - Enable "Developer mode" on the top right.
   - Click "Load unpacked" and select the project folder.

## Usage

1. The extension automatically fetches rules from the backend API and applies them to block specified domains.
2. To view or update the firewall rules, refer to the backend API for rule management.
3. Open the browser console to view logs related to blocked domains and applied rules.

## Contribution

### Commit Message Guidelines

To keep the repository clean and maintainable, use clear and descriptive commit messages. Here's a guide for crafting your commit messages:

#### Format

```
<type>: <subject>
```

- **type**: The type of change you're making. Examples: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`.
- **subject**: A short description of what the commit does (max 50 characters).

#### Example Commit Messages

- `feat: Add dynamic rule fetching from backend API`
- `fix: Resolve issue blocking all sites`
- `docs: Update README with installation instructions`
- `refactor: Improve firewall rule matching algorithm`
- `style: Format code according to linting rules`

## Contribution Guidelines

1. Fork the repository.
2. Create a new branch:

   ```bash
   git checkout -b feature/your-feature-name
   ```

3. Commit your changes with a descriptive message:

   ```bash
   git commit -m "feat: Describe your change"
   ```

4. Push your branch:

   ```bash
   git push origin feature/your-feature-name
   ```

5. Create a pull request to the main repository.

## Issues

If you encounter any issues or bugs, please create a new issue on the GitHub repository and provide detailed steps to reproduce the problem.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
