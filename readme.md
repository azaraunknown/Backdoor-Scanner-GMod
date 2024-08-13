# Lua Backdoor Scanner

This project is a Node.js-based script designed to scan directories for potentially malicious Lua code, such as backdoors or obfuscated code, often used in Garry's Mod add-ons or scripts. The scanner checks for specific patterns that are commonly associated with backdoor behavior and saves the results to your Documents folder.

## Features

- **Pattern Matching**: Scans Lua files for patterns associated with backdoors and exploits, such as `SteamID`, `http.Fetch`, `RunString`, and more.
- **Directory Scanning**: Recursively scans all Lua files within a specified directory.
- **Detailed Logging**: Logs detailed information about any suspicious code found, including the file name, line number, code snippet, and reason for suspicion.
- **Safe Output**: Results are saved to a uniquely named folder within your Documents directory, ensuring they are easy to find and organized.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/azaraunknown/aBackdoorScanner.git
   cd lua-backdoor-scanner
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

## Usage

1. **Set the directory to scan:**
   - Modify the `directoryToScan` variable in the script to point to the directory you wish to scan.
   ```javascript
   const directoryToScan = 'path/to/directory/to/scan';
   ```

2. **Run the scanner:**
   ```bash
   node scanner.js
   ```

3. **Review the results:**
   - The results of the scan will be saved in the `Documents/scans/` directory under a folder with a random name. This folder will contain text files categorized by the type of suspicious patterns found.

## Match Patterns

The scanner looks for the following patterns in Lua files:

- **STEAMIDCHECK**: Detects `STEAM_` identifiers, which could be used for unauthorized access.
- **STEAMID64CHECK**: Detects `SteamID64`, potentially used for user identification in backdoors.
- **HTTPPOST**: Detects `http.Post`, which can send information to external websites.
- **HTTPFETCH**: Detects `http.Fetch`, used for fetching and executing Lua from external sources.
- **RUNSTRING**: Detects `RunString`, which is often used to run obfuscated or encrypted code.
- **COMPILESTRING**: Detects `CompileString`, typically used for compiling and running obfuscated code.
- **LOADSTRING**: Detects `loadstring`, a function that loads and executes Lua code from strings.
- **OBFUSCATEDCODE1**: Detects hexadecimal code (`0x...`), often used in obfuscated code.
- **OBFUSCATEDCODE2**: Detects another common pattern for obfuscated code (`[xX][0-9a-fA-F]`).
- **GETFENV**: Detects `getfenv`, which can manipulate the environment of functions.
- **SETFENV**: Detects `setfenv`, which can be used for environment manipulation.
- **GLOBAL**: Detects `_G`, a reference to the global table, often used in obfuscation.
- **BACKDOOR_TEXT**: Detects the word "backdoor", which often indicates malicious intent.
- **FILE_WRITE**: Detects `file.Write`, which can create or modify files.
- **NET_RECEIVE**: Detects `net.Receive`, which can execute code upon receiving network messages.
- **NET_START**: Detects `net.Start`, used to start network messages that could be used for unauthorized communication.
- **DEBUG_GETREGISTRY**: Detects `debug.getregistry`, which accesses hidden elements, often in exploits.
- **DEBUG_GETUPVALUE**: Detects `debug.getupvalue`, which manipulates upvalues in functions.

## Notes

- **Use Caution**: This tool is designed for educational purposes and to help identify potentially malicious Lua scripts. It should be used responsibly.
- **Results**: Finding one of these patterns does not guarantee that a script is malicious, but it does warrant further investigation.

# License
This project is licensed under the MIT License. See the [LICENSE](license.md) file for details.

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.