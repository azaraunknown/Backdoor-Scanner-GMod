import fs from 'fs';
import { promises as fsPromises } from 'fs';
import path from 'path';
import readline from 'readline';
import crypto from 'crypto';
import os from 'os';

// Directory to scan
const directoryToScan = 'path/to/directory/to/scan';

// patterns to search for
const MATCHES = {
    STEAMIDCHECK: { pattern: /STEAM_/, reason: "Presence of SteamID which could be used for backdooring" },
    STEAMID64CHECK: { pattern: /7656119[0-9]{10}/, reason: "Presence of SteamID64, which can be used for user identification in backdoors" },
    HTTPPOST: { pattern: /http\.Post/, reason: "http.Post can send information to outside websites such as IP, player count, and more" },
    HTTPFETCH: { pattern: /http\.Fetch/, reason: "http.Fetch can request and run Lua from outside websites, which is how most backdoors work." },
    RUNSTRING: { pattern: /RunString/, reason: "Runs Lua code, which is often used for running obfuscated/encrypted Lua code" },
    COMPILESTRING: { pattern: /CompileString/, reason: "CompileString is often used for compiling obfuscated code and running it" },
    OBFUSCATEDCODE1: { pattern: /0[xX][0-9a-fA-F]+/, reason: "[Check 1] Obfuscated/Encrypted code which is often used for running backdoored code secretly" },
    OBFUSCATEDCODE2: { pattern: /\[xX][0-9a-fA-F][0-9a-fA-F]/, reason: "[Check 2] Obfuscated/Encrypted code which is often used for running backdoored code secretly" },
    OBFUSCATEDCODE3: { pattern: /\\x[0-9a-fA-F]{2}/, reason: "Another form of obfuscated/encrypted code using hex escape sequences" },
    GETFENV: { pattern: /getfenv/, reason: "Calling to run function getfenv, which can be used maliciously" },
    SETFENV: { pattern: /setfenv/, reason: "setfenv can be used to manipulate the environment of a function, often used in exploits" },
    GLOBAL: { pattern: /_G/, reason: "References global table, which is often used for generating obfuscated code" },
    BACKDOOR_TEXT: { pattern: /backdoor/i, reason: "Contains 'backdoor' text, which is often an indicator of malicious intent" },
    FILE_WRITE: { pattern: /file\.Write/, reason: "file.Write can be used to create or modify files, potentially storing malicious data" },
    NET_RECEIVE: { pattern: /net\.Receive/, reason: "net.Receive can be used to receive network messages, potentially executing malicious code" },
    NET_START: { pattern: /net\.Start/, reason: "net.Start can be used to start a network message, which may be used for unauthorized communication" },
    DEBUG_GETREGISTRY: { pattern: /debug\.getregistry/, reason: "debug.getregistry can access hidden elements, often used in exploits" },
    DEBUG_GETUPVALUE: { pattern: /debug\.getupvalue/, reason: "debug.getupvalue can manipulate upvalues in functions, which can be dangerous" },
    LUASOCKET: { pattern: /require\s*\(\s*["']?socket["']?\s*\)/, reason: "LuaSocket usage, which can be used for unauthorized network communication" },
    BYTECODE: { pattern: /string\.dump/, reason: "string.dump can be used to generate Lua bytecode, potentially obfuscating malicious code" },
    HTTP_REQUEST: { pattern: /http\.request/, reason: "http.request can be used to communicate with external servers, potentially leaking data or downloading malicious code" },
    OS_EXECUTE: { pattern: /os\.execute/, reason: "os.execute can run system commands, which is highly dangerous if exploited" },
    IO_POPEN: { pattern: /io\.popen/, reason: "io.popen can execute system commands and read their output, potentially used for malicious purposes" },
    PACKAGE_LOADED: { pattern: /package\.loaded/, reason: "Manipulating package.loaded can be used to override or inject malicious modules" },
    HOOK_ADD: { pattern: /hook\.Add/, reason: "hook.Add can be used to inject code into existing functions, potentially for malicious purposes" },
    CONCOMMAND_ADD: { pattern: /concommand\.Add/, reason: "Adding console commands that could be used to trigger malicious actions" },
    TIMER_CREATE: { pattern: /timer\.Create/, reason: "Creating timers that could periodically execute malicious code" },
    UTIL_TABLETOSTRING: { pattern: /util\.TableToString/, reason: "Often used in combination with RunString to execute obfuscated code" },
    BIT_BXOR: { pattern: /bit\.bxor/, reason: "Bitwise XOR operation, commonly used in simple obfuscation techniques" },
    STRINGREP: { pattern: /string\.rep\s*\([^,]+,\s*256/, reason: "Large string repetition, potentially used for buffer overflow exploits" },
    BASE64: { pattern: /base64/, reason: "Base64 encoding/decoding, often used to obfuscate malicious code" },
    WEBSOCKETS: { pattern: /WebSocket/, reason: "WebSocket usage, which can be used for unauthorized real-time communication" },
    EVAL: { pattern: /eval\s*\(/, reason: "eval function usage, which can execute arbitrary code and is often considered unsafe" },
    STRINGMANIP: {pattern: /string\.byte\s*\(\s*[^\)]+\s*\)|string\.char\s*\(\s*[^\)]+\s*\)/, reason: "String manipulation through byte/char conversion, often used to obfuscate function or variable names to evade detection."},
    TABLEMANIP: {pattern: /table\.concat\s*\(\s*[^\)]+\s*\)/, reason: "Concatenation of table elements into strings, which can be used to assemble obfuscated code dynamically."},
    DYNAMICFUNCTIONS: {pattern: /\[[^\]]+\]\s*\(/, reason: "Execution of functions using dynamic variable names, which can disguise malicious code execution."},
    OBFUSSTRING: {pattern: /\([^\)]+\s*%\s*256\)/, reason: "Obfuscation of strings through arithmetic operations, a common technique for hiding malicious code."},
    ADDITIONALDEBUG: {pattern: /debug\s*\[\s*[^\]]+\s*\]/, reason: "Indirect access to the debug library using obfuscated keys, which can be used to bypass security checks and access sensitive elements."},
};

async function findLuaFiles(dir) {
    let files = [];

    try {
        const entries = await fsPromises.readdir(dir, { withFileTypes: true });
        for (let entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                files = files.concat(await findLuaFiles(fullPath));
            } else if (entry.isFile() && fullPath.endsWith('.lua')) {
                files.push(fullPath);
            }
        }
    } catch (err) {
        console.error(`Error reading directory ${dir}: ${err.message}`);
    }

    return files;
}

async function scanDirectory(directory) {
    console.log(`Scanning directory: ${directory}`);

    const files = await findLuaFiles(directory);

    if (files.length === 0) {
        console.log("No Lua files found in the directory.");
        return;
    }

    const matchesByType = {};

    for (const file of files) {
        await checkFile(file, matchesByType);
    }

    const randomDirName = crypto.randomBytes(4).toString('hex');
    const documentsDir = path.join(os.homedir(), 'Documents');
    const outputDir = path.join(documentsDir, 'scans', randomDirName);

    await fsPromises.mkdir(outputDir, { recursive: true });
    await saveMatches(matchesByType, outputDir);

    console.log(`Results saved to: ${outputDir}`);
}

async function checkFile(file, matchesByType) {
    console.log(`Scanning file: ${file}`);

    const fileStream = fs.createReadStream(file);
    const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
    });

    let lineNumber = 0;
    for await (const line of rl) {
        lineNumber += 1;
        for (const [type, match] of Object.entries(MATCHES)) {
            if (match.pattern.test(line)) {
                if (!matchesByType[type]) {
                    matchesByType[type] = [];
                }
                matchesByType[type].push({
                    file,
                    lineNumber,
                    lineContent: line.trim(),
                    reason: match.reason
                });
            }
        }
    }
}

async function saveMatches(matchesByType, outputDir) {
    for (const [type, matches] of Object.entries(matchesByType)) {
        const filePath = path.join(outputDir, `${type}.txt`);
        const fileStream = fs.createWriteStream(filePath);

        for (const match of matches) {
            fileStream.write(`[FOUND] ${match.lineContent}\n`);
            fileStream.write(`[LOCATION] ${match.file}:${match.lineNumber}\n`);
            fileStream.write(`[REASON] ${match.reason}\n\n`);
        }

        fileStream.end();
    }

    console.log(`Results saved to: ${outputDir}`);
}

scanDirectory(directoryToScan);
