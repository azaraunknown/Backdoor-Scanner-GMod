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
    LOADSTRING: { pattern: /loadstring/, reason: "LoadString is often used for loading and executing Lua code from strings, potentially dangerous" },
    OBFUSCATEDCODE1: { pattern: /0[xX][0-9a-fA-F]+/, reason: "[Check 1] Obfuscated/Encrypted code which is often used for running backdoored code secretly" },
    OBFUSCATEDCODE2: { pattern: /\[xX][0-9a-fA-F][0-9a-fA-F]/, reason: "[Check 2] Obfuscated/Encrypted code which is often used for running backdoored code secretly" },
    GETFENV: { pattern: /getfenv/, reason: "Calling to run function getfenv, which can be used maliciously" },
    SETFENV: { pattern: /setfenv/, reason: "setfenv can be used to manipulate the environment of a function, often used in exploits" },
    GLOBAL: { pattern: /_G/, reason: "References global table, which is often used for generating obfuscated code" },
    BACKDOOR_TEXT: { pattern: /backdoor/i, reason: "Contains 'backdoor' text, which is often an indicator of malicious intent" },
    FILE_WRITE: { pattern: /file\.Write/, reason: "file.Write can be used to create or modify files, potentially storing malicious data" },
    NET_RECEIVE: { pattern: /net\.Receive/, reason: "net.Receive can be used to receive network messages, potentially executing malicious code" },
    NET_START: { pattern: /net\.Start/, reason: "net.Start can be used to start a network message, which may be used for unauthorized communication" },
    DEBUG_GETREGISTRY: { pattern: /debug\.getregistry/, reason: "debug.getregistry can access hidden elements, often used in exploits" },
    DEBUG_GETUPVALUE: { pattern: /debug\.getupvalue/, reason: "debug.getupvalue can manipulate upvalues in functions, which can be dangerous" }
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
