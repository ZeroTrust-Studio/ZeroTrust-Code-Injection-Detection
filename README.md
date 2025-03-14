# ZeroTrust External Code Injection Detection

---

### Note

![Banner](https://i.postimg.cc/4NhQT5Yz/Screenshot-9.png)

This detection pattern is extracted from [ZeroTrust Anti-Malware](https://zerotrust.tebex.io/package/6286090). This is just one of dozens of detection patterns available in the premium version. For comprehensive scanning across multiple file types (Lua, JavaScript, C#) and advanced detection capabilities, it's recommended to use the full version. 
ZeroTrust is the best resource on FiveM for scanning threats inside your resources.

<p align='center'>
  ZeroTrust offers the best <b>anticheat and threats detection</b>, visit <a href="https://zerotrust-ac.net">https://zerotrust-ac.net</a>.
</p>

---

A FiveM resource scanner that detects potentially malicious code injection patterns in server-side Lua files.

## Description

This tool scans your server resources for patterns commonly used in malicious code injections, specifically targeting combinations of `PerformHttpRequest` followed by `assert(load)` within a 5-line proximity. These patterns are often used to download and execute any code, which often lead to security risk.

## How It Works

The scanner:
1. Reads all server-side Lua files from your resources
2. Analyzes the code for suspicious patterns
3. Reports any findings with resource and file names
4. Provides a count of total files analyzed

## Limitations

Important: This tool cannot detect patterns in:
- Files encrypted by FiveM's Keymaster/Escrow system
- Obfuscated code
- JS & C# files are ignored

However, it remains useful for:
- Pre-installed resources
- Open-source resources
- Custom resources developed in-house
- Quick security audits of new resources

## Usage

1. Add this resource to your server
2. Start your server or ensure the resource
3. Check server console for any detections
4. Review flagged files manually for confirmation

## Warning

Detected patterns don't always indicate malicious code, but they should be reviewed carefully as they represent potential security risks.
