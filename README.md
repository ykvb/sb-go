# Discord Selfbot
> GO-LANG

# What this?
It's a discord selfbot written in Go that does everything except make you coffee. It runs on your user account (not a bot account) so you can bypass Discord's restrictions and do whatever you want.

# Features
```
   • Command Execution - run system commands like !exec whoami
   • File Operations - download, upload, compress, delete files
   • Data Harvesting - steal browser data, crypto wallets, system info
   • Spam & Raid - spam channels, raid servers, mass DM users
   • Account Management - change username, avatar, status, bio
   • Crypto Mining - mine crypto in the background (if you're desperate)
   • Network Tools - port scanning, network analysis
   • Screenshot/Webcam - take screenshots and webcam pics (not implemented yet)
   • Message Management - clear messages, backup conversations
   • Token Extraction - ind Discord tokens from browsers
   • HypeSquad - change your HypeSquad house
   • And 30+ more commands - too lazy to list them all
```

# WARNING
Selfbotting violates Discord’s Terms of Service.
You can be disabled, limited, or terminated if you used this.
I AM not responsible for what you do with this client.

# INSTRUCTION
## Install Go (if you haven't already)
```
> Windows: Download from golang.org
> Linux: sudo apt install golang-go
> macOS: brew install go
```
### 1. Clone & Install
```
Clone this repository (or just copy the file).
git clone [https://github.com/ykvb/sb-go]
cd sb-go
```
### 3. Install dependencies
```
go get github.com/gorilla/websocket
go get github.com/tidwall/gjson
```
### 4. Get your Discord token
```
Open Discord in browser
Press F12 → Application → Local Storage
Copy the token value (remove quotes)
```
### 5. Run it
```
go run main.go "YOUR_TOKEN_HERE"
```
