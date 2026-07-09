# portwhat

Not knowing what port is used for what? No portblem.

Shows every listening TCP/UDP port, explains what it probably is, flags
security oddities, and recommends a free port for your next dev server.
Reads the local socket tables only — never sends packets.

## Install

```sh
go install github.com/kaxing/portwhat@latest
export PATH="$HOME/go/bin:$PATH"
portwhat
```

## Usage

```
portwhat           overview + security notes + recommended next port
portwhat next      print only the recommended port number (for scripts)
portwhat 3000 80   show status for specific ports
```

Some process names may show as `unknown` without elevated privileges.
