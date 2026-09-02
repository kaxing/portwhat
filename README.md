# portwhat

Not knowing what port is used for what? No portblem.

See what's using your ports, spot anything unusual, and find a free port for
your next dev server. portwhat only reads your local socket tables — it never
sends packets.

## Install & run

```sh
brew install go
go install github.com/kaxing/portwhat@latest
export PATH="$HOME/go/bin:$PATH"
portwhat
```

## Uninstall

```sh
rm "$(go env GOPATH)/bin/portwhat"
```

## Usage

```
portwhat           overview + security notes + recommended next port
portwhat next      print only the recommended port number (for scripts)
portwhat 3000 80   show status for specific ports
```

portwhat never asks for elevated privileges, so a few process details may show as `unknown`.

To see more, run it with `sudo`:

```sh
sudo `which portwhat`
```
