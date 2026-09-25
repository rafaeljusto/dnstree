## Install

```sh
# Debian, Ubuntu
curl -LO @BASE@/dnstree_@BARE@_amd64.deb && sudo dpkg -i dnstree_@BARE@_amd64.deb

# Fedora, RHEL
sudo rpm -i @BASE@/dnstree-@BARE@-1.x86_64.rpm

# Alpine
curl -LO @BASE@/dnstree_@BARE@_x86_64.apk && sudo apk add --allow-untrusted dnstree_@BARE@_x86_64.apk

# Homebrew
curl -LO @BASE@/dnstree.rb && brew install --formula ./dnstree.rb

# Container
docker run --rm ghcr.io/rafaeljusto/dnstree:@VERSION@ www.example.com A
```

arm64 and 32-bit arm packages are here too, alongside the archives for macOS,
Linux, FreeBSD and Windows. `checksums.txt` covers every file.
