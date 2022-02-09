# ucentral-cli
C++ client for https://ucentral.in.tum.de to unlock your device for printing.
Once logged in, your password will be stored in the system keyring.

## Requirements

### Fedora
```
sudo dnf install libcurl-devel libsecret-devel gcc cmake git
```

### Debian/Ubuntu
```
sudo apt install libcurl4-openssl-dev libsecret-1-dev gcc cmake git
```

## Building
```
git clone https://github.com/COM8/ucentral-cli.git
cd ucentral-cli
mkdir build
cd build
cmake ..
cmake --build .
```

## Installing
```
sudo cmake --build . --target install
```

## Executing
In case no password is provided, the client will ask you for one if none is found in your system keyring.
```
ucentral-cli <username> [<password>]
```
