# Suggested Commands

## Build Commands

### Release Build
```bash
git submodule update --init
mkdir build && cd build
cmake ../ -DCMAKE_BUILD_TYPE=Release
make -j
```

### Debug Build
```bash
git submodule update --init
mkdir build && cd build
cmake ../ -DCMAKE_BUILD_TYPE=Debug
make -j
```

## Run Commands

### Run Server
```bash
cd build
./bin/srt_server -c ../sls.conf
```

### Run with Custom Config
```bash
./bin/srt_server -c /path/to/config.conf
```

### Help
```bash
./bin/srt_server -h
```

### Test Client (Push)
```bash
./bin/srt_client -r srt://[server.ip]:8080?streamid=uplive.sls/live/test -i /path/to/file.ts
```

### Test Client (Play)
```bash
./bin/srt_client -r srt://[server.ip]:8080?streamid=live.sls/live/test -o /path/to/save.ts
```

## System Commands
Standard Linux commands are available (grep, find, ls, cd, etc.)
