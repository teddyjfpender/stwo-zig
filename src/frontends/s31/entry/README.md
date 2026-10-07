# Zig build entries

`build.zig` gives each standalone test and executable a tiny entry file here. The implementation stays in its domain directory (`sha/`, `bitcoin/`, `runtime/`, and so on).

Zig 0.15 treats the directory of a module's root file as its import boundary. The `src` symlink points to the parent S31 directory so an entry can import its implementation and that implementation's relative dependencies within one module boundary. Each entry imports exactly one implementation file. Add a matching entry when registering a new `localEntry` in `build.zig`.

The entry files contain no proof logic. Tests are discovered from the imported source; executables forward `main` to it.
