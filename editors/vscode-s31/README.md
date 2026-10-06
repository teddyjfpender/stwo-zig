# S31 source highlighting

This folder is a small VS Code language extension with a TextMate grammar for
the implemented S31 text syntax. It recognizes circuit and function
declarations, public/private inputs, nominal and field types, `std::` paths,
compiler builtins, field literals, operators, and comments. The optional
**S31 Neon** theme uses bright pink `#FF00C8` for language keywords.

For a local VS Code installation, link this folder into the editor's extension
directory and restart the editor:

```sh
ln -s "$(pwd)/editors/vscode-s31" "$HOME/.vscode/extensions/s31-language"
```

When using a VS Code variant, use its own extension directory. Select
**S31 Neon** from the color theme picker if you want the included palette;
the grammar also works with any existing TextMate theme.

## GitHub support

The repository's `.gitattributes` maps `.s31` to GitHub's existing Cairo
highlighter, which handles much of S31's Rust-like syntax today. GitHub will
label those files **Cairo**, and its language breakdown uses Cairo's color.
The exact S31 grammar and neon pink language color cannot be enabled by a
repository setting: GitHub gets languages, colors, and TextMate grammars from
[Linguist](https://github.com/github-linguist/linguist). The
[`linguist-language.yml`](linguist-language.yml) entry is the intended
upstream registration. The grammar here is ready for upstream review when
Linguist's [language usage requirements](https://github.com/github-linguist/linguist/blob/main/CONTRIBUTING.md#language-extension-and-filename-usage-requirements)
are met. The fallback override should then be removed.

## Grammar check

```sh
cd editors/vscode-s31
npm ci
npm test
```

The test tokenizes every shipped S31 example with VS Code's TextMate engine
and checks representative scopes. It does not validate S31 semantics; the
compiler's own checks do that.
