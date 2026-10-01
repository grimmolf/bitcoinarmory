# Homebrew formula for the Rust rebuild of Armory.
#   brew install --build-from-source ./packaging/homebrew/armory.rb
# For a tap: copy to <tap>/Formula/armory.rb. The release workflow's job summary prints the url and
# sha256 for each tag; the all-zero sha256 below is a placeholder until v0.1.0 is tagged.
class Armory < Formula
  desc "Bitcoin wallet for cold storage, paper backups and multisig (CLI and TUI)"
  homepage "https://github.com/grimmolf/bitcoinarmory"
  url "https://github.com/grimmolf/bitcoinarmory/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "AGPL-3.0-or-later"
  head "https://github.com/grimmolf/bitcoinarmory.git", branch: "rust-rebuild"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/armory")
    generate_completions_from_executable(bin/"armory", "completions")
    (man1/"armory.1").write Utils.safe_popen_read(bin/"armory", "manpage")
  end

  def caveats
    <<~EOS
      Armory uses your own Bitcoin Core node (29 or newer, server=1):
        brew install bitcoin
      Then run `armory` for the terminal interface, or `armory --help`.
    EOS
  end

  test do
    assert_match "Armory", shell_output("#{bin}/armory about")
    ENV["ARMORY_DATADIR"] = testpath/"data"
    out = shell_output("#{bin}/armory --network regtest wallet create --label t --no-encrypt " \
                       "--kdf-memory-mib 1 --words 12")
    assert_match "Recovery phrase", out
  end
end
