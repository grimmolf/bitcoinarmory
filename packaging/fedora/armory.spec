# Fedora / COPR package of the Rust rebuild of Armory.
#
#   rpmbuild: spectool -g -R armory.spec && rpmbuild -ba armory.spec
#   COPR:     build from this spec with network access enabled (cargo fetches the locked crates),
#             or vendor them first (`cargo vendor`) and add the tarball as Source1.

%global commit_ref v%{version}

Name:           armory
Version:        0.1.0
Release:        1%{?dist}
Summary:        Bitcoin wallet for cold storage, paper backups and multisig (CLI and TUI)
License:        AGPL-3.0-or-later
URL:            https://github.com/grimmolf/bitcoinarmory
Source0:        %{url}/archive/%{commit_ref}/bitcoinarmory-%{version}.tar.gz

ExclusiveArch:  %{rust_arches}
BuildRequires:  cargo >= 1.85
BuildRequires:  rust >= 1.85
BuildRequires:  gcc

%description
Armory is a Bitcoin wallet focused on cold storage: offline signing, paper and fragmented
backups, multisig lockboxes and message signing. This is the Rust rebuild for Linux and macOS
with a command-line interface and a full-screen terminal interface. It works with your own
Bitcoin Core node (29 or newer) and reads Armory 0.93 wallets and backups.

%prep
%autosetup -n bitcoinarmory-%{version}

%build
cargo build --release --locked -p armory
mkdir -p gen/completions
target/release/armory manpage > gen/armory.1
target/release/armory completions bash > gen/completions/armory
target/release/armory completions zsh > gen/completions/_armory
target/release/armory completions fish > gen/completions/armory.fish

%check
cargo test --release --locked --workspace

%install
install -Dpm 0755 target/release/armory %{buildroot}%{_bindir}/armory
install -Dpm 0644 gen/armory.1 %{buildroot}%{_mandir}/man1/armory.1
install -Dpm 0644 gen/completions/armory %{buildroot}%{bash_completions_dir}/armory
install -Dpm 0644 gen/completions/_armory %{buildroot}%{zsh_completions_dir}/_armory
install -Dpm 0644 gen/completions/armory.fish %{buildroot}%{fish_completions_dir}/armory.fish

%files
%license LICENSE
%doc crates/README.md docs/rust-rebuild
%{_bindir}/armory
%{_mandir}/man1/armory.1*
%{bash_completions_dir}/armory
%{zsh_completions_dir}/_armory
%{fish_completions_dir}/armory.fish

%changelog
* Thu Oct 01 2026 Armory contributors - 0.1.0-1
- First release of the Rust rebuild: CLI and TUI.
