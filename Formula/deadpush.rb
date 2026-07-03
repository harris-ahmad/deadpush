class Deadpush < Formula
  include Language::Python::Virtualenv

  desc "Real-time AI agent guardian with git hooks and MCP write interception"
  homepage "https://github.com/harris-ahmad/deadpush"
  url "https://github.com/harris-ahmad/deadpush/archive/refs/tags/v0.2.1.tar.gz"
  # RELEASE STEP: placeholder sha256 (all-zeros). It can only be filled once the
  # repo is PUBLIC and the tag is pushed. `brew install` will fail loudly with a
  # checksum mismatch until then. Run scripts/brew_release.sh to fetch the tarball,
  # compute the real sha256, write it here, and verify with brew audit/install/test.
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"

  depends_on "python@3.14"

  # Runtime dependencies, pinned to the exact versions in uv.lock (the versions
  # the test suite runs against). Homebrew installs these with --no-deps, so every
  # runtime dependency must be listed explicitly. The PEP 517 build backend
  # (hatchling) is resolved automatically via pip build isolation and is not vendored.
  resource "click" do
    url "https://files.pythonhosted.org/packages/9b/98/518d8e5081007684232226f475082b30087d0f585e8457db087298259f49/click-8.4.1.tar.gz"
    sha256 "918b5633eddf6b41c32d4f454bf0de810065c74e3f7dbf8ee5452f8be88d3e96"
  end

  resource "pathspec" do
    url "https://files.pythonhosted.org/packages/5a/82/42f767fc1c1143d6fd36efb827202a2d997a375e160a71eb2888a925aac1/pathspec-1.1.1.tar.gz"
    sha256 "17db5ecd524104a120e173814c90367a96a98d07c45b2e10c2f3919fff91bf5a"
  end

  resource "watchdog" do
    url "https://files.pythonhosted.org/packages/db/7d/7f3d619e951c88ed75c6037b246ddcf2d322812ee8ea189be89511721d54/watchdog-6.0.0.tar.gz"
    sha256 "9ddf7c82fda3ae8e24decda1338ede66e1c99883db93711d8fb941eaa2d8c282"
  end

  def install
    virtualenv_install_with_resources
  end

  def caveats
    <<~EOS
      Get started by protecting a repository:
        cd your-repo && deadpush init

      For hardened mode (privilege separation via a dedicated _deadpush user):
        sudo deadpush init --mode hardened

      Run the guardian as a background daemon:
        deadpush protect --daemon

      Check status:
        deadpush status
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/deadpush --version")
  end
end
