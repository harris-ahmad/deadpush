class Deadpush < Formula
  desc "Guardrails for the vibe coding era — reachability-based dead code detection + semantic debris detection with pre-push git hooks"
  homepage "https://github.com/harris-ahmad/deadpush"
  url "https://github.com/harris-ahmad/deadpush/archive/refs/tags/v0.2.1.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"
  license "MIT"

  depends_on "python@3.11"

  def install
    # Use pip to install the package and its dependencies
    system "pip3", "install", "--prefix=#{prefix}", "."
  end

  def caveats
    <<~EOS
      To get started, run:
        deadpush init

      For hardened mode (privilege separation via _deadpush user):
        sudo deadpush init --mode hardened

      The guardian can be started as a background daemon:
        deadpush protect --daemon

      Check status with:
        deadpush status
    EOS
  end

  test do
    system "#{bin}/deadpush", "--version"
  end
end