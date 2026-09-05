class MlabMikrotik < Formula
  desc "CLI over the RouterOS REST API, for passive network security work"
  homepage "https://github.com/mlab-sh/mlab-mikrotik"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-mikrotik/releases/download/v#{version}/mlab-mikrotik-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "78d80648b647a84335f8caae93e5a31be3fbf81f6305528544de476b057f1887"
    else
      url "https://github.com/mlab-sh/mlab-mikrotik/releases/download/v#{version}/mlab-mikrotik-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "5acda2dce763e3b2acbadd274a5d9467a27035e5136d15702e0f59c80cca8f9f"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-mikrotik/releases/download/v#{version}/mlab-mikrotik-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "312aff8954a5f8096d5712967ad0835612f905547fece0960a2b2d965aa46340"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-mikrotik/releases/download/v#{version}/mlab-mikrotik-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "67645a57909ce7f6a38a571fbe25b69c251e8d421feccd9fe534d13eeee160a8"
    end
  end

  def install
    bin.install "mlab-mikrotik"
  end

  test do
    assert_match "mlab-mikrotik", shell_output("#{bin}/mlab-mikrotik --version")
  end
end
