# Homebrew recipe for msecret.

require 'formula'

class Msecret < Formula
  homepage 'https://github.com/darconeous/msecret'
  head 'https://github.com/openthread/wpantund.git', :using => :git, :branch => 'master'
  url 'https://github.com/openthread/wpantund.git', :using => :git, :tag => '0.02.00'
  version '0.02.00'

  depends_on 'pkg-config' => :build
  depends_on 'openssl' => :build

  depends_on 'autoconf' => :build
  depends_on 'automake' => :build
  depends_on 'libtool' => :build
  depends_on 'autoconf-archive' => :build

  def install
    system "[ -x configure ] || PATH=\"#{HOMEBREW_PREFIX}/bin:$PATH\" ./bootstrap.sh"

    system "./configure",
      "--prefix=#{prefix}"

    system "make check"
    system "make install"
  end

  def test
    system "msecret"
  end
end
