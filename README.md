## Blacknet Full Node Wallet

[![Pipeline status][]](https://gitlab.com/blacknet-ninja/blacknet/pipelines)
[![Web chat][]](https://app.element.io/#/group/+blacknet:matrix.org)
[![Web site][]](https://blacknet.ninja)

#### Blacknet is decentralized peer-to-peer network that secures public blockchain platform with proof of stake consensus.
#### Blacknet是一种去中心化的点对点网络，通过权益证明共识(proof of stake)来保护的公共区块链平台。

## Get the source code
## 获取源代码

- [Release tags][]
- `git clone https://gitlab.com/blacknet-ninja/blacknet.git`

## Setup the environment
## 设置环境

Install the Java JDK (not only JRE) version 8th number or greater.
安装第8版或更高版本的java-jdk（不是JRE）.

- Debian & Ubuntu: `sudo apt-get install default-jdk git`
- Red Hat & Oracle: `sudo yum install java-11-openjdk git`
- SUSE: `sudo zypper install java-11-openjdk git`
- Arch GNU/Linux: `sudo pacman -S --needed jdk-openjdk git`
- Gentoo: `sudo emerge -av1 --noreplace virtual/jdk dev-vcs/git`
- FreeBSD: `sudo pkg install openjdk11 git`
- OpenBSD: `sudo pkg_add jdk git`

## Make the build
## 编译

```
./gradlew installDist
```

The built program is in `./build/install/`
生成的程序位于 `./build/install/`

To run use `./blacknet`, or on Windows use `.\blacknet.bat`
要运行，请使用`./blacknet`, 或在Windows上使用 `.\blacknet.bat`

Gradle `:run` task is supported but not recommended.
Gradle使用 `:run` 运行方式是支持的，但不建议使用.

## How to contribute
## 如何作出贡献

You are welcome to report a theoretical or practical [Issue][],
欢迎您报告理论或实践[Issue][],

or send changes as a [Pull request][] to the master branch.
或将更改作为[Pull request][]发送到master分支.

## License
## 许可信息

This program is distributed under the terms of the Jelurida Public License
version 1.1 for the Blacknet Public Blockchain Platform. See the [LICENSE][] file.
Blacknet是根据Jelurida 1.1版公共许可证的条款发布的公共区块链平台。请参阅[LICENSE][]文件。

[Issue]: https://gitlab.com/blacknet-ninja/blacknet/issues
[LICENSE]: https://gitlab.com/blacknet-ninja/blacknet/-/blob/master/LICENSE.txt
[Pipeline status]: https://gitlab.com/blacknet-ninja/blacknet/badges/master/pipeline.svg
[Pull request]: https://gitlab.com/blacknet-ninja/blacknet/-/merge_requests
[Release tags]: https://gitlab.com/blacknet-ninja/blacknet/-/tags
[Web chat]: https://img.shields.io/matrix/blacknet:matrix.org
[Web site]: https://img.shields.io/website?url=https%3A%2F%2Fblacknet.ninja
