# framework
基于Skynet_win的轻量化3D编辑器服务端框架

# skynet_win
在此https://github.com/sanikoyes/skynet版本修改的win vs版本

## Skynet

Skynet is a lightweight online game framework, and it can be used in many other fields.

## 前言
##支持windows下运行，支持visual studio 2019

```
此版本修改自官方版skynet，改动部分如下：
1、sproto修改，添加了real（双精度浮点数double）的支持，以及variant类型（可以是real/int/string/bool）的支持
2、windows下不支持epoll，故采用event-select网络模型模拟epoll来保证最小改动skynet源码的情况下，实现网络通讯
3、windows平台下没有pipe兼容的接口，采用了socket api来模拟这一机制
4、控制台输入，hack修改了read函数来模拟读取fd 0(stdin)
```

## 编译
```
windows：
使用visual studio 2013直接打开build/vs2013/skynet.sln即可，目前暂时只支持这一个版本的编译器

linux/macos：
官方版一样
```

## 运行
```
windows：
1、工作目录设置为skynet.exe所在目录，默认为 $(ProjectDir)..\..\
2、命令参数设置为config文件的相对路径，如 examples/config

linux/macos：
和官方版一样
```

## Build

For windows, open build/vs2013/skynet.sln and build all
You can use vs ide to debugging skynet

```
## Difference between offical skynet
1.sproto support real(double)/variant(real/int/string) field type
2.used event-select to simulate epoll
3.use socket api to simulate pipe()
4.hack read fd(0) for console input
```

For linux, install autoconf first for jemalloc:

```
git clone https://github.com/cloudwu/skynet.git
cd skynet
make 'PLATFORM'  # PLATFORM can be linux, macosx, freebsd now
```

Or you can:

```
export PLAT=linux
make
```

For FreeBSD , use gmake instead of make.

## Test

Run these in different consoles:

```
./skynet examples/config	# Launch first skynet node  (Gate server) and a skynet-master (see config for standalone option)
./3rd/lua/lua examples/client.lua 	# Launch a client, and try to input hello.
```

## About Lua version

Skynet now uses a modified version of lua 5.3.3 ( https://github.com/ejoy/lua/tree/skynet ) for multiple lua states.

You can also use official Lua versions, just edit the Makefile by yourself.

## How To Use (Sorry, Only in Chinese now)

* Read Wiki for documents https://github.com/cloudwu/skynet/wiki
* The FAQ in wiki https://github.com/cloudwu/skynet/wiki/FAQ
