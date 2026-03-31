# bjail

`bjail` 是一个基于 Rust 实现的最小 Linux CLI 沙箱。

它参考了 `openai/codex` 的简易沙箱思路，使用 `bubblewrap` (`bwrap`) 创建一个默认只读的文件系统视图，再把指定工作目录重新挂载为可写，并通过 CLI 选项控制：

- 沙箱内可写路径
- 可读白名单
- 不可读黑名单
- 是否保留网络访问
- 是否允许沙箱内程序创建子进程

一个常见用法是把：

```bash
bash -lc 'cat file'
```

替换成：

```bash
bjail cat file
```

这会在沙箱环境内执行 `bash -lc 'cat file'`。

## 运行要求

- Linux
- 已安装 Rust 工具链
- 已安装 `bubblewrap`，并且命令 `bwrap` 可用

检查依赖：

```bash
rustc --version
cargo --version
bwrap --version
```

## 编译

在仓库根目录执行：

```bash
cargo build
```

优化版：

```bash
cargo build --release
```

编译产物位置：

- Debug: `target/debug/bjail`
- Release: `target/release/bjail`

## 基本用法

```bash
bjail [OPTIONS] <command> [args...]
```

例如：

```bash
bjail cat Cargo.toml
```

## 选项

### `--sandbox-path <PATH>`

指定沙箱里允许写入的工作目录。

- 默认值：当前工作目录
- 该目录会在沙箱中重新 bind 为可写
- 其它路径默认保持只读

示例：

```bash
bjail --sandbox-path /tmp/workspace cat hello.txt
```

### `--readable-path <PATH>`

追加可读白名单路径，可重复传入。

- 未设置时：默认仍是整棵 `/` 只读可见，`sandbox-path` 可写
- 设置后：切换到白名单模式，根文件系统从空 `tmpfs` 开始，只挂载最小系统目录、`sandbox-path`、以及你显式指定的可读路径

示例：

```bash
bjail \
  --sandbox-path /tmp/workspace \
  --readable-path /home/user/data \
  ls /home/user/data
```

这时未挂载进来的其它普通路径默认不可见。

### `--allow-env-path`

把当前 `bjail` 进程环境变量 `PATH` 里的现存目录自动并入可读白名单。

- 主要用于白名单模式，避免 `PATH` 里的工具目录因为未挂载而不可执行
- 不存在或不是目录的 `PATH` 项会被忽略

示例：

```bash
bjail \
  --sandbox-path /tmp/workspace \
  --readable-path /home/user/project \
  --allow-env-path \
  bash -lc 'command -v ls && command -v python3'
```

### `--blocked-path <PATH>`

追加不可读黑名单路径，可重复传入。

- 目录会被一个权限为 `000` 的只读 `tmpfs` 覆盖
- 文件会被一个权限为 `000` 的空文件覆盖
- 当前实现要求该路径在宿主机上已经存在

示例：

```bash
bjail \
  --sandbox-path /tmp/workspace \
  --blocked-path /tmp/workspace/secret \
  ls /tmp/workspace
```

结合白名单一起使用：

```bash
bjail \
  --sandbox-path /tmp/workspace \
  --readable-path /home/user/project \
  --blocked-path /home/user/project/.git \
  ls /home/user/project
```

### `--network <true|false>`

控制是否保留网络访问。

- `false`：隔离网络命名空间
- `true`：允许使用宿主机网络

示例：

```bash
bjail --network false python3 -c "import socket; socket.create_connection(('1.1.1.1', 53), 2)"
bjail --network true python3 -c "import socket; socket.create_connection(('1.1.1.1', 53), 2)"
```

### `--subprocess <true|false>`

控制沙箱内 payload 是否允许再创建子进程。

- `true`：允许 `fork/clone`
- `false`：通过 seccomp 拦截 `fork/vfork/clone/clone3`

当该选项为 `false` 时，`bjail` 会把执行形式改为 `exec <command>`，避免 shell 自己额外创建子进程。

示例：

```bash
bjail --subprocess false cat Cargo.toml
bjail --subprocess false python3 -c "import subprocess; subprocess.run(['true'], check=True)"
```

第二条命令会因为禁止子进程而失败。

## 示例

读取文件：

```bash
./target/debug/bjail cat Cargo.toml
```

指定工作区路径：

```bash
./target/debug/bjail --sandbox-path /tmp/work cat notes.txt
```

关闭网络：

```bash
./target/debug/bjail --network false curl https://example.com
```

禁止子进程：

```bash
./target/debug/bjail --subprocess false cat file.txt
```

同时指定多个选项：

```bash
./target/debug/bjail \
  --sandbox-path /tmp/work \
  --readable-path /tmp/work/docs \
  --blocked-path /tmp/work/docs/private \
  --network false \
  --subprocess false \
  cat file.txt
```

## 行为说明

`bjail` 的执行流程分两层：

1. 外层进程调用 `bwrap` 创建沙箱
2. 内层进程在沙箱中执行 `bash --noprofile --norc -lc '<command>'`
3. 如果 `--subprocess false`，会在真正 `exec bash` 之前安装 seccomp 规则

默认挂载策略：

- 默认模式：
  ` / ` 只读绑定，`--sandbox-path` 对应目录重新绑定为可写
- 白名单模式：
  ` / ` 从 `tmpfs` 开始，只挂载最小系统目录、`--readable-path`、以及 `--sandbox-path`
- 黑名单路径会在最后阶段覆盖到对应挂载点上
- `/dev` 使用最小设备节点
- `/proc` 挂载到新的 PID namespace 中

## 限制

- 当前实现仅面向 Linux
- 依赖系统提供的 `bwrap`
- 不是完整容器方案，只是一个最小命令级沙箱
- 黑名单路径当前要求宿主机上已存在

## 开发与测试

运行单元测试：

```bash
cargo test
```

格式检查：

```bash
cargo fmt -- --check
```
