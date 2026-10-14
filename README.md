# 拾语 (Shiyu) — 企业微信(macOS)聊天记录本地备份与检索

**拾语** —— 拾起自己的话语。

从 macOS 版企业微信(`/Applications/企业微信.app`)读取数据库密钥, 离线解密全部
SQLite 库(含 WAL 增量), 备份图片/文件/视频/语音/表情/头像等附件, 汇总成单一结构化
数据库, 并提供中文全文检索的命令行工具与网页界面。

- **只读** —— 不修改被研究的应用, 不写入其数据容器; 密钥扫描只读取进程内存。
- **离线** —— 解密、建库、检索全部在本机完成, 不联网、不上传任何数据。
- **可迁移** —— 所有路径自动发现, 换机器只需把仓库与 `data/` 一起拷过去。

> ⚠️ **免责声明**: 本项目仅供个人学习、技术研究与本人数据备份使用, 仅可用于你本人拥有
> 或已获合法授权的账号数据; 严禁用于获取他人数据、侵犯他人隐私或任何违法用途。
> 完整条款见 [DISCLAIMER.md](DISCLAIMER.md)。下载、复制或运行本项目即视为已阅读并同意。

## 目录

- [目录结构](#目录结构)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [检索用法](#检索用法)
- [Docker 部署](#docker-部署)
- [配置](#配置)
- [工作原理](#工作原理)
- [已知限制](#已知限制)
- [维护](#维护)
- [参考](#参考)
- [许可证](#许可证)

## 目录结构

| 路径 | 功能 |
| --- | --- |
| `wwconfig.py` | 路径配置的唯一入口: 自动发现容器、Profile、数据目录(见[配置](#配置)) |
| `keys/` | 密钥获取: 内存扫描器 `wckey.c`(由 `build_wckey.sh` 编译)、重签名副本生成器 `make_dev_app.sh`、entitlements、`tfp_test.py` 探针、`explore/` 逆向脚本 |
| `decrypt/` | 解密: `wxwork_crypto.py`(密码学核心)、`decrypt_all.py`(全量解密) |
| `media/` | 附件同步: `sync_media.sh`(容器 → `data/media/` 增量同步) |
| `store/` | 建库: `build_store.py`(结构化库)、`parse_proto.py`(消息体解析) |
| `search/` | 检索: `search.py`(命令行)、`webui.py`(网页界面)、`verify_store.py`(建库自检) |
| `Dockerfile` / `compose.yml` | 网页界面的容器化部署 |
| `requirements.txt` | Python 依赖(仅 `decrypt/` 需要) |
| `DISCLAIMER.md` | 免责声明 |
| `LICENSE` | MIT 许可证 |

数据产物统一放在 `data/`(可用 `$WEWORK_DATA_ROOT` 改到别处):

| 路径 | 内容 |
| --- | --- |
| `data/plaintext/` | 解密后的明文库, 镜像原容器目录结构, 附 `manifest.json`(每个库的密钥/页数/WAL 帧数/自检结论) |
| `data/media/` | 附件全量备份, 目录名即文件内容 md5 |
| `data/wecom.sqlite` | 检索用的结构化库(消息/会话/联系人/媒体索引/FTS) |
| `data/backup_raw/` | 加密原始库的快照 |
| `data/raw_snapshot/` | 解密过程中用到的克隆快照, 可随时删除 |

### 版本库不包含的内容

以下内容已在 `.gitignore` 中声明, 不进入版本库:

| 不入库 | 原因 | 如何生成 |
| --- | --- | --- |
| `data/` | 解密结果与附件备份, 属私人数据且体积大 | 按[快速开始](#快速开始)执行 |
| `keys/wxwork_keys.json` | 数据库密钥 | `keys/make_dev_app.sh` + `wckey` 扫内存 |
| `keys/WeCom-dev.app/` | 重签名副本, 体积大且随应用版本变化 | `keys/make_dev_app.sh` |
| `keys/wckey`、`keys/explore/dbg` | 编译产物 | `keys/build_wckey.sh` |
| `keys/logs/`、`*.log`、`*.bak` | 运行日志与临时备份 | — |
| `.venv/`、`__pycache__/`、`.env` | 环境 | `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt` |

## 环境要求

| 用途 | 要求 |
| --- | --- |
| 密钥获取 | macOS, Xcode Command Line Tools(提供 `clang`、`codesign`), 本机安装并登录过企业微信 |
| 解密 | Python 3.8+, 以及 `requirements.txt` 中的 `pycryptodome` |
| 建库与检索 | Python 3.8+(仅标准库, 要求 Python 自带的 sqlite3 支持 FTS5) |
| 容器化部署 | Docker 与 Docker Compose(可选) |

密钥获取依赖 `task_for_pid`, 只能在 macOS 本机进行; 已有 `data/` 的情况下, 解密、建库、
检索三步在不装企业微信的机器上同样可用。

## 快速开始

```bash
# 0. 依赖(仅解密需要第三方库)
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# 1. 获取密钥 → keys/wxwork_keys.json
keys/build_wckey.sh                        # 编译内存扫描器 wckey
keys/make_dev_app.sh                       # 生成重签名副本 keys/WeCom-dev.app
# 收集容器内全部加密库的密钥指纹 KCV(即库文件前 8 字节, 明文库跳过)
KCVS=$(python3 -c '
import os
from wwconfig import paths
P = paths(); out = set()
for root, _dirs, files in os.walk(P.container):
    for f in files:
        if f.endswith(".db"):
            try: h = open(os.path.join(root, f), "rb").read(8)
            except OSError: continue
            if h != b"SQLite f": out.add(h.hex())
print(",".join(sorted(out)))')
osascript -e 'quit app "企业微信"'           # 副本与原版共用数据容器, 不能同时运行
open keys/WeCom-dev.app
PID=$(pgrep -f "WeCom-dev.app/Contents/MacOS/企业微信")
for i in 0 1 2 3 4 5 6 7; do               # 8 路分片并行扫描副本内存
  WCKEY_SHARD=$i WCKEY_NSHARD=8 keys/wckey pid "$PID" "$KCVS" &
done; wait
osascript -e 'quit app "企业微信"'           # 关闭副本, 删除并还原原版
rm -rf keys/WeCom-dev.app; open "/Applications/企业微信.app"

# 2. 解密: 容器 → data/plaintext/
.venv/bin/python decrypt/decrypt_all.py

# 3. 同步附件: 容器 → data/media/
./media/sync_media.sh

# 4. 建库: 明文库 + 附件 → data/wecom.sqlite(全量重建约数分钟)
python3 store/build_store.py --jobs 8

# 5. 检索
python3 search/search.py "关键词"
python3 search/webui.py                   # 网页界面 http://127.0.0.1:8765
```

扫描器会打印命中的密钥(形如 `target#0 key=<32 位 hex>`)。命中数量取决于本机登录过的账号:
容器里其他账号的库若未登录过, 其 KCV 不会命中, 忽略即可。把命中的密钥按用途记入
`keys/wxwork_keys.json`, 并 `chmod 600`:

```json
{
  "<用途备注>": { "key": "<32 位 hex 密钥>", "kcv": "<16 位 hex 指纹>", "verify": "PASS" }
}
```

`key` 与 `kcv` 是必需的; `verify` 仅记录当时的校验结果, 可省略(缺失时由 `key` 现算 KCV)。
库的用途可按容器内路径区分 —— `Contact/` 下的库、主账号 `Messages1/` 下的库、以及老库
`WXWork/Data/<vid>/` 各用一把。

`python3 wwconfig.py` 会打印当前解析到的全部路径, 用于确认配置:

```
容器目录   ~/Library/Containers/com.tencent.WeWorkMac/Data
主 Profile <32 位十六进制哈希>
老库 vid   <16 位数字>
数据根目录 <仓库根>/data
结构化库   <数据根>/wecom.sqlite
媒体备份   <数据根>/media
```

`python3 search/verify_store.py` 在每次建库后运行, 检查完整性、跨库去重、附件关联率与
FTS 可用性, 输出逐项结论。

## 检索用法

```bash
# 全文检索
python3 search/search.py "关键词"
python3 search/search.py "预算" "审批"                    # 多个关键词 = 同时包含
python3 search/search.py "合同" --conv 项目群 --from 2024-01-01 --to 2024-06-30
python3 search/search.py "报表" --sender 张三 --type 14    # 按发送人 / 消息类型过滤
python3 search/search.py "预算" --json                    # 机器可读输出

# 浏览
python3 search/search.py convs                           # 会话列表(按最后消息时间倒序)
python3 search/search.py show 项目群 --limit 200           # 某会话的消息流
python3 search/search.py around 1234567 -n 20             # 某条消息的前后文
python3 search/search.py stats                           # 库统计

# 附件
python3 search/search.py media 1234567                    # 某条消息的附件本地路径
python3 search/search.py export 项目群 --out /tmp/att      # 导出该会话全部附件

# 网页界面
python3 search/webui.py --host 127.0.0.1 --port 8765
```

通用选项: `--db`、`--from` / `--to`(`YYYY-MM-DD[ HH:MM]`)、`--limit`、`--conv`、
`--sender`、`--type`、`--json`。子命令可省略, `search.py 预算` 等价于
`search.py search 预算`。

检索行为说明:

- 关键词 ≥3 字走 FTS5 trigram 索引; 1–2 字无法进入 trigram 索引, 自动回退 `LIKE`
  全表扫描, 建议配合 `--conv` / `--from` 缩小范围;
- `--conv` 接受会话名(精确或子串)或数字 ID; `--sender` 按联系人名称子串匹配;
- 附件优先返回 `data/media/` 中的备份副本, 备份中没有时才回退到原容器路径;
- 同一 md5 通常存在压缩版(`<md5>/`)与高分辨率版(`<md5>_HD/`), 展示与导出优先取后者;
- 网页界面默认只监听 `127.0.0.1`; 附件只按库中记录的 md5 反查路径, 不接受任意路径;
- 网页界面按附件魔数判定 `Content-Type`, 因为部分文件的扩展名与实际格式不符。

## Docker 部署

检索侧只依赖 Python 标准库, 镜像很小; 数据以只读卷挂载, 不打进镜像。

```bash
docker compose up -d --build     # → http://127.0.0.1:8765
docker compose logs -f
docker compose down
```

镜像 `shiyu:latest`, 容器名 `shiyu`。

- 端口只发布到 `127.0.0.1`, 不对外网暴露;
- `data/` 以 `:ro` 只读挂载, 容器内不产生任何写入;
- 容器内时区默认 `Asia/Shanghai`(通过 `TZ` 设置), 修改 `TZ` 会同时改变界面上显示的时间;
- 命令行也可在容器中执行:

```bash
docker compose run --rm --entrypoint python3 shiyu search/search.py "预算" --conv 项目群
docker compose run --rm --entrypoint python3 shiyu search/verify_store.py
```

`.dockerignore` 已排除 `data/` 与 `keys/`, 构建上下文不含数据与密钥。迁移到新机器时,
把仓库与 `data/` 一起拷过去即可, 无需 Python 环境, 也无需安装企业微信。

## 配置

所有路径由 `wwconfig.py` 自动发现, 换机器不需要改代码; 只有自动发现不适用时才用环境变量
覆盖:

| 项 | 环境变量 | 默认行为 |
| --- | --- | --- |
| 容器目录 | `$WEWORK_CONTAINER` | `~/Library/Containers/com.tencent.WeWorkMac/Data` |
| 主 Profile | `$WEWORK_PROFILE` | 扫描 `Documents/Profiles/*/Messages1/Info.db`, 取文件最大的 |
| 老库 vid | `$WEWORK_VID` | 扫描 `WXWork/Data/*/Data/message.db`, 取文件最大的 |
| 数据根目录 | `$WEWORK_DATA_ROOT` | `<仓库根>/data` |
| 结构化库 | `$WECOM_DB` | `<数据根>/wecom.sqlite` |
| 附件备份 | `$WECOM_MEDIA_ROOT` | `<数据根>/media` |
| 网页界面监听 | `$WECOM_WEBUI_HOST` / `$WECOM_WEBUI_PORT` | `127.0.0.1` / `8765` |
| 账号备注信息 | `$WECOM_CORP_ID` / `$WECOM_CORP_NAME` | 空 |

主 Profile 与老库都以**文件大小**判定: 首次运行时数据库还是加密的、读不出内容, 但主账号
对应的库一定是最大的一个。容器不存在时(换机器、容器内运行)退回 `data/plaintext/` 识别
同样的目录名, 因此在只有备份的机器上, 建库与检索依然可用。

`wxwork_keys.json` 不入库。密钥一旦变化(如重新登录), 重新执行密钥获取流程即可。

## 工作原理

整体数据流:

```
企业微信进程内存 ──[KCV 比对]──> 密钥
                                   │
容器内加密库 + WAL ──[页密钥派生 + AES-128-CBC]──> data/plaintext/
客户端缓存目录     ──[rsync]───────────────────> data/media/
                                   │
     明文库 + 附件 ──[解析 / 关联 / 去重]──> data/wecom.sqlite ──> 命令行 / 网页界面
```

### 密钥获取

企业微信的数据库使用 **wxSQLite3 / SQLite3MultipleCiphers** 的 AES-128 加密, 密钥不落盘,
只存在于进程内存中, 因此必须从活进程读取。

macOS 上读取其他进程内存需要 `task_for_pid` 权限, 而原版应用没有
`com.apple.security.get-task-allow` entitlement, 无法读取。因此流程是: 复制应用副本 →
用 `keys/wecom_dev_entitlements.plist` 重签名(在原 entitlements 基础上增加
`get-task-allow` 与 `disable-library-validation`)→ 运行副本 → 扫描其内存。

签名时**不能带 `--options runtime`(硬化运行时)**: 即使拥有 `get-task-allow`, 硬化运行时
仍会阻止 `task_for_pid`(`kr=5`)。`keys/make_dev_app.sh` 在签名后会断言"adhoc 签名 +
无 runtime + 含 get-task-allow + `codesign --verify` 通过", 任一不满足即报错并删除副本。
`keys/tfp_test.py` 可用于单独验证某进程是否可读。

扫描依据是密钥指纹 **KCV**。SQLite3MultipleCiphers 按页派生密钥:

```
页密钥 pk(page) = md5(rawkey[16] || page_no<u32 LE> || b"sAlT")
IV(page)        = sqlite3mcGenerateInitialVector(page_no)   # LCG → md5
KCV             = AES-128-CBC-Enc(pk(1), IV(1), "SQLite format 3\0")[:8]
```

`KCV` 恰好等于加密库文件的**前 8 字节**, 且同一密钥下的所有库都相同。于是扫描时只需读取
每个库的前 8 字节作为目标, 再对内存做 16 字节滑窗比对, 每次校验仅需 1 次 md5 与 1 个
AES 块, 无需试解整库。`keys/wckey.c` 实现该比对, 支持按 `WCKEY_SHARD` / `WCKEY_NSHARD`
分片并行扫描。

副本与原版共用同一个数据容器(相同 bundle id), 两者不能同时运行; 副本仅用于取密钥, 用完
即可删除, 原版应用自始至终不被修改。

### 数据库格式与解密

- 页大小 4096, 页密钥按页号派生, AES-128-CBC, 无 HMAC, `reserve=0`;
- **页 1 特殊**: 文件偏移 0–7 是 KCV(本应是密文的前 8 字节), 8–15 是被挤出的原 16–23
  字节, 16–23 是明文 SQLite 头片段 `1000020200402020`, 24 之后才是密文。解密时先令
  `data[16:24] = data[8:16]`, 从偏移 16 开始 CBC 解密, 校验片段后补回
  `"SQLite format 3\0"`;
- **WAL 必须合并**: 最新消息位于 `-wal` 文件中。WAL 头 32 字节明文, 每帧为 24 字节帧头
  (页号/提交后页数/盐/校验和)加 4096 字节加密页, 只取到最后一个 `db_size != 0` 的提交帧;
- 合并 WAL 后需把头中 18/19 字节由 2(WAL)改回 1(回滚日志), 否则没有配对 `-shm` 文件的
  明文库无法被 sqlite3 只读打开;
- **并发写入竞态**: 应用运行时会持续写入。解密前以 APFS 克隆方式快照, 先克隆 WAL 再克隆
  主库, 且要求期间 WAL 的 size/mtime/inode 未发生变化, 否则重试(最多 3 次)。

`decrypt/decrypt_all.py` 对每个库执行 `PRAGMA quick_check`, 结论写入
`data/plaintext/manifest.json`。

### 消息正文解析

消息体是腾讯的 ant/protobuf 序列化格式, 无公开 schema, 由 `store/parse_proto.py` 递归
遍历字段解析。四条与格式相关的规则:

1. **引用消息的正文取"最后一个非空白文本段"**, 而非最长的一段。`content` 由若干段落拼成,
   每段自带类型(段内字段 1, `0` = 文本段, `5` = 引用对象的发送人 id), 引用他人时结构为:

   ```
   [0: "“张三：\n"] [0: 被引用的正文] [0: "”\n------\n"] [0: 本次回复] [5: 张三的 id] [0: " "]
   ```

   被引用内容在前, 本次回复在后, 末尾附一个空白段。按"最长文本"取会把被引用内容当成正文,
   并导致新旧两库对同一消息解析出不同文本, 使跨库去重失效。

2. **文本叶子外层包有 `0a <len>` 包装**。例如 12 个汉字的正文共 36 字节, 其原始 buffer 为
   `b"\n$示例文本示例文本示例文本"`: `0x0a` 是字段标记, `0x24`(36) 是长度, 其后 36 字节才是
   正文。由于长度字节常落在可打印 ASCII 区间, 整个 buffer 是合法 UTF-8, 会被判定为文本,
   不剥离就会在正文前留下 `\n$` 之类的前缀。`unwrap_text_wrapper()` 负责剥离, 并要求
   "重新编码后与原 buffer 完全一致", 以避免误剥。

3. **附件 md5 只认"整个字段值恰好是 32 位 hex"的叶子**。`content` 中同时存在两份内容:
   顶层是解析好的字段(字段 2 为文件名, 字段 8/10/30 为 32 位 hex md5, 其中字段 10 与缓存
   目录名一致), 而字段 1 把内层消息以 **hex 字符串**再存了一份。对原始字节整体扫描
   `[0-9a-f]{32}` 会从该 hex 串中切出大量假 md5, 因此 `extract_md5s` 不做整块兜底匹配。

4. **遍历时先判 md5 再判文本**。32 位 hex 字符串本身是合法 UTF-8 文本, 判定顺序相反时
   永远进入不了 md5 分支, 且会把 md5 当作正文。

### 跨库去重

数据来自两套库, 消息互有重叠: 新库(`Profiles/<hash>/Messages1/Info.db`)为主, 老库
(`WXWork/Data/<vid>/Data/message.db`)补充更早的历史。两库都以 `(会话, 消息序号)` 标识
消息 —— 新库为 `(conv_id, seq)`, 老库为 `(映射后的 conv_id, sequence)`, 这是主要的去重键;
正文不作为主要去重键, 因为引用消息的正文可能因解析差异而不同。

少数消息两库序号存在漂移(同会话、同发送人、同秒、正文相同但 seq 不同), 由一次内容精确
匹配兜底: 命中的老库行**软删除**(置 `deleted_at`)而非 `DELETE` —— 硬删会使 `msg` 与
`msg_fts` 的 rowid 错位, 而检索层只读取 `deleted_at=0` 的行。

老库会话 id 的映射依据 `conversation_table.id`: `R:<数字>` 即新库 `CONVERSATION.RID`,
`S:<vid>_<vid>` 取非本人的那个 vid(本人 vid 由老库目录名识别)。`con_numeric_id` 是老库
自身的连续编号, 与新库无关, 不可用于映射。

### 结构化库设计

| 表 | 说明 |
| --- | --- |
| `msg` | 消息主体: 发送人/会话/时间/类型/正文/URL/文件名/大小/md5 |
| `msg_fts` | FTS5 `trigram` 分词, 支持中文子串检索 |
| `conv` | 会话(名称/类型/人数/创建时间/最后消息时间) |
| `sender` | 联系人(姓名/别名/职务/手机/邮箱/英文名) |
| `media` | 附件索引(md5、备份内相对路径、原容器路径) |
| `msg_media` | 消息与附件的关联 |
| `legacy_file` | 老库 `file_table4` 的文件登记 |
| `meta` / `account` | 构建元信息与账号备注 |

约定: 主键 `id` 仅标识行, 不承载业务唯一性; 业务键(`lid`/`rid`/`conv_id`/`md5`)使用普通
索引; 所有表都有 `deleted_at`, 检索一律限定 `deleted_at=0`; 库内不含 UNIQUE 索引或约束,
幂等与去重由 `build_store.py` 在应用层完成。

附件关联依据 md5: 缓存目录名即文件内容 md5, 与消息 `content` 中字段 10 的 md5 直接对应。

### 检索实现

- 3 字及以上的关键词使用 FTS5 `trigram` 分词, 短语用双引号包裹以实现子串匹配, 多个短语
  以空格相连表示 AND; 1–2 字无法进入 trigram 索引, 回退 `LIKE`;
- 网页界面使用 `ThreadingHTTPServer`, 每个线程持有独立的 sqlite 连接 —— sqlite3 连接默认
  不允许跨线程使用;
- 建库时子进程将每批解析结果写入临时文件、由主进程按序读回, 不在进程间管道中直接传递
  结果集: 单批结果可达上百 MB, 直接回传会阻塞管道。

## 已知限制

- `content_type` 到类型名称的映射依据真实样本归纳, 未知编号按原样保留, 不影响检索;
- 卡片、小程序等富类型只能提取部分文字, 完整 BLOB 保留在 `data/plaintext/` 中;
- 语音(`.amr`)只备份, 不做转写;
- **仅客户端下载过的附件才有本地文件**。图片与文件在查看后才写入缓存, 未打开过的仍留在
  服务器上, 离线备份无法获取; 这类消息仍可检索到文字与文件名, 但 `media` 中没有对应文件;
- `account` 表的公司信息(`corp_id`/`corp_name`)在库中没有稳定的表可查, 需用
  `$WECOM_CORP_ID` / `$WECOM_CORP_NAME` 指定, 否则留空;
- 老库 `Backup/` 下的历史快照是当前老库的旧版本(消息为子集), 未导入;
- 不包含微盘(WeDrive)文件、邮件、日程、审批等非聊天模块的数据。

## 维护

```bash
# 增量补充新消息: 重新解密(只处理有变化的库), 再重建结构化库
.venv/bin/python decrypt/decrypt_all.py
python3 store/build_store.py --jobs 8               # 全量重建

# 同步新增附件后重建
./media/sync_media.sh
python3 store/build_store.py --jobs 8
python3 search/verify_store.py                      # 自检
```

企业微信在运行时会持续写入新库与老库, 因此每次增量备份都需重新执行解密与建库两步。
若建库过程被中断, 可能残留子进程, 可用以下命令清理:

```bash
pgrep -f "multiprocessing-fork" | xargs -r kill -9
```

## 参考

本项目的加密方案与消息解析思路参考了以下开源项目:

- [tzwkb/wecom-agent](https://github.com/tzwkb/wecom-agent)(MIT) —— 企业微信本地库解密与
  读取, 其结论与本项目对真实库的验证一致;
- `ylytdeng/wechat-decrypt` —— 上述项目注明其解密算法移植自该项目。该仓库已于 2026 年 7 月
  因 DMCA 投诉被 GitHub 下架, 不再提供链接。

本项目未包含上述项目的任何代码。

## 许可证

[MIT](LICENSE)。使用前请阅读 [DISCLAIMER.md](DISCLAIMER.md)。
