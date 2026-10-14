#!/usr/bin/env python3
"""企业微信(macOS)数据路径自动发现 —— 所有脚本共用的唯一配置入口。

换机器 / 换账号时**不需要改代码**:

| 项 | 优先取 | 否则自动发现 |
| --- | --- | --- |
| 容器目录 | `$WEWORK_CONTAINER` | `~/Library/Containers/com.tencent.WeWorkMac/Data` |
| 主 Profile | `$WEWORK_PROFILE` | 扫 `Documents/Profiles/*/Messages1/Info.db`, 取最大的 |
| 老库 vid | `$WEWORK_VID` | 扫 `WXWork/Data/*/Data/message.db`, 取最大的 |
| 数据根目录 | `$WEWORK_DATA_ROOT` | `<仓库根>/data` |
| 结构化库 | `$WECOM_DB` | `<数据根>/wecom.sqlite` |
| 媒体备份 | `$WECOM_MEDIA_ROOT` | `<数据根>/media` |

主 Profile 与老库都用**文件大小**判断: 首次运行时库还是加密的读不出内容, 但主账号的
库一定是最大的那个。容器不在时(换机器/在 Docker 里)退一步从 `plaintext/` 里认同样的
目录名 —— 只拿备份重建结构化库也不需要装企业微信。

**容器可以不存在**: 检索(search/webui/verify)只读 `data/`, 在 Docker 里或换到别的
机器时容器不在也能用; 只有解密与媒体同步会调用 `require_container()` 并在缺容器时
明确报错。

用法:
    from wwconfig import paths
    P = paths()
    P.store_db, P.media_backup, P.info_db, P.info_db_enc, ...
"""
from __future__ import annotations

import glob
import os

REPO = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONTAINER = os.path.expanduser("~/Library/Containers/com.tencent.WeWorkMac/Data")
PROFILES_REL = "Documents/Profiles"
LEGACY_REL = "Library/Application Support/WXWork/Data"
AVATAR_REL = "Documents/UserAvatarUrl"

# 媒体目录: kind → 备份内的相对路径。备份里固定用 profile/ 与 legacy/ 两个前缀,
# 与容器里那个随账号变化的 Profile 哈希无关 —— 所以检索侧不需要知道 Profile 是谁。
MEDIA_BACKUP_RELS = {
    "image":          "profile/Caches/Images",
    "file":           "profile/Caches/Files",
    "video":          "profile/Caches/Videos",
    "emotion":        "profile/Caches/Emotions",
    "voice":          "profile/Caches/Voices",
    "video_thumb":    "profile/Caches/Video_Thumbnail",
    "emotion_thumb":  "profile/Caches/Emotion_Thumbnail",
    "link_thumb":     "profile/Caches/Link_Thumbnail",
    "legacy_file":    "legacy/Cache/File",
    "legacy_image":   "legacy/Cache/Image",
    "legacy_emotion": "legacy/Emotion",
    "legacy_avatar":  "legacy/Avator",
    "avatar":         "UserAvatarUrl",
}
# 容器内的对应子路径(不含 profile/legacy 前缀, 用 {profile}/{legacy} 占位)
MEDIA_CONTAINER_RELS = {
    "image":          "{profile}/Caches/Images",
    "file":           "{profile}/Caches/Files",
    "video":          "{profile}/Caches/Videos",
    "emotion":        "{profile}/Caches/Emotions",
    "voice":          "{profile}/Caches/Voices",
    "video_thumb":    "{profile}/Caches/Video_Thumbnail",
    "emotion_thumb":  "{profile}/Caches/Emotion_Thumbnail",
    "link_thumb":     "{profile}/Caches/Link_Thumbnail",
    "legacy_file":    "{legacy}/Cache/File",
    "legacy_image":   "{legacy}/Cache/Image",
    "legacy_emotion": "{legacy}/Emotion",
    "legacy_avatar":  "{legacy}/Avator",
    "avatar":         AVATAR_REL,
}


def _biggest(pattern: str) -> str | None:
    """在 glob 结果里挑文件最大的那个路径。"""
    cands = []
    for p in glob.glob(pattern):
        try:
            cands.append((os.path.getsize(p), p))
        except OSError:
            continue
    return max(cands)[1] if cands else None


class Paths:
    """一次解析出全部路径。"""

    def __init__(self) -> None:
        self.container = os.environ.get("WEWORK_CONTAINER") or DEFAULT_CONTAINER
        self.container_exists = os.path.isdir(self.container)
        self.data_root = os.environ.get("WEWORK_DATA_ROOT") or os.path.join(REPO, "data")

        # ── 产出目录(检索侧只需要这几个) ──────────────────────────
        self.plaintext = os.path.join(self.data_root, "plaintext")
        self.media_backup = os.environ.get("WECOM_MEDIA_ROOT") or os.path.join(self.data_root, "media")
        self.raw_snapshot = os.path.join(self.data_root, "raw_snapshot")
        self.backup_raw = os.path.join(self.data_root, "backup_raw")
        self.store_db = os.environ.get("WECOM_DB") or os.path.join(self.data_root, "wecom.sqlite")
        self.keys_file = os.path.join(REPO, "keys", "wxwork_keys.json")

        # 容器不在时(比如在 Docker 里只看备份), 这两个留空; 再退一步从 plaintext/ 里认。
        self.profile_hash = (os.environ.get("WEWORK_PROFILE")
                             or self._guess(os.path.join(self.container, PROFILES_REL, "*", "Messages1", "Info.db"))
                             or self._guess_plain(os.path.join(self.plaintext, PROFILES_REL, "*", "Messages1", "Info.db")))
        self.legacy_vid = (os.environ.get("WEWORK_VID")
                           or self._guess(os.path.join(self.container, LEGACY_REL, "*", "Data", "message.db"))
                           or self._guess_plain(os.path.join(self.plaintext, LEGACY_REL, "*", "Data", "message.db")))

    # ── 容器相关(需要容器在场) ────────────────────────────────────
    def _guess(self, pattern: str) -> str:
        return self._from_path(_biggest(pattern)) if self.container_exists else ""

    def _guess_plain(self, pattern: str) -> str:
        """容器不在时的兜底: 已经解密过的 plaintext/ 同样能认出版本号。"""
        return self._from_path(_biggest(pattern))

    @staticmethod
    def _from_path(p: str | None) -> str:
        # Messages1/Info.db → 取上一层的目录名(Profile 哈希); Data/message.db → 取 vid
        return os.path.basename(os.path.dirname(os.path.dirname(p))) if p else ""

    @property
    def profile_rel(self) -> str:
        self.require_container()
        return f"{PROFILES_REL}/{self.profile_hash}"

    @property
    def legacy_rel(self) -> str:
        self.require_container()
        return f"{LEGACY_REL}/{self.legacy_vid}"

    def require_container(self) -> None:
        if not self.container_exists:
            raise SystemExit(
                f"找不到企业微信数据目录: {self.container}\n"
                f"这一步需要本机装有企业微信并登录过; 若安装在别处, "
                f"设置环境变量 WEWORK_CONTAINER 指向它。")
        if not self.profile_hash:
            raise SystemExit(
                f"在 {self.container}/{PROFILES_REL} 下没找到任何 Profile"
                f"(…/Messages1/Info.db)。请确认企业微信登录过, 或用 WEWORK_PROFILE 指定。")

    def media_scan_pairs(self) -> dict[str, tuple[str, str]]:
        """{kind: (备份里的相对路径, 容器里的相对路径)} —— 供媒体索引/同步使用。

        容器(或其中的 Profile/vid)认不出来时容器侧给空串, 调用方跳过即可: 只拿备份
        重建结构化库时不该因为没装企业微信而失败。
        """
        prof = f"{PROFILES_REL}/{self.profile_hash}" if self.profile_hash else ""
        leg = f"{LEGACY_REL}/{self.legacy_vid}" if self.legacy_vid else ""
        out = {}
        for kind, back_rel in MEDIA_BACKUP_RELS.items():
            tpl = MEDIA_CONTAINER_RELS[kind]
            missing = ("{profile}" in tpl and not prof) or ("{legacy}" in tpl and not leg)
            out[kind] = (back_rel, "" if missing else tpl.format(profile=prof, legacy=leg))
        return out

    # ── 加密库(decrypt 的输入) ────────────────────────────────────
    @property
    def info_db_enc(self) -> str:
        return os.path.join(self.container, self.profile_rel, "Messages1/Info.db")

    @property
    def session_db_enc(self) -> str:
        return os.path.join(self.container, self.profile_rel, "Messages1/Session.db")

    @property
    def legacy_msg_db_enc(self) -> str:
        return os.path.join(self.container, self.legacy_rel, "Data/message.db")

    # ── 解密后的明文库(store 的输入) ──────────────────────────────
    @property
    def info_db(self) -> str:
        return os.path.join(self.plaintext, PROFILES_REL, self.profile_hash, "Messages1/Info.db")

    @property
    def session_db(self) -> str:
        return os.path.join(self.plaintext, PROFILES_REL, self.profile_hash, "Messages1/Session.db")

    def _legacy_plain(self, name: str) -> str:
        return os.path.join(self.plaintext, LEGACY_REL, self.legacy_vid, "Data", name)

    @property
    def legacy_msg_db(self) -> str:
        return self._legacy_plain("message.db")

    @property
    def legacy_session_db(self) -> str:
        return self._legacy_plain("session.db")

    @property
    def legacy_user_db(self) -> str:
        return self._legacy_plain("user.db")

    @property
    def legacy_file_db(self) -> str:
        return self._legacy_plain("file.db")

    # ── 汇总 ──────────────────────────────────────────────────────
    def describe(self) -> str:
        return "\n".join([
            f"容器目录   {self.container}" + ("" if self.container_exists else "  (不存在)"),
            f"主 Profile {self.profile_hash or '(未发现)'}",
            f"老库 vid   {self.legacy_vid or '(未发现)'}",
            f"数据根目录 {self.data_root}",
            f"结构化库   {self.store_db}" + ("" if os.path.exists(self.store_db) else "  (尚未构建)"),
            f"媒体备份   {self.media_backup}" + ("" if os.path.isdir(self.media_backup) else "  (尚未同步)"),
        ])


P: Paths | None = None  # 延迟初始化: import 本模块不应因为路径缺失而失败


def paths() -> Paths:
    """取全局 Paths(首次调用时构造)。"""
    global P
    if P is None:
        P = Paths()
    return P


if __name__ == "__main__":
    print(paths().describe())
