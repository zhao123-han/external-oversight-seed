"""宿主不可篡改隔离检测（创造级辅助）.

企业部署下 rules.json 应以只读方式挂载（容器 ro 卷 / ConfigMap ro / immutable 属性）。
本模块在部署校验时探测 rules 是否真不可写；若 stop=true 但规则可写，说明环境未真正
落实「不可篡改」，应告警——这是 P0 签名检测（detection）之上的环境级预防（prevention）兜底。

创造归人红线提示：本文件只做「探测与问询」，不替部署者改写环境；是否落实隔离由拿到
环境与平台授权的人决定。
"""

import os


def rules_writable(rules_path):
    """返回 (writable, reason)。探测规则文件当前是否可被改写（不实际改动内容）。"""
    if not os.path.exists(rules_path):
        return True, "rules.json 不存在"
    try:
        # 以追加写模式试开，立即关闭；成功=文件系统允许写入
        fd = os.open(rules_path, os.O_WRONLY | os.O_APPEND)
        os.close(fd)
        return True, "文件系统允许写入（非只读挂载 / 无 immutable 属性）"
    except (PermissionError, OSError):
        return False, "文件系统拒绝写入（只读挂载 / immutable 属性生效）"


def check_enterprise_lock(rules_path, stop_enabled):
    """企业不可篡改校验：stop 开启却可写 = 环境未落实隔离，应告警。"""
    writable, reason = rules_writable(rules_path)
    if stop_enabled and writable:
        return {
            "locked": False,
            "writable": True,
            "reason": reason,
            "message": "[企业隔离缺失] stop=true 但 rules.json 可写，宿主不可篡改隔离未落实；"
                       "请改为只读挂载或 immutable 属性后再开制止。",
        }
    return {
        "locked": not writable,
        "writable": writable,
        "reason": reason,
        "message": "[企业隔离] rules.json 只读=%s" % (not writable),
    }
