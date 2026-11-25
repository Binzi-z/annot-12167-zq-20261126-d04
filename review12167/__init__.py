"""12167 离线取证时间差复核工具（仅使用 Python 标准库）。

模块划分：
- evidence:   规范化 JSON、SHA-256 摘要、HMAC-SHA256 签名、封装记录校验、同号异摘要检测
- constraints:把签名记录归约为差分约束边、弱连通组件
- solver:     Bellman-Ford 最短路、端点偏移见证、分层 DP 求最短负环
- certificate:矛盾证书的构造与独立验证支持
- small_data / scale_data: 确定性合成数据
- pipeline:   封存报告 / 更新解释 / 规模增量重算
- cli:        命令行入口
"""

SCHEMA_VERSION = "r12167-evidence-v1"
CERT_SCHEMA_VERSION = "r12167-negative-cycle-cert-v1"
