# 离线安全复核 12167

获确认的题面位于 task/PROMPT.txt。使用原生 Windows 和标准库，输入与验证使用本地合成数据。

## 运行

```bat
python run_all.py
```

或双击 `run_all.bat`。仅需 Python 3.8+，无第三方依赖、不联网。
单独跑测试：`python -m unittest discover -s tests -v`。

结论与方法见 **[复核报告.md](复核报告.md)**；运行后生成：

- `reports/sealed_report.md` — 原封存报告（历史快照，含封存根摘要）
- `reports/updated_explanation.md` — 更新后的解释（晚到校准 + 同号异摘要 + 端点见证）
- `reports/empty_case_report.md` 与 `reports/contradiction_certificate.json` — 空区间/最短负环证书
- `reports/scale_acceptance.md`、`reports/scale_metrics.json` — 63000 事件规模与增量重算记录数
- `review12167/verify_certificate.py` — 可单独拷走、只用标准库的证书独立复核器

