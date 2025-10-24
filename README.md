# cysic-node-monitor

轻量级的本地节点监控工具，采集运行 Cysic 节点（validator/verifier/prover）时的资源使用与进程状态，生成日志并支持输出 JSON 以便上报或接入监控系统。适用于 macOS / Linux（包括在 Mac Mini M4 上运行）。

## 功能
- 监控指定进程名或 PID（例：`cysicd`、`cysic-prover`）
- 周期性记录 CPU、内存、磁盘、网络与进程状态
- 输出到本地日志文件（滚动按日期）并支持 JSON 输出（方便 webhook 或 Prometheus node exporter 适配）
- 可作为 systemd 服务运行（示例 service 文件提供）

## 要求
- Python 3.10+
- 推荐在虚拟环境中安装依赖

## 快速开始
```bash
git clone <your-repo-url>
cd cysic-node-monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 编辑 config.toml（参见示例）或使用命令行参数
python monitor.py --process-name cysicd --interval 30
